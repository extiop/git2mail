//! Result writers: legacy text files and opt-in JSON reports.
//!
//! All paths are relative to the current working directory (`./results/…`),
//! which fixes the `cargo install` bug where results were written next to the
//! original Cargo project root: `get_project_root()` is gone.

use crate::errors::Error;
use crate::sanitize::is_control_or_invisible;
use crate::sanitize::log_safe;
use log::info;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Byte ceiling for one sanitized output path component. The per-component
/// limit of the common filesystems is 255 bytes; keeping the ceiling well
/// below it leaves room for the sibling component and any consumer suffix.
const MAX_FILE_NAME_BYTES: usize = 200;

/// The when and what of a JSON report: the UTC generation timestamp and the
/// tool version. Flattened into every report, so an archived report can
/// always be traced back to the run that produced it (the report still does
/// not know the command line that produced it: archive that next to it for
/// full reproducibility).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    /// RFC 3339 UTC timestamp of the moment the report was assembled
    /// (`YYYY-MM-DDTHH:MM:SSZ`); the run's local time zone is deliberately
    /// not applied, so two archived reports sort without ambiguity.
    pub generated_at: String,
    /// Version of git2mail that wrote the report (the same string
    /// `git2mail --version` prints).
    pub tool_version: &'static str,
}

impl Provenance {
    /// Stamps the current instant from the system clock. A clock reporting
    /// before the Unix epoch (a pathological system state) degrades to the
    /// epoch itself instead of panicking: the timestamp would be wrong, but
    /// the report must still be written.
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        Self {
            generated_at: rfc3339_utc(secs),
            tool_version: env!("CARGO_PKG_VERSION"),
        }
    }
}

impl Default for Provenance {
    fn default() -> Self {
        Self::now()
    }
}

/// Formats a Unix timestamp (seconds) as RFC 3339 UTC
/// (`YYYY-MM-DDTHH:MM:SSZ`), hand-rolled so the crate keeps zero date
/// dependencies: the civil-from-days algorithm (Howard Hinnant) maps the
/// day count to a proleptic Gregorian calendar date.
pub fn rfc3339_utc(timestamp_secs: u64) -> String {
    let days = (timestamp_secs / 86_400) as i64;
    let secs_of_day = timestamp_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// The civil-from-days algorithm (Howard Hinnant, "chrono-Compatible
/// Low-Level Date Algorithms"): a day count since 1970-01-01 to a
/// proleptic Gregorian `(year, month, day)`.
fn civil_from_days(day_count: i64) -> (i64, u32, u32) {
    let z = day_count + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64; // [0, 146_096]
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365; // [0, 399]
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100); // [0, 365]
    let mp = (5 * day_of_year + 2) / 153; // [0, 11]
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if month <= 2 { year + 1 } else { year }, month as u32, day)
}

/// The search request a `search` JSON report records next to its findings:
/// the query, the language filter and every advanced qualifier actually
/// provided, so the report can be told apart from any other run's (the
/// historical gap: two runs with different qualifiers wrote
/// indistinguishable reports).
#[derive(Debug, Serialize)]
pub struct SearchRequest<'a> {
    /// The keyword query, as typed.
    pub query: &'a str,
    /// The `--language` filter (empty string when not provided).
    pub language: &'a str,
    /// The advanced qualifiers actually provided (absent fields are
    /// omitted from the report, not serialized as `null`).
    pub qualifiers: &'a crate::sources::SearchQualifiers,
}

/// The scan/search JSON report: the findings plus the provenance of the run
/// itself (see [`Provenance`]) and, for a keyword search, of the request
/// (see [`SearchRequest`]). A struct writer instead of a `json!` literal:
/// the field set is part of the documented report shape, so it must be
/// checked by the compiler.
#[derive(Debug, Serialize)]
pub struct ScanJsonReport<'a> {
    /// The scan target as given (URL, query, ...).
    pub target: &'a str,
    /// The scan mode (`repository`, `profile` or `search`).
    pub mode: &'a str,
    /// The search request provenance; `None` for a repository or profile
    /// scan (the target URL is already the whole request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<SearchRequest<'a>>,
    /// The emails found, deduplicated and sorted.
    pub emails: &'a [String],
    /// The emails found per repository (a keyword search scans many
    /// repositories); omitted when empty (a single-repository or profile
    /// scan has no breakdown to report).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub per_repository: &'a BTreeMap<String, Vec<String>>,
    /// The scan coverage.
    pub scanned: ScannedCoverage,
    /// The per-author correlation report.
    pub correlation: &'a crate::correlate::Correlation,
    /// The when/what of the report.
    #[serde(flatten)]
    pub provenance: Provenance,
}

/// The `scanned` object of a scan/search JSON report.
#[derive(Debug, Serialize)]
pub struct ScannedCoverage {
    /// Repositories actually scanned.
    pub repos: usize,
    /// Successful API requests of the whole run.
    pub pages: usize,
    /// Whether whole listed repositories may have been left unscanned.
    pub partial: bool,
}

/// Serializes the temporary staging names of concurrent publishers within
/// one process (two threads publishing different targets in the same
/// directory must never stage into the same temp file); the process id
/// disambiguates concurrent processes.
static TMP_SERIAL: AtomicU64 = AtomicU64::new(0);

/// Builds one unique staging name for an atomic publish: a sibling of the
/// target (same directory → same filesystem → [`fs::rename`] is atomic),
/// under the tool's own `.git2mail-stage.` namespace so a crash between the
/// staging write and the rename leaves no file a consumer would mistake for
/// a result, and so [`sweep_stale_staging`] can match its exact shape
/// whatever the published file's own name.
fn staging_path(directory: &Path) -> PathBuf {
    directory.join(format!(
        ".git2mail-stage.{}.{}.tmp",
        std::process::id(),
        TMP_SERIAL.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Age beyond which a staging file is an orphan: a live publisher stages
/// for milliseconds, so any `.git2mail-stage.*.tmp` file older than a day
/// was left by a crashed or killed run (power loss, `kill -9`, OOM) and is
/// swept on the next publish of the same directory.
const STAGING_ORPHAN_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Removes the stale staging files an interrupted run left in `directory`
/// (`.git2mail-stage.<pid>.<serial>.tmp`, modification time older than
/// [`STAGING_ORPHAN_AGE`]): best-effort housekeeping — a removal failure is
/// silently ignored (the file may be swept on a later publish) and a live
/// publisher's staging file (milliseconds old) can never match the age
/// bound.
fn sweep_stale_staging(directory: &Path) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(_) => return, // the directory may not exist yet: nothing to sweep
    };
    let mut swept = 0usize;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // the exact staging shape a crashed run can leave — only the
        // tool's own `.git2mail-stage.<pid>.<serial>.tmp` files match
        // (digit-checked counters), never a user file that happens to end
        // in .tmp
        let is_staging = name
            .strip_prefix(".git2mail-stage.")
            .and_then(|rest| rest.strip_suffix(".tmp"))
            .is_some_and(|counters| {
                let mut parts = counters.split('.');
                let digit = |part: Option<&str>| {
                    part.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
                };
                digit(parts.next()) && digit(parts.next()) && parts.next().is_none()
            });
        if !is_staging {
            continue;
        }
        let age = match entry
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
        {
            Some(age) => age,
            None => continue,
        };
        if age > STAGING_ORPHAN_AGE && fs::remove_file(entry.path()).is_ok() {
            swept += 1;
        }
    }
    if swept > 0 {
        info!(
            "[.] removed {swept} stale staging file{} left by an interrupted run",
            if swept > 1 { "s" } else { "" }
        );
    }
}

/// Publishes `content` at `target` atomically: the body is staged into a
/// unique sibling temporary file, then renamed over the target. [`fs::rename`]
/// replaces an existing target on every supported platform (Unix `rename(2)`,
/// Windows `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`) and is atomic
/// within a filesystem, so a concurrent reader observes either the previous
/// or the new complete content — never a truncated or interleaved file — and
/// two concurrent publishers of the same target each publish their own
/// complete run (last complete publisher wins) instead of tearing each
/// other's lines (the previous direct `File::create` + per-line write left
/// the target truncated mid-file by the second publisher's open, with the
/// first publisher's stale offset never rewritten: measured 42/60 torn
/// rounds of mixed lines and NUL holes). Because the rename swaps the
/// inode, the previous target's permissions are copied onto the staging
/// file first: a user-tightened mode (`0600`) or the executable bit on an
/// existing result file would otherwise silently reset to the
/// freshly-created file's umask default on every republish (the previous
/// in-place `File::create` preserved the mode). On any staging failure the
/// temporary file is removed and the error returned; the target itself is
/// never left half-written.
fn publish_atomically(target: &Path, staging: &Path, content: &str) -> Result<(), Error> {
    // the housekeeping runs on every publish, before staging: the sweep
    // only touches day-old files, so it can never race a live publisher
    sweep_stale_staging(
        target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    );
    // rename(2) replaces a symlink, it never follows one: a target that
    // happens to be a symlink (a user convenience link like
    // `latest.json -> run-2024.json`, or a system device link like
    // `/dev/stdout`) would be silently replaced by a regular file — the
    // report would neither reach the link's target nor the stdout device,
    // and the link itself would be destroyed, all while reporting success.
    // Refuse instead: the link and its target are left untouched, and the
    // failure is loud (checked pre-flight for `--json` through
    // [`ensure_report_target`]; re-checked here so every writer of this
    // module is covered, whatever the target's origin)
    if let Ok(metadata) = fs::symlink_metadata(target)
        && metadata.file_type().is_symlink()
    {
        return Err(Error::OutputWrite(format!(
            "cannot write {}: the path is a symlink (remove the link or write to its target directly)",
            log_safe(&target.display().to_string())
        )));
    }
    // the staging file is created OWNER-ONLY (0600 on Unix): the results
    // hold personal data (harvested email addresses), so "safe by default"
    // beats the umask's usual 0644 world-readable default — a user-tightened
    // or relaxed mode on an EXISTING target is still preserved below
    #[cfg(unix)]
    let staged = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(staging)
            .and_then(|mut file| file.write_all(content.as_bytes()))
            .map_err(|err| {
                Error::OutputWrite(format!(
                    "cannot write {}: {err}",
                    log_safe(&staging.display().to_string())
                ))
            })
    };
    #[cfg(not(unix))]
    let staged = fs::write(staging, content).map_err(|err| {
        Error::OutputWrite(format!(
            "cannot write {}: {err}",
            log_safe(&staging.display().to_string())
        ))
    });
    if let Err(err) = staged {
        let _ = fs::remove_file(staging);
        return Err(err);
    }
    // the rename replaces the inode, so the staging file's permissions are
    // what the target ends up with: copy the previous target's permissions
    // over (the symlink case is already refused above, and a target that
    // does not exist yet keeps the umask default, like a first publish)
    if let Ok(target_metadata) = fs::metadata(target)
        && let Err(err) = fs::set_permissions(staging, target_metadata.permissions())
    {
        let _ = fs::remove_file(staging);
        return Err(Error::OutputWrite(format!(
            "cannot publish {}: cannot preserve the previous permissions: {err}",
            log_safe(&target.display().to_string())
        )));
    }
    if let Err(err) = fs::rename(staging, target) {
        let _ = fs::remove_file(staging);
        return Err(Error::OutputWrite(format!(
            "cannot publish {}: {err}",
            log_safe(&target.display().to_string())
        )));
    }
    Ok(())
}

/// Writes the legacy text output: one email per line, into
/// `results/<directory>/<file_name>` relative to the current working
/// directory. The text format is unchanged.
///
/// # Errors
///
/// Returns `Ok(None)` when there is nothing to write (an empty result: no
/// file is created, the caller decides what an empty run means), or
/// [`Error::OutputWrite`] carrying the offending path when the results
/// directory or the file itself cannot be created or written.
pub fn write_text(
    directory: &str,
    file_name: &str,
    emails: &[String],
) -> Result<Option<PathBuf>, Error> {
    // an empty result is `Ok(None)`, not an error: the caller keeps the
    // written-path report (or its absence) and decides what an empty run
    // means for its own exit code, instead of every call site re-matching
    // a sentinel error variant
    if emails.is_empty() {
        return Ok(None);
    }
    // both path components are sanitized, not just the file name: the
    // sibling parameter is hardened, so a future caller passing a
    // query/author-derived directory cannot reintroduce path traversal
    // (`..\\x`) or Windows reserved device names (`CON`)
    let directory = sanitize_file_name(directory);
    let file_name = sanitize_file_name(file_name);

    info!("--------------------------------");
    if emails.len() > 1 {
        info!("[+] Found {} emails", emails.len());
    } else {
        info!("[+] Found 1 email");
    }

    let dir_path: PathBuf = Path::new("results").join(directory);
    let file_path: PathBuf = dir_path.join(&file_name);
    fs::create_dir_all(&dir_path).map_err(|err| {
        Error::OutputWrite(format!(
            "cannot create {}: {err}",
            log_safe(&dir_path.display().to_string())
        ))
    })?;
    // the whole output is composed in memory and published atomically (see
    // [`publish_atomically`]): one email per line, the format unchanged
    let mut content = String::new();
    for email in emails {
        content.push_str(email);
        content.push('\n');
    }
    let staging = staging_path(&dir_path);
    publish_atomically(&file_path, &staging, &content)?;
    info!("[+] Result is available at {}", file_path.display());
    Ok(Some(file_path))
}

/// Windows reserves device names for itself, with or without extension and
/// case-insensitively: a query like `CON` or `com1` would create a file
/// Windows refuses to open.
const WINDOWS_RESERVED_DEVICE_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Sanitizes a user- or API-derived name for use as an output file name:
/// path separators, Windows-reserved characters and control characters
/// become `_`, and trailing dots and spaces (also illegal on Windows) are
/// trimmed, so a raw query like `a/b` or `language:rust` can never escape
/// `results/<directory>/` or fail only after a full scan completed. A name
/// whose stem is a Windows reserved device name (`CON`, `NUL`, `COM1`…,
/// with or without extension, like `CON.txt`) is prefixed with `_`.
/// Because the replacement is lossy, a name the sanitizer changed also
/// carries a hash of the raw name: distinct raw queries that collapse onto
/// the same sanitized file name (`a/b`, `a:b`, `a\\b` → `a_b`) must not
/// silently overwrite each other's result file.
fn sanitize_file_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if is_control_or_invisible(c)
                || matches!(c, '/' | '\\' | ':' | '?' | '*' | '"' | '<' | '>' | '|')
            {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = sanitized.trim_end_matches(['.', ' ']);
    let candidate = if trimmed.is_empty() { "_" } else { trimmed };
    // Windows reserves the device names with or without extension: the
    // check is on the stem before the first dot, so `CON.txt` or `nul.json`
    // are caught as well as the bare names.
    let stem = candidate.split('.').next().unwrap_or(candidate);
    let mut candidate = if WINDOWS_RESERVED_DEVICE_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        format!("_{candidate}")
    } else {
        candidate.to_string()
    };
    // Sanitization is lossy: distinct raw names (`a/b`, `a:b`, `a\\b`, a
    // control-bearing name…) collapse onto the same sanitized file name, and
    // each run would silently overwrite the previous one's result file. A
    // name the sanitizer CHANGED therefore carries a hash of the raw name,
    // so the collapsed class is disambiguated — the same anti-clobber
    // suffix the length cap below uses. A byte-unchanged name keeps its
    // exact file name (`hello` stays `hello`, `Rust` stays `Rust`): the
    // suffix only answers a real loss, it never decorates an untouched
    // name. Two runs of the same query still overwrite each other by
    // design (a rerun refreshes the results); note that on a
    // case-insensitive filesystem (macOS APFS, Windows NTFS) two targets
    // differing only by case (`rust lang` vs `Rust Lang`) share one file
    // name — the target and its case are visible in every report line, and
    // the JSON report carries the exact target.
    if candidate != name {
        candidate = format!("{candidate}-{:016x}", stable_hash(name));
    }
    // A filesystem path component is limited to 255 bytes: a long multibyte
    // search query (GitHub caps queries at 256 *characters*, so a 110-CJK-
    // character query is accepted by the API but its raw file name weighs
    // 269 bytes) used to make the whole output write fail with
    // ENAMETOOLONG *after* the scan had completed, discarding the results.
    // The sanitized name is therefore capped at [`MAX_FILE_NAME_BYTES`],
    // cut on a char boundary; when the cap applies, a hash of the full RAW
    // name is appended so two distinct long queries cannot silently clobber
    // each other's result file (hashing the truncated candidate instead
    // would discard any earlier suffix and collide two long names sharing
    // the same prefix — the raw name is what makes the targets distinct)
    if candidate.len() > MAX_FILE_NAME_BYTES {
        // the cap announces itself: a silent truncation would leave the
        // analyst guessing why the printed path differs from the target
        // (same caps-say-so convention as the commit and search ceilings)
        log::info!(
            "result file name capped at {MAX_FILE_NAME_BYTES} bytes with a hash suffix (the target name was longer)"
        );
        let mut end = MAX_FILE_NAME_BYTES;
        while !candidate.is_char_boundary(end) {
            end -= 1;
        }
        return format!("{}-{:016x}", &candidate[..end], stable_hash(name));
    }
    candidate.to_string()
}

/// FNV-1a over the raw name bytes: the anti-clobber suffix must be stable
/// across Rust releases. std's `DefaultHasher` is documented as having an
/// unspecified algorithm, so a toolchain upgrade could change the suffix:
/// a rerun of the same query would then write a new file and leave the
/// previous result stale instead of refreshing it, silently breaking the
/// documented rerun-overwrite contract. FNV-1a is self-contained, stable,
/// and only needs to distinguish names, not resist adversaries.
fn stable_hash(name: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let mut hash = FNV_OFFSET_BASIS;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// The conventional stdout path marker: `--json -` writes the report to the
/// standard output instead of a literal file named `-`, following the
/// universal CLI convention (the same as `gzip -c`, `curl -o -`…).
const STDOUT_PATH_MARKER: &str = "-";

/// Rejects a `--json` report target that can never succeed, before any scan
/// runs: a path that already exists as a directory collides with the report
/// write (it would fail with `Is a directory`), so the check would only
/// fire after the whole run's API budget was spent on a report that cannot
/// be written. The `-` stdout marker and a non-existing or file path are
/// accepted (the report may also target a path created mid-run — this is
/// only a pre-flight, not a reservation).
///
/// # Errors
///
/// Returns [`Error::OutputWrite`] when the path exists and is a directory
/// (the path is carried in the error, sanitized).
pub fn ensure_report_target(path: &Path) -> Result<(), Error> {
    ensure_report_target_named(path, "JSON report")
}

/// The same pre-flight, with the deliverable's user-facing name in the
/// error messages (a rejected `--csv results` must not blame the "JSON
/// report").
///
/// # Errors
///
/// Returns [`Error::OutputWrite`] describing the first blocking property of
/// the path.
pub fn ensure_report_target_named(path: &Path, deliverable: &str) -> Result<(), Error> {
    if path == Path::new(STDOUT_PATH_MARKER) {
        return Ok(());
    }
    // a NUL byte in the path fails every syscall with EINVAL: the pre-flight
    // surfaces it now instead of after the run's API budget is spent
    if path.as_os_str().to_string_lossy().contains('\0') {
        return Err(Error::OutputWrite(format!(
            "cannot write the {deliverable} to {}: the path contains a NUL byte",
            log_safe(&path.to_string_lossy())
        )));
    }
    // a regular file occupying the parent directory can never become the
    // report's directory: the pre-flight rejects it now instead of after
    // the run's API budget is spent
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && parent.is_file()
    {
        return Err(Error::OutputWrite(format!(
            "cannot write the {deliverable} to {}: its parent path is a file, not a directory",
            log_safe(&path.to_string_lossy())
        )));
    }
    if path.is_dir() {
        return Err(Error::OutputWrite(format!(
            "cannot write the {deliverable} to {}: the path is a directory",
            log_safe(&path.to_string_lossy())
        )));
    }
    // a symlink target is rejected pre-flight (before the run's API budget
    // is spent), for the same reason [`publish_atomically`] refuses it: the
    // atomic rename would replace the link instead of following it, so the
    // report would never reach the link's target and the link would be
    // destroyed (live repro: `--json /dev/stdout` replaced the system's
    // stdout device link with a 46 kB regular file)
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(Error::OutputWrite(format!(
            "cannot write the {deliverable} to {}: the path is a symlink (remove the link or write to its target directly)",
            log_safe(&path.to_string_lossy())
        )));
    }
    Ok(())
}

/// Writes any serializable report as pretty JSON at `path` (creating parent
/// directories when needed): the shared writing logic of every `--json`
/// deliverable (scan/search reports, the `user` investigation report, the
/// `org` and reverse-lookup reports). The path `-`
/// means the standard output: the report is printed there instead of a
/// literal file named `-` being created.
///
/// Sanitizes a serialized JSON body for the terminal: every line runs
/// through [`crate::sanitize::log_safe`] and the lines are rejoined with the
/// original structural newlines, so the result still parses as JSON
/// (in-string newlines are serde_json escape text, never raw) while
/// hostile characters become `_`.
fn sanitize_json_for_stdout(body: &str) -> String {
    body.split('\n')
        .map(log_safe)
        .collect::<Vec<_>>()
        .join("\n")
}

/// # Errors
///
/// Returns [`Error::OutputWrite`] when the report cannot be written (the
/// path is carried in the error) and [`Error::Json`] when the report cannot
/// be serialized.
pub fn write_report_json<T: Serialize>(path: &Path, report: &T) -> Result<(), Error> {
    let body = serde_json::to_string_pretty(report)?;
    if path == Path::new(STDOUT_PATH_MARKER) {
        // `-` means stdout: the report goes to the pipe, and no stray file
        // named `-` is left behind. `write_all` instead of `println!`: a
        // closed/broken-pipe stdout must surface as an [`Error::OutputWrite`],
        // not panic out of the never-panic contract. The body is sanitized
        // LINE BY LINE before hitting a terminal: a raw `\n` in the
        // serialized body is always serde_json's own structural formatting
        // (in-string newlines are escaped as the two-character text \n),
        // so joining the sanitized lines back with newlines preserves a
        // parseable document while stripping the hostile characters
        // serde_json leaves raw inside string values (bidi overrides,
        // zero-width, C1/DEL) — sanitizing the whole body would destroy
        // the structural newlines and write invalid JSON (the file path
        // stays lossless — a JSON reader renders, it does not interpret)
        let safe = sanitize_json_for_stdout(&body);
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        return out
            .write_all(safe.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map(|()| {
                info!("[+] JSON report written to the standard output");
            })
            .map_err(|err| {
                Error::OutputWrite(format!(
                    "cannot write the JSON report to the standard output: {err}"
                ))
            });
    }
    // the report directory, computed once: created up front and reused as
    // the staging root of the atomic publish
    let parent_dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent_dir).map_err(|err| {
        Error::OutputWrite(format!(
            "cannot create {}: {err}",
            log_safe(&parent_dir.display().to_string())
        ))
    })?;
    // the report is published atomically (see [`publish_atomically`]): a
    // concurrent reader or a concurrent run targeting the same --json path
    // must observe one complete report, never a half-written one
    let staging_directory = parent_dir;
    let staging = staging_path(&staging_directory);
    publish_atomically(path, &staging, &body)?;
    info!(
        "[+] JSON report is available at {}",
        log_safe(&path.display().to_string())
    );
    Ok(())
}

/// Escapes one CSV field per RFC 4180: a field containing a comma, a
/// double quote, or a line break is wrapped in double quotes with the
/// embedded quotes doubled, so a hostile author name like
/// `Alice,fake@x.com,"Rust` stays ONE spreadsheet cell instead of forging
/// extra rows or columns. Like the JSON report, the file stays lossless:
/// the escaping preserves every character, the reader renders the rest.
fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        let escaped = text.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        text.to_string()
    }
}

/// Writes the per-author correlation report as a CSV spreadsheet at `path`
/// (one row per correlated author, sorted like the JSON report's
/// `correlation.authors`): `author_name, emails, repositories,
/// dominant_language, commits`. The multi-valued cells join their values
/// with `;` (the separator a spreadsheet user can split on without
/// renaming columns). No stdout mode: a spreadsheet export is a file.
/// Written atomically like every report deliverable (staging file +
/// rename, like the JSON reports).
///
/// # Errors
///
/// Returns [`Error::OutputWrite`] when the file cannot be written (the
/// path is carried in the error).
pub fn write_correlation_csv(
    path: &Path,
    correlation: &crate::correlate::Correlation,
) -> Result<(), Error> {
    // the whole file is composed in memory and published atomically, like
    // the JSON reports: a concurrent reader never observes a torn sheet
    let mut body = String::from("author_name,emails,repositories,dominant_language,commits\n");
    for author in &correlation.authors {
        let dominant = author.languages.first().map(String::as_str).unwrap_or("");
        let repositories = author
            .repos
            .iter()
            .map(|repo| repo.name.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let row = [
            csv_field(&author.author),
            csv_field(&author.emails.join(";")),
            csv_field(&repositories),
            csv_field(dominant),
            author.total_hits.to_string(),
        ];
        body.push_str(&row.join(","));
        body.push('\n');
    }
    let parent_dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    fs::create_dir_all(&parent_dir).map_err(|err| {
        Error::OutputWrite(format!(
            "cannot create {}: {err}",
            log_safe(&parent_dir.display().to_string())
        ))
    })?;
    let staging = staging_path(&parent_dir);
    publish_atomically(path, &staging, &body)?;
    info!(
        "[+] CSV export is available at {}",
        log_safe(&path.display().to_string())
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::test_logger::in_temp_cwd;

    #[test]
    fn rfc3339_utc_formats_known_timestamps() {
        // the epoch, a leap day, and a "round" modern timestamp: pin the
        // civil-from-days conversion on dates a reader can verify by hand
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(951_868_800), "2000-03-01T00:00:00Z");
        assert_eq!(rfc3339_utc(1_000_000_000), "2001-09-09T01:46:40Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn the_search_request_is_recorded_in_the_report_and_qualifiers_omitted_when_unset() {
        // the search-report provenance: two runs with different qualifiers
        // must write distinguishable reports
        let path = std::env::temp_dir().join(format!(
            "git2mail_output_test_{}_search_request.json",
            std::process::id()
        ));
        let correlation = crate::correlate::Correlation::default();
        let emails = ["a@b.c".to_string()];
        let per_repository =
            BTreeMap::from([("octocat/hello-world".to_string(), vec!["a@b.c".to_string()])]);
        let qualifiers = crate::sources::SearchQualifiers {
            stars: Some(">100".to_string()),
            ..Default::default()
        };
        let report = ScanJsonReport {
            target: "nmap",
            mode: "search",
            request: Some(SearchRequest {
                query: "nmap",
                language: "rust",
                qualifiers: &qualifiers,
            }),
            emails: &emails,
            per_repository: &per_repository,
            scanned: ScannedCoverage {
                repos: 1,
                pages: 2,
                partial: false,
            },
            correlation: &correlation,
            provenance: Provenance::now(),
        };
        write_report_json(&path, &report).expect("json output must write");

        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report must be readable"))
                .expect("report must be valid JSON");
        assert_eq!(parsed["request"]["query"], "nmap");
        assert_eq!(parsed["request"]["language"], "rust");
        assert_eq!(parsed["request"]["qualifiers"]["stars"], ">100");
        // the qualifiers that were not provided are omitted, not null
        assert!(parsed["request"]["qualifiers"].get("created").is_none());
        // the per-repository breakdown travels with a search report
        assert_eq!(
            parsed["per_repository"]["octocat/hello-world"],
            serde_json::json!(["a@b.c"])
        );
        fs::remove_file(&path).ok();
    }

    #[test]
    fn sanitize_file_name_neuters_invisible_characters() {
        // output file names derive from user-typed queries: invisible
        // characters surviving the sanitizer would make two visually
        // identical queries land in two different files, and a carried RTL
        // override could visually spoof the name in directory listings
        for c in [
            '\u{200B}', '\u{200E}', '\u{202E}', '\u{2060}', '\u{FEFF}', '\u{2028}', '\u{2029}',
            '\u{0600}',
        ] {
            assert!(
                sanitize_file_name(&format!("a{c}b")).starts_with("a_b"),
                "U+{:04X} must be neutralized in file names",
                c as u32
            );
        }
        // sampled sweep over the same invisible ranges the log-safety tests
        // pin exhaustively (file names share `is_control_or_invisible`)
        for cp in [
            0x202A, 0x202E, 0x2066, 0x2069, 0x200D, 0x2064, 0x06DD, 0x070F, 0x180E, 0x206F,
            0x110BD, 0x110CD, 0x13430, 0x1343F, 0x1BCA0, 0x1BCA3, 0x1D173, 0x1D17A, 0xFE00, 0xFE0F,
            0xE0100, 0xE01EF, 0xFFF9, 0xFFFB, 0xE0000, 0xE007F,
        ] {
            let c = char::from_u32(cp).expect("a valid scalar");
            assert!(
                sanitize_file_name(&format!("q{c}x")).starts_with("q_x"),
                "U+{cp:05X} must be neutralized in file names"
            );
        }
    }

    #[test]
    fn distinct_raw_names_that_sanitize_alike_get_distinct_result_files() {
        // the sanitization is lossy: `a/b`, `a:b` and `a\\b` all collapse
        // onto `a_b`, and each run used to silently overwrite the previous
        // one's result file (live repro: three distinct queries, one file,
        // only a generic "available at" line between them). A changed name
        // must carry a hash of the raw name, so the collapsed class is
        // disambiguated; a name the sanitizer did not change keeps its
        // exact file name
        assert_eq!(sanitize_file_name("a_b"), "a_b");
        assert_eq!(sanitize_file_name("hello"), "hello");
        let collapsed: Vec<String> = ["a/b", "a:b", "a\\b"]
            .into_iter()
            .map(sanitize_file_name)
            .collect();
        for name in &collapsed {
            assert!(
                name.starts_with("a_b-"),
                "a changed name must carry the disambiguating hash: {name}"
            );
            assert!(
                name.len() <= 255,
                "the disambiguated name must stay one filesystem component: {name}"
            );
        }
        // ... and distinct raw names must never collapse onto one file
        assert_ne!(collapsed[0], collapsed[1]);
        assert_ne!(collapsed[1], collapsed[2]);
        assert_ne!(collapsed[0], collapsed[2]);
        // deterministic across runs (the length-cap suffix already relies
        // on the same stable hasher)
        assert_eq!(collapsed[0], sanitize_file_name("a/b"));
        // the same raw name always keeps the same file (a rerun overwrites
        // its own results by design)
        assert_eq!(sanitize_file_name("a:b"), collapsed[1]);
        // trailing-dot trimming is a change too: `a.` must not collapse
        // onto `a`
        assert_ne!(sanitize_file_name("a."), sanitize_file_name("a"));
    }

    #[test]
    fn the_anti_clobber_hash_is_stable_across_rust_releases() {
        // std's DefaultHasher has an unspecified algorithm: a toolchain
        // upgrade used to change the suffix, so a rerun of the same query
        // wrote a new file and left the previous result stale instead of
        // refreshing it. The suffix is now a self-contained FNV-1a, pinned
        // here by its exact value: if this test fails, the suffix changed
        // and old result files will no longer be overwritten by reruns
        assert_eq!(format!("{:016x}", stable_hash("a/b")), "e620c3190468cf61");
        assert_eq!(format!("{:016x}", stable_hash("a:b")), "e661911904a01160");
        assert_eq!(format!("{:016x}", stable_hash("Rust")), "ea8ce02b70d73b07");
        // both suffix sites (case-fold and length cap) derive from the
        // same hash: the disambiguation test above keeps them coherent,
        // this pin keeps them stable
    }

    #[test]
    fn ensure_report_target_rejects_a_nul_byte_path_before_the_scan() {
        // a NUL byte fails every syscall with EINVAL: the pre-flight must
        // surface it before the run's API budget is spent
        let error = ensure_report_target(Path::new("report\u{0}.json"))
            .expect_err("a NUL-byte path must be rejected");
        assert!(
            matches!(error, Error::OutputWrite(ref details) if details.contains("NUL byte")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn ensure_report_target_rejects_a_file_as_parent_before_the_scan() {
        // a regular file occupying the parent path can never become the
        // report's directory: reject it pre-flight
        let file =
            std::env::temp_dir().join(format!("git2mail-parent-is-a-file-{}", std::process::id()));
        std::fs::write(&file, "not a directory").expect("the temp file must be writable");
        let target = file.join("report.json");
        let error = ensure_report_target(&target).expect_err("a file parent must be rejected");
        assert!(
            matches!(error, Error::OutputWrite(ref details) if details.contains("parent path is a file")),
            "unexpected error: {error:?}"
        );
        std::fs::remove_file(&file).expect("the temp file must be removable");
    }

    #[test]
    fn ensure_report_target_rejects_an_existing_directory_before_the_scan() {
        // `--json results` collides with the legacy results/ directory: the
        // check must reject it before the run's API budget is spent, not at
        // report-write time after the whole scan completed
        let dir = std::env::temp_dir().join(format!(
            "git2mail-ensure-report-target-dir-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("the temp directory must be creatable");
        let error = ensure_report_target(&dir).expect_err("a directory target must be rejected");
        assert!(
            matches!(error, Error::OutputWrite(ref details) if details.contains("is a directory")),
            "unexpected error: {error:?}"
        );
        // the stdout marker, a non-existing path and a plain file are accepted
        assert!(ensure_report_target(Path::new("-")).is_ok());
        assert!(
            ensure_report_target(&std::env::temp_dir().join(format!(
                "git2mail-no-such-report-{}.json",
                std::process::id()
            )))
            .is_ok()
        );
        let file = std::env::temp_dir().join(format!(
            "git2mail-ensure-report-target-file-{}.json",
            std::process::id()
        ));
        std::fs::write(&file, "{}").expect("the temp file must be writable");
        assert!(ensure_report_target(&file).is_ok());
        std::fs::remove_dir(&dir).ok();
        std::fs::remove_file(&file).ok();
    }

    #[cfg(unix)]
    #[test]
    fn ensure_report_target_rejects_a_symlink_target_before_the_scan() {
        // `--json latest.json` where latest.json is a symlink (or a system
        // device link like /dev/stdout): the atomic publish would replace the
        // link instead of following it, so the report would neither reach the
        // link's target nor the device — the rejection must happen pre-flight,
        // before the run's API budget is spent (live repro: --json /dev/stdout
        // replaced the system's stdout device link with a regular file)
        let dir = std::env::temp_dir().join(format!(
            "git2mail-ensure-report-target-symlink-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the temp directory must be creatable");
        let real = dir.join("real.json");
        std::fs::write(&real, "sentinel").expect("the temp file must be writable");
        let link = dir.join("latest.json");
        std::os::unix::fs::symlink(&real, &link).expect("the symlink must be creatable");

        let error = ensure_report_target(&link).expect_err("a symlink target must be rejected");
        assert!(
            matches!(error, Error::OutputWrite(ref details) if details.contains("is a symlink")),
            "unexpected error: {error:?}"
        );
        // the rejection is pre-flight: nothing was touched
        assert!(
            fs::symlink_metadata(&link)
                .expect("the link must still exist")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&real).expect("the target must be intact"),
            "sentinel"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_report_json_never_replaces_a_symlink_target() {
        // the atomic rename replaces a symlink, it never follows one: without
        // the publish-time guard, `write_report_json` over a symlink silently
        // destroyed the link, delivered the report to a new regular file at
        // the link's path, and still reported success (the link's target was
        // never updated) — the writer must refuse loudly instead
        in_temp_cwd(|| {
            let real = Path::new("real.json");
            fs::write(real, "sentinel").expect("the temp file must be writable");
            let link = Path::new("link.json");
            std::os::unix::fs::symlink(real, link).expect("the symlink must be creatable");

            let error = write_report_json(link, &serde_json::json!({ "probe": true }))
                .expect_err("a symlink target must be refused");
            assert!(
                matches!(error, Error::OutputWrite(ref details) if details.contains("is a symlink")),
                "unexpected error: {error:?}"
            );
            // the link and its target are both untouched
            assert!(
                fs::symlink_metadata(link)
                    .expect("the link must still exist")
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(
                fs::read_to_string(real).expect("the target must be intact"),
                "sentinel"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn write_text_never_replaces_a_symlink_result_file() {
        // the same guard covers every writer of the module: a symlinked file
        // inside results/ is refused, not silently replaced by the rename
        in_temp_cwd(|| {
            fs::create_dir_all("results/keyword").expect("the results dir must be creatable");
            let real = Path::new("results/keyword/real.txt");
            fs::write(real, "sentinel").expect("the temp file must be writable");
            let link = Path::new("results/keyword/acme.txt");
            std::os::unix::fs::symlink(real, link).expect("the symlink must be creatable");

            let error = write_text("keyword", "acme.txt", &["dev@acme.com".to_string()])
                .expect_err("a symlink target must be refused");
            assert!(
                matches!(error, Error::OutputWrite(ref details) if details.contains("is a symlink")),
                "unexpected error: {error:?}"
            );
            assert!(
                fs::symlink_metadata(link)
                    .expect("the link must still exist")
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(
                fs::read_to_string(real).expect("the target must be intact"),
                "sentinel"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_republish_preserves_the_existing_result_file_permissions() {
        // the atomic publish swaps the target's inode, so without copying
        // the previous target's permissions onto the staging file, a
        // user-tightened mode (0600) on an existing result file silently
        // reset to the staging file's umask default on every republish (the
        // previous in-place `File::create` preserved the mode)
        in_temp_cwd(|| {
            use std::os::unix::fs::PermissionsExt;
            let first = write_text("keyword", "acme.txt", &["dev@acme.com".to_string()])
                .expect("the first publish must succeed")
                .expect("the file must be written");
            fs::set_permissions(&first, fs::Permissions::from_mode(0o600))
                .expect("the mode must be settable");
            let second = write_text("keyword", "acme.txt", &["dev2@acme.com".to_string()])
                .expect("the republish must succeed")
                .expect("the file must be written");
            assert_eq!(second, first, "the republish must target the same file");
            let mode = fs::metadata(&second)
                .expect("the result file must exist")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "the user-set 0600 mode must survive the republish"
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn a_first_publish_creates_the_result_file_owner_only() {
        // the results hold personal data: a FIRST publish (no previous
        // target whose permissions could be inherited) must not fall back
        // to the umask's world-readable 0644 default — the staging file is
        // created 0600, so "safe by default" needs no user awareness
        in_temp_cwd(|| {
            use std::os::unix::fs::PermissionsExt;
            let first = write_text("keyword", "acme.txt", &["dev@acme.com".to_string()])
                .expect("the first publish must succeed")
                .expect("the file must be written");
            let mode = fs::metadata(&first)
                .expect("the result file must exist")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "a first publish must create the result file owner-only (0600)"
            );
        });
    }

    // the hostile path embeds raw C0 control characters: legal to *reject*
    // on every platform but impossible to create as a real file on Windows
    // (Win32 reserves U+0001..U+001F in path components), so the
    // create-then-log assertion is unix-only — the log-sanitization
    // contract itself is covered platform-independently elsewhere
    #[cfg(unix)]
    #[test]
    fn write_report_json_success_log_never_echoes_a_hostile_path_raw() {
        in_temp_cwd(|| {
            // the success log prints the user-typed --json path: a path
            // carrying control characters (a hostile
            // `--json $'ev\n\x1b[31m.json'`) would forge and recolor a log
            // line — it must be sanitized like every terminal-printed string
            let (result, lines) = crate::test_logger::capture(|| {
                write_report_json(
                    Path::new("git2mail_json_log_test")
                        .join("ev\n\u{1b}[31m.json")
                        .as_path(),
                    &serde_json::json!({}),
                )
            });
            result.expect("the report must be written");
            // per-line assertion: the process-wide capture logger can also
            // carry lines from a concurrent test that logs without capture
            // (the harness serializes captures, not unrelated logs), so the
            // lines must not be joined into one string here — a join would
            // inject a control-character newline of its own
            let line = lines
                .iter()
                .find(|line| line.contains("ev__"))
                .unwrap_or_else(|| panic!("the success log must be captured: {lines:?}"));
            assert!(
                !line.chars().any(|c| c.is_control()),
                "the success log must not echo a raw control character: {line:?}"
            );
            assert!(line.contains("ev__[31m.json"), "{line}");
        });
    }

    #[test]
    fn write_text_writes_one_email_per_line_relative_to_cwd() {
        in_temp_cwd(|| {
            // unique directory so parallel test runs never collide
            let directory = format!("git2mail_output_test_one_line_{}", std::process::id());
            let emails = vec!["a@b.c".to_string(), "d@e.f".to_string()];

            let path = write_text(&directory, "scan", &emails)
                .expect("text output must write")
                .expect("the file must be written");

            let content = fs::read_to_string(&path).expect("result must be readable");
            assert_eq!(content, "a@b.c\nd@e.f\n");
            // path is relative to the (temp) current working directory
            assert!(path.starts_with("results/"));
        });
    }

    #[test]
    fn a_publish_sweeps_the_staging_files_an_interrupted_run_left_behind() {
        in_temp_cwd(|| {
            // write_text publishes into `results/<directory>`: the orphans
            // must be planted there, next to the target
            let directory = format!("git2mail_output_test_sweep_{}", std::process::id());
            let planted = std::path::PathBuf::from("results").join(&directory);
            fs::create_dir_all(&planted).expect("test setup: results dir");
            // two orphans from a crashed run (24 h+ old) and one fresh
            // staging file a concurrent run could legitimately own: only
            // the orphans may be swept
            let stale = planted.join(".git2mail-stage.99999.0.tmp");
            let stale_csv = planted.join(".git2mail-stage.99999.1.tmp");
            let fresh = planted.join(".git2mail-stage.99998.0.tmp");
            let user_file = planted.join("sweep-99999.0.tmp");
            for file in [&stale, &stale_csv, &fresh, &user_file] {
                fs::write(file, "orphan").expect("test setup: staging file");
            }
            // age the two orphans beyond the sweep bound (std-only: no
            // filetime dependency)
            let old = std::time::SystemTime::now() - std::time::Duration::from_secs(25 * 60 * 60);
            for file in [&stale, &stale_csv] {
                let handle = fs::OpenOptions::new()
                    .append(true)
                    .open(file)
                    .expect("test setup: reopen staging file");
                handle
                    .set_times(std::fs::FileTimes::new().set_modified(old))
                    .expect("test setup: backdate staging file");
            }

            write_text(directory.as_str(), "sweep", &["a@b.c".to_string()])
                .expect("text output must write")
                .expect("the file must be written");

            assert!(!stale.exists(), "the stale staging file must be swept");
            assert!(
                !stale_csv.exists(),
                "the stale csv staging file must be swept"
            );
            assert!(
                fresh.exists(),
                "a fresh staging file (a concurrent run's) must never be swept"
            );
            assert!(
                user_file.exists(),
                "a user file that happens to end in .tmp must never be swept"
            );
        });
    }

    #[test]
    fn write_text_reports_an_empty_result_as_none() {
        let written =
            write_text("whatever", "empty", &[]).expect("an empty result is not an error");
        assert!(written.is_none(), "an empty result must write no file");
        assert!(!Path::new("results/whatever").exists());
    }

    #[test]
    fn write_text_sanitizes_unsafe_file_names() {
        in_temp_cwd(|| {
            let directory = format!("git2mail_output_test_unsafe_{}", std::process::id());
            let emails = vec!["a@b.c".to_string()];

            // a '/' in a raw query would escape the results directory, and
            // the lossy replacement disambiguates the collapsed class: two
            // distinct raw queries that sanitize to the same name must not
            // silently overwrite each other's result file
            let path = write_text(&directory, "a/b", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            let slashed = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a UTF-8 result file name");
            assert!(slashed.starts_with("a_b-"), "unexpected name: {slashed}");
            let plain = write_text(&directory, "a_b", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            assert_eq!(
                plain.file_name().and_then(|name| name.to_str()),
                Some("a_b"),
                "a name the sanitizer did not change keeps its exact file name"
            );
            assert_ne!(plain, path, "a/b and a_b must land in distinct files");

            // Windows-reserved characters are replaced, trailing dots/spaces trimmed
            let path = write_text(&directory, "language:rust ", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a UTF-8 result file name");
            assert!(
                name.starts_with("language_rust-"),
                "unexpected name: {name}"
            );

            // a name entirely made of dots would be a directory: fall back to "_"
            let path = write_text(&directory, "..", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a UTF-8 result file name");
            assert!(name.starts_with("_-"), "unexpected name: {name}");

            // the directory component is sanitized like the file name: a
            // traversal (`..\\x`) or a Windows reserved device name (`CON`)
            // must never escape `results/` or produce an unopenable path
            let path = write_text("../escape", "scan", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            // compare components, not the lossy string: the separator is
            // `/` on Unix and `\` on Windows; the sanitized DIRECTORY
            // carries the `.._escape-` name, under `results/`
            let dir = path.parent().expect("a parent directory");
            assert!(
                dir.file_name()
                    .and_then(|name| name.to_str())
                    .expect("a UTF-8 directory name")
                    .starts_with(".._escape-")
            );
            assert_eq!(
                dir.parent().map(|parent| parent.to_string_lossy()),
                Some(std::borrow::Cow::Borrowed("results"))
            );
            let path = write_text("CON", "scan", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            let dir = path.parent().expect("a parent directory");
            assert!(
                dir.file_name()
                    .and_then(|name| name.to_str())
                    .expect("a UTF-8 directory name")
                    .starts_with("_CON-")
            );
            assert_eq!(
                dir.parent().map(|parent| parent.to_string_lossy()),
                Some(std::borrow::Cow::Borrowed("results"))
            );
        });
    }

    #[test]
    fn write_text_sanitizes_windows_reserved_device_names_and_control_characters() {
        in_temp_cwd(|| {
            let directory = format!("git2mail_output_test_reserved_{}", std::process::id());
            let emails = vec!["a@b.c".to_string()];

            // Windows reserved device names are refused with or without
            // extension, case-insensitively: they are prefixed with "_"
            for reserved in ["CON", "nul", "Com1"] {
                let path = write_text(&directory, reserved, &emails)
                    .expect("text output must write")
                    .expect("the file must be written");
                let expected = format!("_{reserved}");
                let actual = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("a UTF-8 result file name");
                assert!(actual.starts_with(&expected), "unexpected name: {actual}");
            }

            // the reservation also holds for "name.extension" forms
            for reserved in ["CON.txt", "nul.json"] {
                let path = write_text(&directory, reserved, &emails)
                    .expect("text output must write")
                    .expect("the file must be written");
                let expected = format!("_{reserved}");
                let actual = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("a UTF-8 result file name");
                assert!(actual.starts_with(&expected), "unexpected name: {actual}");
            }

            // control characters are replaced, like the other illegal characters
            let path = write_text(&directory, "a\nb", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a UTF-8 result file name");
            assert!(name.starts_with("a_b-"), "unexpected name: {name}");
        });
    }

    #[test]
    fn write_text_maps_a_filesystem_failure_to_output_write_with_the_path() {
        in_temp_cwd(|| {
            // a file sitting where the results directory should be makes
            // create_dir_all fail: the error must be an OutputWrite carrying
            // the offending path, not a bare I/O error
            let blocker = format!("git2mail_output_test_blocker_{}", std::process::id());
            fs::create_dir_all(Path::new("results")).expect("test setup: results dir");
            fs::write(Path::new("results").join(&blocker), "not a directory")
                .expect("test setup: blocker file");

            let error = write_text(&blocker, "scan", &["a@b.c".to_string()])
                .expect_err("a blocked directory must fail");
            assert!(
                matches!(error, Error::OutputWrite(details) if details.contains("results") && details.contains(&blocker))
            );
        });
    }

    /// Builds a scan report for the tests: one site per field, so a
    /// shape change breaks the compile here instead of silently
    /// dropping a field from the documented shape.
    /// The empty per-repository map the non-search test reports carry.
    static EMPTY_PER_REPOSITORY: BTreeMap<String, Vec<String>> = BTreeMap::new();

    fn test_report<'a>(
        target: &'a str,
        mode: &'a str,
        emails: &'a [String],
        repos: usize,
        pages: usize,
        partial: bool,
        correlation: &'a crate::correlate::Correlation,
    ) -> ScanJsonReport<'a> {
        ScanJsonReport {
            target,
            mode,
            request: None,
            emails,
            per_repository: &EMPTY_PER_REPOSITORY,
            scanned: ScannedCoverage {
                repos,
                pages,
                partial,
            },
            correlation,
            provenance: Provenance::now(),
        }
    }

    #[test]
    fn write_json_maps_a_filesystem_failure_to_output_write_with_the_path() {
        // writing the report onto a directory path must surface as an
        // OutputWrite carrying that path
        let directory = std::env::temp_dir().join(format!(
            "git2mail_output_test_json_blocker_{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test setup: blocker directory");

        let correlation = crate::correlate::Correlation::default();
        let emails = ["a@b.c".to_string()];
        let report = test_report("target", "repository", &emails, 1, 1, false, &correlation);
        let error = write_report_json(&directory, &report).expect_err("a directory path must fail");
        assert!(
            matches!(error, Error::OutputWrite(details) if details.contains(&directory.display().to_string()))
        );

        fs::remove_dir(&directory).ok();
    }

    // same C0-in-filename constraint as the sibling test above: unix-only
    #[cfg(unix)]
    #[test]
    fn output_write_errors_never_echo_a_hostile_path_raw() {
        in_temp_cwd(|| {
            // a file sitting where the --json report's parent directory
            // should be makes create_dir_all fail: the error carries the
            // (user-typed) path, so a path carrying control characters (a
            // hostile `--json $'a\nb.json'` or an ESC-bearing name) must be
            // sanitized in the payload like every other terminal-printed
            // string, never echoed raw
            let blocker = "git2mail_output_test_hostile_block\u{1b}[31m".to_string();
            fs::create_dir_all(Path::new("results")).expect("test setup: results dir");
            fs::write(Path::new("results").join(&blocker), "not a directory")
                .expect("test setup: blocker file");

            let hostile = Path::new("results").join(&blocker).join("report.json");
            let error = write_report_json(&hostile, &serde_json::json!({}))
                .expect_err("a blocked parent must fail");
            let printed = error.to_string();
            assert!(
                !printed.chars().any(|c| c.is_control()),
                "the error payload must not carry a raw control character: {printed:?}"
            );
            assert!(printed.contains("block_[31m"), "{printed}");
        });
    }

    #[test]
    fn a_dash_json_path_writes_the_report_to_the_standard_output_not_a_file() {
        in_temp_cwd(|| {
            // the universal CLI convention: `--json -` pipes the report to
            // stdout instead of creating a literal file named `-` (which
            // used to leave an empty pipe, a stray junk file, and an
            // ambiguous "available at -" log line)
            let (result, lines) = crate::test_logger::capture(|| {
                write_report_json(Path::new("-"), &serde_json::json!({"key": "value"}))
            });
            result.expect("the stdout report must write");
            let printed = lines.join("\n");
            assert!(
                printed.contains("standard output"),
                "the success log must name the standard output, not an ambiguous path: {printed}"
            );
            assert!(
                !Path::new("-").exists(),
                "no literal file named '-' may be created"
            );
        });
    }

    #[test]
    fn the_hash_suffix_is_added_only_on_a_real_loss() {
        // the anti-clobber suffix answers a real sanitization loss: a byte-
        // unchanged name keeps its exact file name, whatever its case — the
        // suffix never decorates an untouched name (the JSON report and the
        // log lines carry the exact target, so nothing is silently hidden;
        // on a case-insensitive filesystem two case-only variants share one
        // file name, as documented)
        assert_eq!(sanitize_file_name("rust lang"), "rust lang");
        assert_eq!(sanitize_file_name("hello"), "hello");
        assert_eq!(sanitize_file_name("Rust Lang"), "Rust Lang");
        // a genuinely lossy name carries the 16-hex suffix of the RAW name
        let lossy = sanitize_file_name("a/b");
        assert!(
            lossy.starts_with("a_b-") && lossy.len() == "a_b-".len() + 16,
            "a collapsed name must carry the 16-hex anti-clobber suffix: {lossy}"
        );
        assert_ne!(
            sanitize_file_name("a/b"),
            sanitize_file_name("a:b"),
            "two raw names collapsing onto the same sanitized name must stay distinct"
        );
    }

    #[test]
    fn the_length_cap_hashes_the_raw_name_not_the_truncation() {
        // two distinct long names sharing a truncated prefix must stay
        // distinct: the cap's hash is taken over the raw name, so cutting
        // the candidate cannot collapse them (they would silently clobber
        // each other's result file on a 255-byte filesystem limit)
        let long_a = "日".repeat(110);
        let long_b = format!("{long_a}語");
        let a = sanitize_file_name(&long_a);
        let b = sanitize_file_name(&long_b);
        assert!(
            a.len() <= 255 && b.len() <= 255,
            "both names must respect the filesystem component limit: {a:?} {b:?}"
        );
        assert_ne!(
            a, b,
            "distinct long names must not collide after truncation"
        );
    }

    #[test]
    fn the_stdout_json_sanitizer_preserves_a_parseable_document() {
        // a report carrying hostile characters stays valid JSON on stdout:
        // every line parses, structural newlines survive, and no control
        // or invisible character other than the newline reaches the body
        let report = serde_json::json!({
            "author": "jane\u{202e}DUPONT\u{200b}",
            "email": "jane\u{1b}[31m@acme.com",
            "nested": { "list": ["a", "b"], "n": 3 }
        });
        let body = serde_json::to_string_pretty(&report)
            .expect("serialization of a plain map cannot fail");
        let safe = sanitize_json_for_stdout(&body);
        let parsed: serde_json::Value = serde_json::from_str(&safe)
            .expect("the sanitized stdout body must still parse as JSON");
        // stdout is a sanitized VIEW, not the lossless file: characters
        // serde_json leaves raw (bidi overrides, zero-width, C1/DEL) become
        // `_`, while C0 controls were already escaped by serde_json itself
        // and survive as escape text (a JSON reader never renders them raw)
        assert_eq!(
            parsed["author"], "jane_DUPONT_",
            "the hostile invisible characters must be neutered"
        );
        assert!(
            safe.chars().all(|c| c == '\n' || !c.is_control()),
            "no control character other than the structural newline may remain: {safe:?}"
        );
    }

    #[test]
    fn write_json_serializes_the_spec_shape() {
        let path = std::env::temp_dir().join(format!(
            "git2mail_output_test_{}_report.json",
            std::process::id()
        ));
        let correlation = crate::correlate::Correlation::default();
        let emails = ["a@b.c".to_string()];
        write_report_json(
            &path,
            &test_report(
                "https://github.com/octocat/hello-world",
                "repository",
                &emails,
                1,
                3,
                false,
                &correlation,
            ),
        )
        .expect("json output must write");

        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report must be readable"))
                .expect("report must be valid JSON");
        assert_eq!(parsed["target"], "https://github.com/octocat/hello-world");
        assert_eq!(parsed["mode"], "repository");
        assert_eq!(parsed["emails"], serde_json::json!(["a@b.c"]));
        assert_eq!(parsed["scanned"]["repos"], 1);
        assert_eq!(parsed["scanned"]["pages"], 3);
        assert_eq!(parsed["scanned"]["partial"], false);
        // the correlation object is always part of the opt-in report
        assert_eq!(parsed["correlation"]["authors"], serde_json::json!([]));
        // the provenance is always part of the report: an archived report
        // traces back to the run that produced it
        assert_eq!(parsed["tool_version"], env!("CARGO_PKG_VERSION"));
        assert!(
            parsed["generated_at"]
                .as_str()
                .is_some_and(|stamp| stamp.len() == 20 && stamp.ends_with('Z')),
        );
        // a repository scan carries no request provenance and no
        // per-repository breakdown (its one target is the whole report)
        assert!(parsed.get("request").is_none());
        assert!(parsed.get("per_repository").is_none());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn write_json_flags_a_token_death_truncation_in_the_machine_readable_marker() {
        // the CHANGELOG contract: `scanned.partial` is the machine-readable
        // truncation marker of the `search`/`scan` JSON report — a mutation
        // hardcoding `false` at the wiring site must fail the suite, so the
        // `true` path is pinned here too, not only at the reducer level
        let path = std::env::temp_dir().join(format!(
            "git2mail_output_test_{}_partial_report.json",
            std::process::id()
        ));
        let correlation = crate::correlate::Correlation::default();
        let emails = ["a@b.c".to_string()];
        write_report_json(
            &path,
            &test_report(
                "https://github.com/octocat/hello-world",
                "search",
                &emails,
                3,
                7,
                true,
                &correlation,
            ),
        )
        .expect("json output must write");

        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report must be readable"))
                .expect("report must be valid JSON");
        assert_eq!(parsed["scanned"]["partial"], true);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn write_report_json_creates_the_missing_parent_directories() {
        // the --json path can point into directories that do not exist yet:
        // the writer creates the whole parent chain instead of failing after
        // a full scan completed
        let base = std::env::temp_dir().join(format!(
            "git2mail_output_test_{}_nested_report",
            std::process::id()
        ));
        let path = base.join("deep/dir/report.json");
        write_report_json(&path, &serde_json::json!({ "ok": true }))
            .expect("the nested report must be written");
        assert!(path.is_file());
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn write_json_includes_the_correlation_report_on_top_of_the_legacy_fields() {
        let path = std::env::temp_dir().join(format!(
            "git2mail_output_test_{}_correlation.json",
            std::process::id()
        ));
        let mut builder = crate::correlate::CorrelationBuilder::new();
        builder.add_repo(crate::correlate::RepoContribution {
            name: "octocat/hello-world".to_string(),
            language: Some("Rust".to_string()),
            authors: vec![crate::correlate::CommitAuthor {
                name: "Alice".to_string(),
                email: "a@b.c".to_string(),
                hits: 2,
                last_commit_date: None,
            }],
        });
        let correlation = builder.finish();
        let emails = ["a@b.c".to_string()];
        write_report_json(
            &path,
            &test_report(
                "https://github.com/octocat/hello-world",
                "repository",
                &emails,
                1,
                1,
                false,
                &correlation,
            ),
        )
        .expect("json output must write");

        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report must be readable"))
                .expect("report must be valid JSON");
        // the legacy fields are unchanged, the correlation is an addition
        assert_eq!(parsed["emails"], serde_json::json!(["a@b.c"]));
        assert_eq!(parsed["scanned"]["repos"], 1);
        let alice = &parsed["correlation"]["authors"][0];
        assert_eq!(alice["author"], "Alice");
        assert_eq!(alice["emails"], serde_json::json!(["a@b.c"]));
        assert_eq!(alice["repos"][0]["name"], "octocat/hello-world");
        assert_eq!(alice["repos"][0]["language"], "Rust");
        assert_eq!(alice["languages"], serde_json::json!(["Rust"]));
        assert_eq!(alice["first_seen_repo"], "octocat/hello-world");
        assert_eq!(alice["total_hits"], 2);
        fs::remove_file(&path).ok();
    }

    #[test]
    fn write_text_publishes_the_complete_output_and_leaves_no_staging_file() {
        in_temp_cwd(|| {
            let directory = format!("git2mail_output_test_atomic_{}", std::process::id());
            let emails: Vec<String> = (0..500).map(|i| format!("dev{i}@example.com")).collect();
            let path = write_text(&directory, "atomic", &emails)
                .expect("text output must write")
                .expect("the file must be written");
            let expected: String = emails.iter().map(|email| format!("{email}\n")).collect();
            assert_eq!(
                fs::read_to_string(&path).expect("result must be readable"),
                expected
            );
            // a rerun replaces the file completely (last complete publisher
            // wins), and no dot-prefixed staging file survives the publish
            let fewer: Vec<String> = emails[..10].to_vec();
            let path = write_text(&directory, "atomic", &fewer)
                .expect("rerun must write")
                .expect("the file must be written");
            let expected: String = fewer.iter().map(|email| format!("{email}\n")).collect();
            assert_eq!(
                fs::read_to_string(&path).expect("result must be readable"),
                expected
            );
            let dir = Path::new("results").join(&directory);
            let entries: Vec<_> = fs::read_dir(&dir)
                .expect("directory must be readable")
                .collect::<Result<_, _>>()
                .expect("no io error");
            assert_eq!(
                entries.len(),
                1,
                "a staging file must never survive the publish: {entries:?}"
            );
        });
    }

    #[test]
    fn a_failed_publish_removes_the_staging_file_and_keeps_the_previous_report() {
        // the target cannot be replaced (a directory sits on its path): the
        // publish must fail with the target's error, remove its staging
        // file, and leave any previous complete file unharmed — the old
        // direct write could leave the target truncated
        let base = std::env::temp_dir().join(format!(
            "git2mail_output_test_failed_publish_{}",
            std::process::id()
        ));
        fs::create_dir_all(&base).expect("test setup: base dir");
        let previous = base.join("report.json");
        fs::write(&previous, "{ \"previous\": true }").expect("test setup: previous report");
        // a directory where the staging SIBLING file should be: the staging
        // write fails, so the previous report must survive untouched
        let staging_blocker = base.join(".git2mail-stage.tmp-blocker");
        fs::create_dir_all(&staging_blocker).expect("test setup: blocker dir");
        // publish_atomically derives its own unique staging name, so the
        // deterministic blocker is the target itself: make the rename fail
        // by replacing the target with a directory AFTER writing a first,
        // complete report — rename(file -> existing dir) fails on every
        // platform, and the previous content (the directory here) plus the
        // staging hygiene are what the test pins
        let target = base.join("blocked.json");
        fs::create_dir_all(&target).expect("test setup: target as directory");
        let error = write_report_json(&target, &serde_json::json!({ "new": true }))
            .expect_err("a directory target must fail");
        assert!(
            matches!(error, Error::OutputWrite(_)),
            "unexpected error: {error:?}"
        );
        // the staging file must not survive the failed publish
        let leftovers: Vec<_> = fs::read_dir(&base)
            .expect("directory must be readable")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".git2mail-stage.") && name.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a staging file must never survive a failed publish: {leftovers:?}"
        );
        // and the untouched previous file is exactly as before
        assert_eq!(
            fs::read_to_string(&previous).expect("previous must survive"),
            "{ \"previous\": true }"
        );
        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn two_concurrent_publishers_of_the_same_result_file_never_tear_it() {
        // two git2mail instances targeting the same query used to tear each
        // other's results/ file: both opened it with O_TRUNC and wrote
        // per-line at fd-private offsets, so the second open truncated the
        // first's already-written lines and the erased region was never
        // rewritten (measured 42/60 torn rounds of mixed lines and NUL
        // holes). The atomic publish makes every round yield exactly one
        // writer's complete output
        in_temp_cwd(|| {
            let directory = format!("git2mail_output_test_race_{}", std::process::id());
            let a: Vec<String> = (0..3000)
                .map(|i| format!("writerA-{i}@example.com"))
                .collect();
            let b: Vec<String> = (0..3000)
                .map(|i| format!("writerB-{i}@example.com"))
                .collect();
            for round in 0..30 {
                let name = format!("round{round}");
                let (a, b) = (a.clone(), b.clone());
                let (name_a, name_b) = (name.clone(), name.clone());
                let (directory_a, directory_b) = (directory.clone(), directory.clone());
                let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
                let (barrier_a, barrier_b) = (barrier.clone(), barrier);
                let (handle_a, handle_b) = (
                    std::thread::spawn(move || {
                        barrier_a.wait();
                        write_text(&directory_a, &name_a, &a).expect("writer A must write")
                    }),
                    std::thread::spawn(move || {
                        barrier_b.wait();
                        write_text(&directory_b, &name_b, &b).expect("writer B must write")
                    }),
                );
                handle_a.join().expect("writer A must not panic");
                handle_b.join().expect("writer B must not panic");
                let content = fs::read_to_string(Path::new("results").join(&directory).join(&name))
                    .expect("result must be readable");
                let all_a = content.lines().all(|line| line.starts_with("writerA-"));
                let all_b = content.lines().all(|line| line.starts_with("writerB-"));
                assert!(
                    (all_a || all_b) && content.lines().count() == 3000,
                    "round {round}: the published file must be exactly one writer's complete output, got {} lines starting with A and {} with B",
                    content
                        .lines()
                        .filter(|l| l.starts_with("writerA-"))
                        .count(),
                    content
                        .lines()
                        .filter(|l| l.starts_with("writerB-"))
                        .count(),
                );
                assert!(
                    !content.bytes().any(|byte| byte == 0),
                    "round {round}: a NUL hole (truncation artifact) reached the published file"
                );
            }
        });
    }

    #[test]
    fn two_concurrent_publishers_of_the_same_json_report_never_tear_it() {
        // the --json report write is published through the same atomic
        // staging rename: a concurrent reader observes one complete JSON
        // document, and two instances targeting the same --json path each
        // publish their own complete report instead of interleaving
        //
        // the target lives in a private directory: the staging sibling of
        // the target is `.git2mail-stage.<pid>.<serial>.tmp`, and other
        // tests of this suite publish reports from the shared temp root
        // with the same pid and stem — scanning the shared root for
        // leftovers could observe a CONCURRENT test's in-flight staging
        // file and fail spuriously (observed once in ~15 full-suite runs)
        let directory = std::env::temp_dir().join(format!(
            "git2mail_output_test_json_race_dir_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("test setup: private race directory");
        let target = directory.join("report.json");
        let report_a = serde_json::json!({ "run": "a", "emails": ["a@x.example"] });
        let report_b = serde_json::json!({ "run": "b", "emails": ["b@x.example"] });
        let (path_a, path_b) = (target.clone(), target.clone());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (barrier_a, barrier_b) = (barrier.clone(), barrier);
        let (handle_a, handle_b) = (
            std::thread::spawn(move || {
                barrier_a.wait();
                write_report_json(&path_a, &report_a).expect("writer A must write")
            }),
            std::thread::spawn(move || {
                barrier_b.wait();
                write_report_json(&path_b, &report_b).expect("writer B must write")
            }),
        );
        handle_a.join().expect("writer A must not panic");
        handle_b.join().expect("writer B must not panic");
        let content = fs::read_to_string(&target).expect("report must be readable");
        let parsed: serde_json::Value = serde_json::from_str(&content)
            .expect("the published report must be one complete JSON document");
        assert!(
            parsed == serde_json::json!({ "run": "a", "emails": ["a@x.example"] })
                || parsed == serde_json::json!({ "run": "b", "emails": ["b@x.example"] }),
            "the published report must be exactly one writer's document: {content}"
        );
        // no staging file survives next to the report (the scan is sound
        // here: the private directory holds no other publisher)
        let leftovers: Vec<_> = fs::read_dir(&directory)
            .expect("directory must be readable")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".git2mail-stage.") && name.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a staging file must never survive the publish: {leftovers:?}"
        );
        fs::remove_file(&target).ok();
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn write_text_plain_output_stays_byte_identical_for_any_email_set() {
        // property (byte-identity compatibility gate): whatever the scan found,
        // the legacy text file is exactly one email per line — the
        // correlation report changes nothing to the plain output
        let mut state = 0x1234_5678_u32;
        for _case in 0..8 {
            let mut emails: Vec<String> = Vec::new();
            for _i in 0..(state % 40 + 1) {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                emails.push(format!("dev{state}@example.com"));
            }
            in_temp_cwd(|| {
                let directory = format!("git2mail_output_test_property_{}", std::process::id());
                let path = write_text(&directory, "property", &emails)
                    .expect("text output must write")
                    .expect("the file must be written");
                let content = fs::read_to_string(&path).expect("result must be readable");
                let expected: String = emails.iter().map(|email| format!("{email}\n")).collect();
                assert_eq!(content, expected);
            });
            state = state.wrapping_add(7);
        }
    }

    /// A long multibyte search query is a real input: GitHub caps queries
    /// at 256 *characters*, so a 110-CJK-character query is accepted by the
    /// API (its UTF-8 weight is 330 bytes), but the raw result file name
    /// exceeded the 255-byte filesystem component limit and the whole
    /// output write failed with ENAMETOOLONG *after* the scan completed,
    /// discarding the results (live repro). The sanitized name must be
    /// capped below the limit, deterministically and without collisions
    /// between distinct long names.
    #[test]
    fn sanitize_file_name_caps_long_multibyte_names_below_the_filesystem_limit() {
        let long = "日".repeat(110);
        let name = sanitize_file_name(&long);
        assert!(
            name.len() <= 255,
            "capped name must fit one filesystem component: {} bytes",
            name.len()
        );
        // deterministic across runs, valid UTF-8 (cut on a char boundary)
        assert_eq!(name, sanitize_file_name(&long));
        // the cap announces itself (no silent truncation)
        let (_, lines) = crate::test_logger::capture(|| {
            let _ = sanitize_file_name(&long);
        });
        assert!(
            lines
                .iter()
                .any(|line| line.contains("result file name capped")),
            "the cap must be announced: {lines:?}"
        );
        // two distinct long names must not collapse into one result file
        let other = "語".repeat(110);
        assert_ne!(name, sanitize_file_name(&other));
        // a long ASCII name is capped the same way
        let ascii = "a".repeat(400);
        assert!(sanitize_file_name(&ascii).len() <= 255);
        // short names are untouched by the cap
        assert_eq!(sanitize_file_name("hello"), "hello");
    }

    /// End-to-end pin of the live ENAMETOOLONG repro: a scan whose query
    /// builds a 330-byte result file name must write its results instead of
    /// failing the whole run after the scan completed.
    #[test]
    fn write_text_survives_a_multibyte_name_exceeding_255_bytes() {
        in_temp_cwd(|| {
            let directory = format!("git2mail_output_test_cjk_{}", std::process::id());
            let emails = vec!["a@b.c".to_string()];
            let path = write_text(&directory, &"日".repeat(110), &emails)
                .expect("a 330-byte multibyte name must still write")
                .expect("the file must be written");
            assert!(path.exists());
            let content = fs::read_to_string(&path).expect("result must be readable");
            assert_eq!(content, "a@b.c\n");
        });
    }

    fn correlation_with(
        authors: Vec<crate::correlate::AuthorReport>,
    ) -> crate::correlate::Correlation {
        crate::correlate::Correlation { authors }
    }

    fn author_report(
        name: &str,
        emails: &[&str],
        repos: &[&str],
        languages: &[&str],
        hits: usize,
    ) -> crate::correlate::AuthorReport {
        crate::correlate::AuthorReport {
            author: name.to_string(),
            emails: emails.iter().map(|email| email.to_string()).collect(),
            repos: repos
                .iter()
                .map(|name| crate::correlate::RepoLanguage {
                    name: name.to_string(),
                    language: None,
                })
                .collect(),
            languages: languages
                .iter()
                .map(|language| language.to_string())
                .collect(),
            first_seen_repo: repos.first().unwrap_or(&"").to_string(),
            total_hits: hits,
            last_commit_date: None,
        }
    }

    #[test]
    fn the_csv_export_writes_one_row_per_author_with_a_header() {
        in_temp_cwd(|| {
            let path = std::path::PathBuf::from("authors.csv");
            let correlation = correlation_with(vec![
                author_report(
                    "Alice",
                    &["a@x.com", "b@x.com"],
                    &["acme/one", "acme/two"],
                    &["Rust"],
                    12,
                ),
                author_report("Bob", &["bob@x.com"], &["acme/one"], &["Go", "Rust"], 3),
            ]);
            write_correlation_csv(&path, &correlation).expect("the export must succeed");
            let content = fs::read_to_string(&path).expect("the csv must be readable");
            assert_eq!(
                content,
                "author_name,emails,repositories,dominant_language,commits\n\
                 Alice,a@x.com;b@x.com,acme/one;acme/two,Rust,12\n\
                 Bob,bob@x.com,acme/one,Go,3\n",
                "the sheet shape (header, one row per author, semicolon-joined \
                  multi-values) must be pinned"
            );
            let _ = fs::remove_file(&path);
        });
    }

    #[test]
    fn the_csv_export_quotes_hostile_fields_instead_of_forging_rows() {
        in_temp_cwd(|| {
            let path = std::path::PathBuf::from("hostile.csv");
            // a commit-forged author name carrying RFC 4180 metacharacters:
            // the field must stay ONE cell (quoted, quotes doubled), never
            // extra rows or columns a spreadsheet would render as findings
            let correlation = correlation_with(vec![author_report(
                "Alice\",fake@x.com,\nEvil",
                &["a@x.com"],
                &["acme/one"],
                &["Rust"],
                1,
            )]);
            write_correlation_csv(&path, &correlation).expect("the export must succeed");
            let content = fs::read_to_string(&path).expect("the csv must be readable");
            assert_eq!(
                content,
                "author_name,emails,repositories,dominant_language,commits\n\
                 \"Alice\"\",fake@x.com,\nEvil\",a@x.com,acme/one,Rust,1\n",
                "the hostile name must be one quoted cell with doubled quotes"
            );
            // and the sheet still parses as exactly 2 rows x 5 columns (an
            // RFC 4180 parser: quoted fields span embedded newlines)
            let parse_csv = |content: &str| {
                let mut rows: Vec<Vec<String>> = Vec::new();
                let mut row: Vec<String> = Vec::new();
                let mut cell = String::new();
                let mut in_quotes = false;
                let mut chars = content.chars().peekable();
                while let Some(c) = chars.next() {
                    if in_quotes {
                        if c == '"' {
                            if chars.peek() == Some(&'"') {
                                cell.push('"');
                                chars.next();
                            } else {
                                in_quotes = false;
                            }
                        } else {
                            cell.push(c);
                        }
                    } else {
                        match c {
                            '"' => in_quotes = true,
                            ',' => row.push(std::mem::take(&mut cell)),
                            '\n' => {
                                row.push(std::mem::take(&mut cell));
                                rows.push(std::mem::take(&mut row));
                            }
                            '\r' => {}
                            other => cell.push(other),
                        }
                    }
                }
                if !cell.is_empty() || !row.is_empty() {
                    row.push(cell);
                    rows.push(row);
                }
                rows
            };
            let rows = parse_csv(&content);
            assert_eq!(rows.len(), 2, "one header row plus one data row");
            assert!(rows.iter().all(|row| row.len() == 5), "5 columns per row");
            assert_eq!(rows[1][0], "Alice\",fake@x.com,\nEvil");
            let _ = fs::remove_file(&path);
        });
    }
}
