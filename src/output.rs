//! Result writers: legacy text files and opt-in JSON reports.
//!
//! All paths are relative to the current working directory (`./results/…`),
//! which fixes the `cargo install` bug where results were written next to the
//! original Cargo project root: `get_project_root()` is gone.

use crate::errors::Error;
use log::info;
use serde_json::json;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Writes the legacy text output: one email per line, into
/// `results/<directory>/<file_name>` relative to the current working
/// directory. The text format is unchanged.
///
/// # Errors
///
/// Returns [`Error::NoResults`] when there is nothing to write, or
/// [`Error::OutputWrite`] carrying the offending path when the results
/// directory or the file itself cannot be created or written. Never panics.
pub fn write_text(directory: &str, file_name: &str, emails: &[String]) -> Result<PathBuf, Error> {
    if emails.is_empty() {
        return Err(Error::NoResults);
    }
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
        Error::OutputWrite(format!("cannot create {}: {err}", dir_path.display()))
    })?;
    let mut file = File::create(&file_path).map_err(|err| {
        Error::OutputWrite(format!("cannot create {}: {err}", file_path.display()))
    })?;
    for email in emails {
        writeln!(file, "{email}").map_err(|err| {
            Error::OutputWrite(format!("cannot write {}: {err}", file_path.display()))
        })?;
    }
    info!("[+] Result is available at {}", file_path.display());
    Ok(file_path)
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
fn sanitize_file_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '?' | '*' | '"' | '<' | '>' | '|') {
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
    if WINDOWS_RESERVED_DEVICE_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        format!("_{candidate}")
    } else {
        candidate.to_string()
    }
}

/// Writes the opt-in JSON report to `path`:
/// `{ "target", "mode": "repository|profile|search", "emails", "scanned": { "repos", "pages" } }`.
/// The JSON report is an addition: the text output is always written too.
///
/// # Errors
///
/// Returns [`Error::OutputWrite`] when the report cannot be written (the
/// path is carried in the error) and [`Error::Json`] when the report cannot
/// be serialized. Never panics.
pub fn write_json(
    path: &Path,
    target: &str,
    mode: &str,
    emails: &[String],
    repos_scanned: usize,
    pages_fetched: usize,
) -> Result<(), Error> {
    let report = json!({
        "target": target,
        "mode": mode,
        "emails": emails,
        "scanned": { "repos": repos_scanned, "pages": pages_fetched },
    });
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|err| {
            Error::OutputWrite(format!("cannot create {}: {err}", parent.display()))
        })?;
    }
    let body = serde_json::to_string_pretty(&report)?;
    fs::write(path, &body)
        .map_err(|err| Error::OutputWrite(format!("cannot write {}: {err}", path.display())))?;
    info!("[+] JSON report is available at {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::Mutex;

    /// Serializes the tests that move the process working directory:
    /// `set_current_dir` is process-wide, so concurrent tests would
    /// otherwise observe each other's CWD.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    /// Runs `f` inside a fresh per-process temp directory: the CWD-relative
    /// `results/` outputs never depend on (nor pollute) the real working
    /// directory, so a read-only CWD or leftover results from a previous run
    /// cannot break the tests.
    fn in_temp_cwd<T>(f: impl FnOnce() -> T) -> T {
        let lock = CWD_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let original = std::env::current_dir().expect("test setup: current dir");
        let temp =
            std::env::temp_dir().join(format!("git2mail_output_cwd_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).expect("test setup: temp cwd");
        std::env::set_current_dir(&temp).expect("test setup: enter temp cwd");
        let result = f();
        std::env::set_current_dir(&original).expect("test teardown: restore cwd");
        let _ = fs::remove_dir_all(&temp);
        drop(lock);
        result
    }

    #[test]
    fn write_text_writes_one_email_per_line_relative_to_cwd() {
        in_temp_cwd(|| {
            // unique directory so parallel test runs never collide
            let directory = format!("git2mail_output_test_one_line_{}", std::process::id());
            let emails = vec!["a@b.c".to_string(), "d@e.f".to_string()];

            let path = write_text(&directory, "scan", &emails).expect("text output must write");

            let content = fs::read_to_string(&path).expect("result must be readable");
            assert_eq!(content, "a@b.c\nd@e.f\n");
            // path is relative to the (temp) current working directory
            assert!(path.starts_with("results/"));
        });
    }

    #[test]
    fn write_text_rejects_empty_results() {
        let error = write_text("whatever", "empty", &[]).expect_err("empty results must fail");
        assert!(matches!(error, Error::NoResults));
    }

    #[test]
    fn write_text_sanitizes_unsafe_file_names() {
        in_temp_cwd(|| {
            let directory = format!("git2mail_output_test_unsafe_{}", std::process::id());
            let emails = vec!["a@b.c".to_string()];

            // a '/' in a raw query would escape the results directory
            let path = write_text(&directory, "a/b", &emails).expect("text output must write");
            assert_eq!(path, Path::new("results").join(&directory).join("a_b"));

            // Windows-reserved characters are replaced, trailing dots/spaces trimmed
            let path =
                write_text(&directory, "language:rust ", &emails).expect("text output must write");
            assert_eq!(
                path,
                Path::new("results").join(&directory).join("language_rust")
            );

            // a name entirely made of dots would be a directory: fall back to "_"
            let path = write_text(&directory, "..", &emails).expect("text output must write");
            assert_eq!(path, Path::new("results").join(&directory).join("_"));
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
                let path =
                    write_text(&directory, reserved, &emails).expect("text output must write");
                let expected = format!("_{reserved}");
                assert_eq!(path, Path::new("results").join(&directory).join(expected));
            }

            // the reservation also holds for "name.extension" forms
            for reserved in ["CON.txt", "nul.json"] {
                let path =
                    write_text(&directory, reserved, &emails).expect("text output must write");
                let expected = format!("_{reserved}");
                assert_eq!(path, Path::new("results").join(&directory).join(expected));
            }

            // control characters are replaced, like the other illegal characters
            let path = write_text(&directory, "a\nb", &emails).expect("text output must write");
            assert_eq!(path, Path::new("results").join(&directory).join("a_b"));
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

    #[test]
    fn write_json_maps_a_filesystem_failure_to_output_write_with_the_path() {
        // writing the report onto a directory path must surface as an
        // OutputWrite carrying that path
        let directory = std::env::temp_dir().join(format!(
            "git2mail_output_test_json_blocker_{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).expect("test setup: blocker directory");

        let error = write_json(
            &directory,
            "target",
            "repository",
            &["a@b.c".to_string()],
            1,
            1,
        )
        .expect_err("a directory path must fail");
        assert!(
            matches!(error, Error::OutputWrite(details) if details.contains(&directory.display().to_string()))
        );

        fs::remove_dir(&directory).ok();
    }

    #[test]
    fn write_json_serializes_the_spec_shape() {
        let path = std::env::temp_dir().join(format!(
            "git2mail_output_test_{}_report.json",
            std::process::id()
        ));
        write_json(
            &path,
            "https://github.com/extiop/ctf",
            "repository",
            &["a@b.c".to_string()],
            1,
            3,
        )
        .expect("json output must write");

        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report must be readable"))
                .expect("report must be valid JSON");
        assert_eq!(parsed["target"], "https://github.com/extiop/ctf");
        assert_eq!(parsed["mode"], "repository");
        assert_eq!(parsed["emails"], serde_json::json!(["a@b.c"]));
        assert_eq!(parsed["scanned"]["repos"], 1);
        assert_eq!(parsed["scanned"]["pages"], 3);
        fs::remove_file(&path).ok();
    }
}
