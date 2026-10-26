//! Test-only capturing logger: pins at the wiring level that the terminal
//! report builders actually apply the shared log sanitizer, not only that
//! the sanitizer helper works (a dropped `log_safe()` call must fail the
//! suite). Every caller is a test, so the test-only panic allowance applies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::thread::ThreadId;

/// Log lines grouped by the thread that emitted them. Grouping is what
/// makes parallel captures possible: `cargo test` runs test modules in
/// parallel, and a capture must only see its own test's lines - including
/// the lines its spawned scan workers emitted - never a sibling test's.
static RECORDS: std::sync::LazyLock<Mutex<HashMap<ThreadId, Vec<String>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Serializes whole captures: the logger is process-wide, and `cargo test`
/// runs test modules in parallel, so concurrent captures would read each
/// other's lines (or wipe them mid-run). The lock is held across the whole
/// capture - it cannot be [`RECORDS`] itself, which the logger locks inside
/// `f` (holding it here would deadlock).
static CAPTURE_SERIALIZATION: Mutex<()> = Mutex::new(());

static INSTALL: std::sync::Once = std::sync::Once::new();

/// A `log::Log` implementation recording every line into [`RECORDS`],
/// tagged with the emitting thread.
struct Capture;

impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata())
            && let Ok(mut records) = RECORDS.lock()
        {
            records
                .entry(std::thread::current().id())
                .or_default()
                .push(record.args().to_string());
        }
    }

    fn flush(&self) {}
}

/// Runs `f` with the capturing logger installed (once per process) and
/// returns its result together with the log lines it emitted: the calling
/// thread's lines plus the lines of threads that first logged during this
/// capture (the scan workers `f` spawned). Threads that had already logged
/// before the capture started - a sibling test's threads running in
/// parallel - are excluded, so a sibling's "capped at the…" warning can
/// never leak into this capture's assertions.
pub fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    INSTALL.call_once(|| {
        // one logger per process: installed once, before any capture
        let _ = log::set_boxed_logger(Box::new(Capture));
        log::set_max_level(log::LevelFilter::Info);
    });
    // a panicking test releases (but poisons) the lock: keep capturing
    let _serialization = CAPTURE_SERIALIZATION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let me = std::thread::current().id();
    // threads that had already logged are parallel tests' threads: their
    // lines must never reach this capture
    let preexisting: HashSet<ThreadId> = if let Ok(records) = RECORDS.lock() {
        records.keys().copied().collect()
    } else {
        HashSet::new()
    };
    if let Ok(mut records) = RECORDS.lock() {
        records.clear();
    }
    let result = f();
    let mut lines = Vec::new();
    if let Ok(records) = RECORDS.lock() {
        for (thread, thread_lines) in records.iter() {
            if *thread == me || !preexisting.contains(thread) {
                lines.extend(thread_lines.iter().cloned());
            }
        }
    }
    if let Ok(mut records) = RECORDS.lock() {
        records.clear();
    }
    (result, lines)
}

/// A CWD-isolated body for the tests that exercise the relative
/// `results/` layout: the text writer writes relative to the current
/// directory, so the result-file scenarios must not touch the real
/// workspace. The single process-wide chdir lock is shared by every user
/// of this fixture (output tests and CLI-arm tests alike): the chdir is
/// process-wide, so two fixtures restoring "their own" CWD concurrently
/// could restore one another into a deleted temp directory.
///
/// Test-only, but compiled with the crate: callers are `#[cfg(test)]`
/// modules of the lib and the bin.
pub fn in_temp_cwd<T>(f: impl FnOnce() -> T) -> T {
    use std::path::Path;
    use std::sync::{Mutex, OnceLock};
    static CWD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let lock = CWD_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let original = std::env::current_dir().expect("test setup: current dir");
    let temp = std::env::temp_dir().join(format!("git2mail_cwd_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(&temp).expect("test setup: temp cwd");
    std::env::set_current_dir(&temp).expect("test setup: enter temp cwd");
    // panic-safe restore: a test panicking inside `f` must not leave the
    // process CWD inside the temp directory the teardown deletes (every
    // later `current_dir()` of the suite would then fail with NotFound)
    struct RestoreCwd<'a>(&'a Path);
    impl Drop for RestoreCwd<'_> {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(self.0);
        }
    }
    let _restore = RestoreCwd(&original);
    let result = f();
    drop(_restore);
    std::env::set_current_dir(&original).expect("test teardown: restore cwd");
    let _ = std::fs::remove_dir_all(&temp);
    drop(lock);
    result
}
