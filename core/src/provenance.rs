//! Report provenance: the UTC generation timestamp and the tool version,
//! flattened into every JSON report so an archived report can always be
//! traced back to the run that produced it. Pure `std`: compiles to
//! `wasm32-unknown-unknown` (the web reports carry the same stamps).

use serde::Serialize;

/// The when and what of a JSON report: the UTC generation timestamp and the
/// tool version. Flattened into every report, so an archived report can
/// always be traced back to the run that produced it (the report still does
/// not know the command line that produced it: archive that next to it for
/// full reproducibility).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
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
    /// Stamps the current instant from the system clock, with the version
    /// of the crate that WRITES the report (the caller passes its own
    /// `env!("CARGO_PKG_VERSION")`: the core cannot know which front end -
    /// CLI or web - is stamping). A clock reporting before the Unix epoch
    /// (a pathological system state) degrades to the epoch itself instead
    /// of panicking: the timestamp would be wrong, but the report must
    /// still be written.
    pub fn now(tool_version: &'static str) -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        Self {
            generated_at: rfc3339_utc(secs),
            tool_version,
        }
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

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

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
}
