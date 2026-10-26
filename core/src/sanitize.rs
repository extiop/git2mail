//! Log-safety for strings derived from untrusted metadata.

/// Replaces every character matching [`is_control_or_invisible`] with `_`:
/// the shared sanitizer for terminal-printed strings and output file names.
pub fn log_safe(text: &str) -> String {
    text.chars()
        .map(|c| if is_control_or_invisible(c) { '_' } else { c })
        .collect()
}

/// Whether a character must never reach a terminal-printed string or an
/// output file name raw: control characters (newlines, tabs, ESC and other
/// ANSI escape openers…), the Unicode bidi/format characters (RTL override,
/// isolates), the zero-width / invisible format characters and the
/// remaining invisible-or-line-separating characters a terminal may honor
/// (the LINE/PARAGRAPH SEPARATORs, the soft hyphen, the variation selectors
/// (both the FE00..FE0F block and the E0100..E01EF supplement, whose 240
/// invisible characters would otherwise splice into terminal lines and
/// build two byte-distinct but visually identical file names), the
/// interlinear annotation characters and the invisible
/// Unicode tag block, which can encode hidden ASCII in captured output).
/// The shared log-safety rule for strings derived from untrusted metadata
/// (commit author names/emails, profile fields, key titles…), so a hostile
/// commit can never forge, recolor, visually reorder, invisibly splice or
/// line-break report lines. The JSON *file* path needs no equivalent:
/// `serde_json` escapes the C0 control range itself (U+0000..U+001F - but
/// NOT the C1 range, DEL, or the bidi/format/invisible characters above,
/// which pass through raw there - the JSON report must stay a lossless
/// machine-readable view of the data, so escaping them is left to the JSON
/// reader's rendering, not this file). The `--json -` stdout path is the
/// exception: its output goes to a terminal, so each of its lines runs
/// through [`log_safe`] first (the structural newlines of the
/// pretty-printer are preserved by joining the sanitized lines, so the
/// body stays valid JSON - only invisible/hostile characters become `_`).
pub fn is_control_or_invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // bidi controls (RTL override, isolates, Arabic letter mark)
            '\u{200E}' | '\u{200F}' | '\u{061C}'
                | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
                // zero-width / invisible format characters: visually
                // indistinguishable from nothing, so a hostile name
                // like `alice\u{200B}admin` would splice report text
                | '\u{200B}'..='\u{200D}' | '\u{2060}'..='\u{2064}'
                | '\u{FEFF}'
                // the remaining category-Cf format characters: equally
                // invisible (invisible splices in captured output), found
                // by a character-class sweep against the Unicode Cf table
                | '\u{0600}'..='\u{0605}' | '\u{06DD}' | '\u{070F}'
                | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}'
                | '\u{206A}'..='\u{206F}'
                | '\u{110BD}' | '\u{110CD}'
                | '\u{13430}'..='\u{1343F}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                // line/paragraph separators (categories Zl/Zp: not
                // `is_control`, but a terminal or captured output can
                // still honor them as line breaks) and the remaining
                // invisible characters (soft hyphen, variation
                // selectors, interlinear annotation, the Unicode tag
                // block that encodes hidden ASCII)
                | '\u{2028}' | '\u{2029}' | '\u{00AD}'
                | '\u{FE00}'..='\u{FE0F}' | '\u{E0100}'..='\u{E01EF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{E0000}'..='\u{E007F}'
        )
}

#[cfg(test)]
mod tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn log_safe_neuters_control_characters_and_ansi_escapes() {
        // the terminal report prints commit-derived strings: newlines and
        // ANSI escape openers must never forge or recolor a log line
        assert_eq!(log_safe("jane\nDUPONT\r"), "jane_DUPONT_");
        assert_eq!(log_safe("\x1b[31mevil\x1b[0m"), "_[31mevil_[0m");
        assert_eq!(log_safe("plain@mail.example"), "plain@mail.example");
    }

    #[test]
    fn log_safe_neuters_the_unicode_bidi_and_format_characters() {
        // unlike ESC, the Unicode bidi overrides and isolates are not
        // control characters: a hostile commit author name carrying one
        // would visually reorder the adjacent report content while passing
        // the plain control-character filter
        assert_eq!(log_safe("a\u{202E}b\u{202C}c"), "a_b_c");
        assert_eq!(log_safe("a\u{2066}b\u{2069}c"), "a_b_c");
        assert_eq!(log_safe("a\u{200F}b\u{200E}c"), "a_b_c");
        // U+061C (Arabic Letter Mark) is the remaining Unicode bidi control:
        // category Cf (not caught by `is_control`), so it must be listed too
        assert_eq!(log_safe("a\u{061C}b"), "a_b");
        // the zero-width / invisible format characters (ZWSP, ZWNJ, ZWJ,
        // word joiner and friends, BOM) are equally invisible: a hostile
        // name like `alice\u{200B}admin` would splice report content while
        // printing as plain text
        assert_eq!(log_safe("a\u{200B}b\u{200C}c\u{200D}d"), "a_b_c_d");
        assert_eq!(log_safe("a\u{2060}b\u{2061}c\u{2064}d"), "a_b_c_d");
        assert_eq!(log_safe("a\u{FEFF}b"), "a_b");
        // the line/paragraph separators (categories Zl/Zp, not caught by
        // `is_control`) would still break or split report lines in a
        // terminal or captured output that honors them
        assert_eq!(log_safe("a\u{2028}b\u{2029}c"), "a_b_c");
        // and the remaining invisible characters: soft hyphen, variation
        // selectors, interlinear annotation, the Unicode tag block (which
        // can encode hidden ASCII in captured output)
        assert_eq!(log_safe("a\u{00AD}b"), "a_b");
        assert_eq!(log_safe("a\u{FE0F}b\u{FE00}c"), "a_b_c");
        assert_eq!(log_safe("a\u{FFF9}b\u{FFFB}c"), "a_b_c");
        assert_eq!(log_safe("a\u{E0041}b\u{E007F}c"), "a_b_c");
        assert_eq!(
            log_safe("a\u{00E9}b"),
            "a\u{00E9}b",
            "printable non-ASCII is kept"
        );
    }

    #[test]
    fn log_safe_neuters_every_remaining_invisible_format_character() {
        // the remaining Unicode category-Cf format characters: visually
        // indistinguishable from nothing (invisible splices in captured
        // report lines), so the whole category must be neutralized, not just
        // the bidi and zero-width members. One probe per documented range
        // (full-list sweep of the Cf coverage gaps found by a character-class
        // sweep against the Unicode Cf table).
        for c in [
            '\u{0600}',
            '\u{0605}',
            '\u{06DD}',
            '\u{070F}',
            '\u{0890}',
            '\u{0891}',
            '\u{08E2}',
            '\u{180E}',
            '\u{206A}',
            '\u{206F}',
            '\u{110BD}',
            '\u{110CD}',
            '\u{13430}',
            '\u{1343F}',
            '\u{1BCA0}',
            '\u{1BCA3}',
            '\u{1D173}',
            '\u{1D17A}',
        ] {
            assert_eq!(
                log_safe(&format!("a{c}b")),
                "a_b",
                "U+{:04X} must be neutralized",
                c as u32
            );
        }
    }

    #[test]
    fn the_variation_selector_supplement_is_neutered_like_the_base_block() {
        // the sanitizer comment promises "the variation selectors", but only
        // FE00..FE0F (VS1-16) was listed once: the 240 invisible characters
        // of the Variation Selectors Supplement (U+E0100..U+E01EF, category
        // Mn, neither `is_control` nor Cf) leaked raw into terminal lines
        // and into two byte-distinct but visually identical file names
        for cp in [
            0xE0100usize, // first VS17
            0xE01EF,      // last VS256
            0xE0145,      // an interior value
        ] {
            let c = char::from_u32(cp as u32).expect("a valid scalar");
            assert_eq!(
                log_safe(&format!("a{c}b")),
                "a_b",
                "U+{cp:05X} must be neutralized in log text"
            );
        }
        // the rest of the supplement range: a sampled sweep keeps the whole
        // 240-character block pinned without a 240-iteration loop's noise
        for cp in (0xE0100..=0xE01EF).step_by(7) {
            let c = char::from_u32(cp).expect("a valid scalar");
            assert_eq!(
                log_safe(&format!("a{c}")),
                "a_",
                "U+{cp:05X} must be neutralized"
            );
        }
    }
}

/// Byte ceiling for one sanitized output path component. The per-component
/// limit of the common filesystems is 255 bytes; keeping the ceiling well
/// below it leaves room for the sibling component and any consumer suffix.
const MAX_FILE_NAME_BYTES: usize = 200;
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
pub fn sanitize_file_name(name: &str) -> String {
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
    // so the collapsed class is disambiguated - the same anti-clobber
    // suffix the length cap below uses. A byte-unchanged name keeps its
    // exact file name (`hello` stays `hello`, `Rust` stays `Rust`): the
    // suffix only answers a real loss, it never decorates an untouched
    // name. Two runs of the same query still overwrite each other by
    // design (a rerun refreshes the results); note that on a
    // case-insensitive filesystem (macOS APFS, Windows NTFS) two targets
    // differing only by case (`rust lang` vs `Rust Lang`) share one file
    // name - the target and its case are visible in every report line, and
    // the JSON report carries the exact target.
    if candidate != name {
        candidate = format!("{candidate}-{:016x}", stable_hash(name));
    }
    // A filesystem path component is limited to 255 bytes: a long multibyte
    // search query (GitHub caps queries at 256 *characters*, so a 110-CJK-
    // character query is accepted by the API but its raw file name weighs
    // 269 bytes) used to make the whole output write fail with
    // ENAMETOOLONG *after* the scan had completed, discarding the results.
    // The sanitized name is therefore capped at the crate-private `MAX_FILE_NAME_BYTES` ceiling,
    // cut on a char boundary; when the cap applies, a hash of the full RAW
    // name is appended so two distinct long queries cannot silently clobber
    // each other's result file (hashing the truncated candidate instead
    // would discard any earlier suffix and collide two long names sharing
    // the same prefix - the raw name is what makes the targets distinct)
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
pub fn stable_hash(name: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let mut hash = FNV_OFFSET_BASIS;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod file_name_tests {
    // Tests may unwrap, expect and panic freely: a failing assertion must
    // be loud, so the zero-panic lints do not apply to the test modules.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

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

    /// End-to-end pin of the live ENAMETOOLONG repro: a scan whose query
    /// builds a 330-byte result file name must write its results instead of
    /// failing the whole run after the scan completed.
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
}
