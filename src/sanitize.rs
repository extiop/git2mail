//! Log-safety for strings derived from untrusted metadata.

/// Replaces every character matching [`is_control_or_invisible`] with `_`:
/// the shared sanitizer for terminal-printed strings and output file names.
pub(crate) fn log_safe(text: &str) -> String {
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
/// — both the FE00..FE0F block and the E0100..E01EF supplement, whose 240
/// invisible characters would otherwise splice into terminal lines and
/// build two byte-distinct but visually identical file names —, the
/// interlinear annotation characters and the invisible
/// Unicode tag block, which can encode hidden ASCII in captured output).
/// The shared log-safety rule for strings derived from untrusted metadata
/// (commit author names/emails, profile fields, key titles…), so a hostile
/// commit can never forge, recolor, visually reorder, invisibly splice or
/// line-break report lines. The JSON *file* path needs no equivalent:
/// `serde_json` escapes the C0 control range itself (U+0000..U+001F — but
/// NOT the C1 range, DEL, or the bidi/format/invisible characters above,
/// which pass through raw there — the JSON report must stay a lossless
/// machine-readable view of the data, so escaping them is left to the JSON
/// reader's rendering, not this file). The `--json -` stdout path is the
/// exception: its output goes to a terminal, so each of its lines runs
/// through [`log_safe`] first (the structural newlines of the
/// pretty-printer are preserved by joining the sanitized lines, so the
/// body stays valid JSON — only invisible/hostile characters become `_`).
pub(crate) fn is_control_or_invisible(c: char) -> bool {
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
    use super::log_safe;
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
