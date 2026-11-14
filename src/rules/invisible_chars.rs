use super::{
    Issue, Rule, Severity, invisible_char_description, is_emoji_presentation, is_unicode_tag,
};

pub struct InvisibleCharactersRule {
    pub include_confusable_spaces: bool,
}

impl InvisibleCharactersRule {
    pub const fn new() -> Self {
        Self {
            include_confusable_spaces: false,
        }
    }

    pub const fn with_confusable_spaces(mut self) -> Self {
        self.include_confusable_spaces = true;
        self
    }

    /// Decodes a Unicode tag character (U+E0000 + ASCII code) to its ASCII
    /// character, or returns `None` for any other character.
    const fn decode_unicode_tag(ch: char) -> Option<char> {
        if !is_unicode_tag(ch) {
            return None;
        }
        #[expect(
            clippy::cast_possible_truncation,
            reason = "Tag codepoints are U+E0000-U+E007F, so the offset fits in u8"
        )]
        let ascii = (ch as u32 - 0xE0000) as u8;
        Some(ascii as char)
    }

    /// Returns `true` when `ch` is a Unicode codepoint that commonly serves as
    /// an emoji base — i.e. the preceding character in an `<emoji> + VS-16`
    /// sequence.  This covers:
    ///  - Emoticons, Dingbats, Symbols, Transport/Map symbols, etc.
    ///  - Miscellaneous Symbols & Pictographs, Supplemental Symbols
    ///  - Flags (regional indicators), skin-tone modifiers
    ///  - Common text characters with emoji presentation (digits, #, *, ©, ®, ‼, etc.)
    pub const fn is_emoji_base(ch: char) -> bool {
        let cp = ch as u32;
        matches!(cp,
            // ASCII characters with emoji variants (#, *, 0-9)
            0x0023 | 0x002A | 0x0030..=0x0039 |
            // Latin-1 symbols with emoji presentation
            0x00A9 | 0x00AE |
            // General Punctuation
            0x203C | 0x2049 |
            // Letterlike Symbols
            0x2122 | 0x2139 |
            // Arrows
            0x2194..=0x2199 | 0x21A9..=0x21AA |
            // Miscellaneous Technical
            0x231A..=0x231B | 0x2328 | 0x23CF |
            0x23E9..=0x23F3 | 0x23F8..=0x23FA |
            // Enclosed Alphanumerics
            0x24C2 |
            // Geometric Shapes
            0x25AA..=0x25AB | 0x25B6 | 0x25C0 | 0x25FB..=0x25FE |
            // Miscellaneous Symbols
            0x2600..=0x27BF |
            // Supplemental Arrows / Dingbats
            0x2934..=0x2935 | 0x2B05..=0x2B07 | 0x2B1B..=0x2B1C | 0x2B50 | 0x2B55 |
            // CJK Symbols
            0x3030 | 0x303D | 0x3297 | 0x3299 |
            // Enclosed Ideographic Supplement
            0x1F000..=0x1F02F |
            // Mahjong Tiles, Domino Tiles
            0x1F030..=0x1F09F |
            // Playing Cards
            0x1F0A0..=0x1F0FF |
            // Enclosed Alphanumeric Supplement
            0x1F100..=0x1F1FF |
            // Enclosed Ideographic Supplement
            0x1F200..=0x1F2FF |
            // Miscellaneous Symbols and Pictographs
            0x1F300..=0x1F5FF |
            // Emoticons
            0x1F600..=0x1F64F |
            // Transport and Map Symbols
            0x1F680..=0x1F6FF |
            // Geometric Shapes Extended
            0x1F780..=0x1F7FF |
            // Supplemental Symbols and Pictographs
            0x1F900..=0x1F9FF |
            // Symbols and Pictographs Extended-A
            0x1FA00..=0x1FA6F |
            // Symbols and Pictographs Extended-B
            0x1FA70..=0x1FAFF |
            // Tags block (regional flag base)
            0xE0020..=0xE007F
        )
    }

    /// Check if character is a confusable/suspicious space
    const fn is_confusable_space(ch: char) -> Option<&'static str> {
        match ch {
            '\u{00A0}' => Some("NO-BREAK SPACE"),
            '\u{2000}' => Some("EN QUAD"),
            '\u{2001}' => Some("EM QUAD"),
            '\u{2002}' => Some("EN SPACE"),
            '\u{2003}' => Some("EM SPACE"),
            '\u{2004}' => Some("THREE-PER-EM SPACE"),
            '\u{2005}' => Some("FOUR-PER-EM SPACE"),
            '\u{2006}' => Some("SIX-PER-EM SPACE"),
            '\u{2007}' => Some("FIGURE SPACE"),
            '\u{2008}' => Some("PUNCTUATION SPACE"),
            '\u{2009}' => Some("THIN SPACE"),
            '\u{200A}' => Some("HAIR SPACE"),
            '\u{202F}' => Some("NARROW NO-BREAK SPACE"),
            '\u{205F}' => Some("MEDIUM MATHEMATICAL SPACE"),
            '\u{2800}' => Some("BRAILLE PATTERN BLANK"),
            '\u{3000}' => Some("IDEOGRAPHIC SPACE"),
            '\u{3164}' => Some("HANGUL FILLER"),
            '\u{FFA0}' => Some("HALFWIDTH HANGUL FILLER"),
            _ => None,
        }
    }
}

impl Rule for InvisibleCharactersRule {
    fn name(&self) -> &'static str {
        "invisible-characters"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line_idx = line_num + 1;
            // (start column, decoded ASCII) of the Unicode tag run in progress
            let mut tag_run: Option<(usize, String)> = None;
            let mut prev_char: Option<char> = None;

            for (col, ch) in line.chars().enumerate() {
                let col_idx = col + 1;

                // Unicode tags are reported once per run, with the hidden
                // text decoded so the reviewer can see what was smuggled.
                if let Some(decoded) = Self::decode_unicode_tag(ch) {
                    tag_run
                        .get_or_insert_with(|| (col_idx, String::new()))
                        .1
                        .push(decoded);
                    prev_char = Some(ch);
                    continue;
                }
                if let Some((start_col, payload)) = tag_run.take() {
                    issues.push(self.tag_run_issue(line_idx, start_col, &payload));
                }

                if is_emoji_presentation(prev_char, ch) {
                    prev_char = Some(ch);
                    continue;
                }

                if let Some(description) = invisible_char_description(ch) {
                    issues.push(Issue::new(
                        self.name(),
                        Severity::Error,
                        line_idx,
                        Some(col_idx),
                        format!("Invisible character: {description}"),
                    ));
                }

                if self.include_confusable_spaces
                    && let Some(description) = Self::is_confusable_space(ch)
                {
                    issues.push(Issue::new(
                        self.name(),
                        Severity::Warning,
                        line_idx,
                        Some(col_idx),
                        format!("Confusable space: {description}"),
                    ));
                }

                prev_char = Some(ch);
            }

            if let Some((start_col, payload)) = tag_run {
                issues.push(self.tag_run_issue(line_idx, start_col, &payload));
            }
        }

        issues
    }
}

impl InvisibleCharactersRule {
    fn tag_run_issue(&self, line: usize, column: usize, payload: &str) -> Issue {
        Issue::new(
            self.name(),
            Severity::Error,
            line,
            Some(column),
            format!(
                "{} hidden Unicode tag character{} (ASCII smuggling), decoded: '{payload}'",
                payload.chars().count(),
                if payload.chars().count() == 1 {
                    ""
                } else {
                    "s"
                },
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zero_width_space() {
        let rule = InvisibleCharactersRule::new();
        let content = "Text with\u{200B}invisible space";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("ZERO WIDTH SPACE"))
        );
    }

    #[test]
    fn detects_zero_width_joiner() {
        let rule = InvisibleCharactersRule::new();
        let content = "Text with\u{200D}joiner";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("ZERO WIDTH JOINER"))
        );
    }

    #[test]
    fn detects_bom() {
        let rule = InvisibleCharactersRule::new();
        let content = "\u{FEFF}Text with BOM";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.message.contains("BOM")));
    }

    #[test]
    fn detects_multiple_invisible_chars() {
        let rule = InvisibleCharactersRule::new();
        let content = "\u{200B}\u{200C}\u{200D}Three different invisible chars";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 3);
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let rule = InvisibleCharactersRule::new();
        let content = "Normal text without any invisible characters";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn correctly_identifies_position() {
        let rule = InvisibleCharactersRule::new();
        let content = "abc\u{200B}def";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].line, 1);
        assert_eq!(issues[0].column, Some(4));
    }

    #[test]
    fn detects_unicode_tags_ascii_smuggling() {
        let rule = InvisibleCharactersRule::new();
        // Encode "Hi" as Unicode tags: U+E0048 U+E0069
        let content = "Normal text\u{E0048}\u{E0069}here";
        let issues = rule.check(content);

        // One finding per run, at the run's first character, with the payload
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].column, Some(12));
        assert!(
            issues[0]
                .message
                .contains("2 hidden Unicode tag characters (ASCII smuggling), decoded: 'Hi'")
        );
    }

    #[test]
    fn separate_tag_runs_are_reported_separately() {
        let rule = InvisibleCharactersRule::new();
        let content = "a\u{E0041}b\u{E0042}\u{E0043}\nc\u{E0044}";
        let messages: Vec<String> = rule.check(content).into_iter().map(|i| i.message).collect();
        assert_eq!(messages.len(), 3, "{messages:?}");
        assert!(messages[0].ends_with("decoded: 'A'"));
        assert!(messages[1].ends_with("decoded: 'BC'"));
        assert!(messages[2].ends_with("decoded: 'D'"));
    }

    #[test]
    fn detects_standalone_variation_selector_16() {
        let rule = InvisibleCharactersRule::new();
        // VS-16 NOT preceded by an emoji base — suspicious
        let content = "text\u{FE0F}here";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("VARIATION SELECTOR"))
        );
    }

    #[test]
    fn ignores_vs16_after_emoji() {
        let rule = InvisibleCharactersRule::new();
        // ❤ (U+2764) + VS-16 = standard color emoji heart ❤️
        let content = "I \u{2764}\u{FE0F} Rust";
        let issues = rule.check(content);

        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("VARIATION SELECTOR")),
            "VS-16 after emoji should NOT be flagged, got: {issues:?}"
        );
    }

    #[test]
    fn ignores_vs16_after_various_emoji() {
        let rule = InvisibleCharactersRule::new();
        // Test multiple emoji + VS-16 combos that appear in real skill files
        for input in [
            "✅\u{FE0F} VERIFIED", // check mark + VS16
            "⚠\u{FE0F} WARNING",   // warning sign + VS16
            "❌\u{FE0F} FAILED",   // cross mark + VS16
            "☁\u{FE0F} cloud",     // cloud + VS16
            "1\u{FE0F}\u{20E3}",   // keycap 1 (digit + VS16 + combining enclosing keycap)
            "#\u{FE0F}\u{20E3}",   // keycap # (hash + VS16 + combining enclosing keycap)
            "©\u{FE0F}",           // copyright + VS16
            "🏛\u{FE0F} building",  // classical building (supplemental) + VS16
        ] {
            let issues = rule.check(input);
            assert!(
                !issues
                    .iter()
                    .any(|i| i.message.contains("VARIATION SELECTOR")),
                "VS-16 after emoji should NOT be flagged in: {input}"
            );
        }
    }

    #[test]
    fn ignores_vs15_after_emoji() {
        let rule = InvisibleCharactersRule::new();
        // VS-15 forces text presentation — also legitimate
        let content = "❤\u{FE0E} text heart";
        let issues = rule.check(content);

        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("VARIATION SELECTOR")),
            "VS-15 after emoji should NOT be flagged"
        );
    }

    #[test]
    fn still_detects_other_variation_selectors() {
        let rule = InvisibleCharactersRule::new();
        // VS-1 through VS-14 should still be flagged (CJK glyph selectors, rare in skill files)
        let content = "text\u{FE01}here";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("VARIATION SELECTOR"))
        );
    }

    #[test]
    fn detects_directional_overrides() {
        let rule = InvisibleCharactersRule::new();
        let content = "text\u{202E}reversed\u{202C}normal";
        let issues = rule.check(content);

        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("RIGHT-TO-LEFT OVERRIDE"))
        );
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("POP DIRECTIONAL FORMATTING"))
        );
    }

    #[test]
    fn detects_invisible_operators() {
        let rule = InvisibleCharactersRule::new();
        let content = "a\u{2062}b";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.message.contains("INVISIBLE TIMES")));
    }

    #[test]
    fn detects_deprecated_format_controls() {
        let rule = InvisibleCharactersRule::new();
        let content = "text\u{206A}here";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.message.contains("deprecated")));
    }

    #[test]
    fn confusable_spaces_disabled_by_default() {
        let rule = InvisibleCharactersRule::new();
        let content = "text\u{00A0}here"; // NBSP
        let issues = rule.check(content);

        // NBSP should NOT be flagged without include_confusable_spaces
        assert!(!issues.iter().any(|i| i.message.contains("NO-BREAK SPACE")));
    }

    #[test]
    fn confusable_spaces_when_enabled() {
        let rule = InvisibleCharactersRule::new().with_confusable_spaces();
        let content = "text\u{00A0}here"; // NBSP
        let issues = rule.check(content);

        assert!(issues.iter().any(|i| i.message.contains("NO-BREAK SPACE")));
    }

    #[test]
    fn detects_hangul_filler_when_confusable_enabled() {
        let rule = InvisibleCharactersRule::new().with_confusable_spaces();
        let content = "text\u{3164}here";
        let issues = rule.check(content);

        assert!(issues.iter().any(|i| i.message.contains("HANGUL FILLER")));
    }

    #[test]
    fn detects_combining_grapheme_joiner() {
        let rule = InvisibleCharactersRule::new();
        let content = "te\u{034F}xt";
        let issues = rule.check(content);

        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("COMBINING GRAPHEME JOINER"))
        );
    }

    #[test]
    fn detects_bidi_isolates() {
        let rule = InvisibleCharactersRule::new();
        let content = "a\u{2066}b\u{2069}c";
        let issues = rule.check(content);

        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("LEFT-TO-RIGHT ISOLATE"))
        );
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("POP DIRECTIONAL ISOLATE"))
        );
    }
}
