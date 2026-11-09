use super::{Issue, Rule, Severity};

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

    /// Check if a character is a Unicode tag (U+E0000-U+E007F)
    fn is_unicode_tag(ch: char) -> bool {
        let cp = ch as u32;
        (0xE0000..=0xE007F).contains(&cp)
    }

    /// Decode a Unicode tag character to ASCII
    fn decode_unicode_tag(ch: char) -> Option<char> {
        let cp = ch as u32;
        if (0xE0000..=0xE007F).contains(&cp) {
            // U+E0000 + ascii_code
            #[expect(
                clippy::cast_possible_truncation,
                reason = "Tag codepoints are in range 0xE0000-0xE007F, difference always fits in u8"
            )]
            let ascii_code = (cp - 0xE0000) as u8;
            if ascii_code <= 0x7F {
                return Some(ascii_code as char);
            }
        }
        None
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

    /// Returns true if `ch` is a variation selector used for emoji/text
    /// presentation (VS-15 = text style, VS-16 = emoji style).
    const fn is_emoji_variation_selector(ch: char) -> bool {
        matches!(ch, '\u{FE0E}' | '\u{FE0F}')
    }

    /// Get the name/description for an invisible character
    fn get_char_description(ch: char) -> Option<&'static str> {
        match ch {
            // Zero-width characters
            '\u{200B}' => Some("ZERO WIDTH SPACE"),
            '\u{200C}' => Some("ZERO WIDTH NON-JOINER"),
            '\u{200D}' => Some("ZERO WIDTH JOINER"),
            '\u{FEFF}' => Some("ZERO WIDTH NO-BREAK SPACE (BOM)"),
            '\u{2060}' => Some("WORD JOINER"),
            '\u{00AD}' => Some("SOFT HYPHEN"),
            '\u{180E}' => Some("MONGOLIAN VOWEL SEPARATOR"),
            '\u{034F}' => Some("COMBINING GRAPHEME JOINER"),

            // Directional marks
            '\u{200E}' => Some("LEFT-TO-RIGHT MARK"),
            '\u{200F}' => Some("RIGHT-TO-LEFT MARK"),
            '\u{061C}' => Some("ARABIC LETTER MARK"),
            '\u{202A}' => Some("LEFT-TO-RIGHT EMBEDDING"),
            '\u{202B}' => Some("RIGHT-TO-LEFT EMBEDDING"),
            '\u{202C}' => Some("POP DIRECTIONAL FORMATTING"),
            '\u{202D}' => Some("LEFT-TO-RIGHT OVERRIDE"),
            '\u{202E}' => Some("RIGHT-TO-LEFT OVERRIDE"),
            '\u{2066}' => Some("LEFT-TO-RIGHT ISOLATE"),
            '\u{2067}' => Some("RIGHT-TO-LEFT ISOLATE"),
            '\u{2068}' => Some("FIRST STRONG ISOLATE"),
            '\u{2069}' => Some("POP DIRECTIONAL ISOLATE"),

            // Invisible operators
            '\u{2061}' => Some("FUNCTION APPLICATION (invisible operator)"),
            '\u{2062}' => Some("INVISIBLE TIMES"),
            '\u{2063}' => Some("INVISIBLE SEPARATOR"),
            '\u{2064}' => Some("INVISIBLE PLUS"),

            // Deprecated format controls
            '\u{206A}' => Some("INHIBIT SYMMETRIC SWAPPING (deprecated)"),
            '\u{206B}' => Some("ACTIVATE SYMMETRIC SWAPPING (deprecated)"),
            '\u{206C}' => Some("INHIBIT ARABIC FORM SHAPING (deprecated)"),
            '\u{206D}' => Some("ACTIVATE ARABIC FORM SHAPING (deprecated)"),
            '\u{206E}' => Some("NATIONAL DIGIT SHAPES (deprecated)"),
            '\u{206F}' => Some("NOMINAL DIGIT SHAPES (deprecated)"),

            // Variation Selectors 1-16 (U+FE00-U+FE0F)
            '\u{FE00}'..='\u{FE0F}' => {
                let vs_num = ch as u32 - 0xFE00 + 1;
                Some(match vs_num {
                    1 => "VARIATION SELECTOR-1",
                    2 => "VARIATION SELECTOR-2",
                    3 => "VARIATION SELECTOR-3",
                    4 => "VARIATION SELECTOR-4",
                    5 => "VARIATION SELECTOR-5",
                    6 => "VARIATION SELECTOR-6",
                    7 => "VARIATION SELECTOR-7",
                    8 => "VARIATION SELECTOR-8",
                    9 => "VARIATION SELECTOR-9",
                    10 => "VARIATION SELECTOR-10",
                    11 => "VARIATION SELECTOR-11",
                    12 => "VARIATION SELECTOR-12",
                    13 => "VARIATION SELECTOR-13",
                    14 => "VARIATION SELECTOR-14",
                    15 => "VARIATION SELECTOR-15",
                    16 => "VARIATION SELECTOR-16",
                    _ => "VARIATION SELECTOR",
                })
            }

            // Unicode Tags
            ch if Self::is_unicode_tag(ch) => Some("UNICODE TAG (ASCII smuggling)"),

            // Variation Selectors 17-256 (U+E0100-U+E01EF)
            '\u{E0100}'..='\u{E01EF}' => {
                let vs_num = ch as u32 - 0xE0100 + 17;
                Some(match vs_num {
                    17 => "VARIATION SELECTOR-17",
                    18 => "VARIATION SELECTOR-18",
                    19 => "VARIATION SELECTOR-19",
                    20 => "VARIATION SELECTOR-20",
                    21 => "VARIATION SELECTOR-21",
                    22 => "VARIATION SELECTOR-22",
                    23 => "VARIATION SELECTOR-23",
                    24 => "VARIATION SELECTOR-24",
                    25 => "VARIATION SELECTOR-25",
                    26 => "VARIATION SELECTOR-26",
                    27 => "VARIATION SELECTOR-27",
                    28 => "VARIATION SELECTOR-28",
                    29 => "VARIATION SELECTOR-29",
                    30 => "VARIATION SELECTOR-30",
                    31 => "VARIATION SELECTOR-31",
                    32 => "VARIATION SELECTOR-32",
                    _ => "VARIATION SELECTOR",
                })
            }

            _ => None,
        }
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
        let mut unicode_tag_payloads: Vec<(usize, usize, String)> = Vec::new(); // (line, start_col, decoded)

        for (line_num, line) in content.lines().enumerate() {
            let line_idx = line_num + 1;
            let mut current_tag_run: Option<(usize, Vec<char>)> = None; // (start_col, chars)
            let mut prev_char: Option<char> = None;

            for (col, ch) in line.chars().enumerate() {
                let col_idx = col + 1;

                // Skip VS-15/VS-16 when they follow an emoji base character.
                // This is standard emoji presentation formatting (e.g. ❤\uFE0F).
                if Self::is_emoji_variation_selector(ch)
                    && let Some(prev) = prev_char
                    && Self::is_emoji_base(prev)
                {
                    prev_char = Some(ch);
                    continue;
                }

                // Check for Unicode tag characters
                if Self::is_unicode_tag(ch) {
                    if current_tag_run.is_none() {
                        current_tag_run = Some((col_idx, Vec::new()));
                    }
                    if let Some((_, ref mut chars)) = current_tag_run
                        && let Some(decoded) = Self::decode_unicode_tag(ch)
                    {
                        chars.push(decoded);
                    }

                    issues.push(Issue {
                        severity: Severity::Error,
                        line: line_idx,
                        column: Some(col_idx),
                        message: format!(
                            "Unicode tag character (ASCII smuggling): U+{:04X}",
                            ch as u32
                        ),
                        rule: self.name().to_string(),
                    });
                    continue;
                } else if let Some((start_col, decoded_chars)) = current_tag_run.take() {
                    // End of tag run - save the decoded payload
                    if !decoded_chars.is_empty() {
                        let decoded: String = decoded_chars.iter().collect();
                        unicode_tag_payloads.push((line_idx, start_col, decoded));
                    }
                }

                // Check for invisible characters
                if let Some(description) = Self::get_char_description(ch) {
                    let message = if Self::is_unicode_tag(ch) {
                        // Already handled above
                        continue;
                    } else {
                        format!("Invisible character: {description}")
                    };

                    issues.push(Issue {
                        severity: Severity::Error,
                        line: line_idx,
                        column: Some(col_idx),
                        message,
                        rule: self.name().to_string(),
                    });
                }

                // Check for confusable spaces if enabled
                if self.include_confusable_spaces
                    && let Some(description) = Self::is_confusable_space(ch)
                {
                    issues.push(Issue {
                        severity: Severity::Warning,
                        line: line_idx,
                        column: Some(col_idx),
                        message: format!("Confusable space: {description}"),
                        rule: self.name().to_string(),
                    });
                }

                prev_char = Some(ch);
            }

            // Handle tag run that extends to end of line
            if let Some((start_col, decoded_chars)) = current_tag_run
                && !decoded_chars.is_empty()
            {
                let decoded: String = decoded_chars.iter().collect();
                unicode_tag_payloads.push((line_idx, start_col, decoded));
            }
        }

        // Add summary issues for Unicode tag payloads
        for (line, col, payload) in unicode_tag_payloads {
            issues.push(Issue {
                severity: Severity::Error,
                line,
                column: Some(col),
                message: format!(
                    "Decoded Unicode tag payload: '{}'",
                    payload.replace('\n', "\\n").replace('\r', "\\r")
                ),
                rule: self.name().to_string(),
            });
        }

        issues
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

        // Should detect individual tag chars + decoded payload
        assert!(issues.iter().any(|i| i.message.contains("Unicode tag")));
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("Decoded Unicode tag payload: 'Hi'"))
        );
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
