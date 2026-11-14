use super::{Issue, Rule, Severity};

/// Detects classic Cc control characters (excluding TAB/LF, and CR as part
/// of a CRLF line ending).
/// Zero-width and other invisible Unicode are handled by `InvisibleCharactersRule`.
pub struct NonPrintableCharRule {
    /// Also scan for Cc control characters (enabled by --include-cc)
    pub include_cc: bool,
}

impl NonPrintableCharRule {
    pub const fn new() -> Self {
        Self { include_cc: false }
    }
}

impl Rule for NonPrintableCharRule {
    fn name(&self) -> &'static str {
        "non-printable-chars"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for (col, ch) in line.chars().enumerate() {
                // Check for control characters except TAB/LF. This covers C0
                // (U+0000-U+001F) and C1 (U+0080-U+009F) controls. `lines()`
                // already strips the CR of a CRLF ending, so any CR left is
                // mid-line, where it makes a terminal overwrite the text
                // before it.
                if ch.is_control() && !matches!(ch, '\t' | '\n') {
                    // When --include-cc is off, only flag the most suspicious ones
                    // (null byte, backspace, carriage return, escape, delete)
                    let is_high_signal = matches!(ch as u32, 0x00 | 0x08 | 0x0D | 0x1B | 0x7F);

                    if is_high_signal || self.include_cc {
                        issues.push(Issue::new(
                            self.name(),
                            Severity::Error,
                            line_num + 1,
                            Some(col + 1),
                            format!(
                                "Non-printable control character U+{:04X} detected",
                                ch as u32
                            ),
                        ));
                    }
                }
            }
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_null_byte() {
        let rule = NonPrintableCharRule::new();
        let content = "Normal text\nText with null: \0here\nMore text";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "non-printable-chars");
        assert!(issues[0].message.contains("U+0000"));
    }

    #[test]
    fn detects_escape_char() {
        let rule = NonPrintableCharRule::new();
        let content = "Text with \u{001B}escape";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("U+001B"));
    }

    #[test]
    fn include_cc_detects_all_controls() {
        let mut rule = NonPrintableCharRule::new();
        rule.include_cc = true;
        // U+0001 (SOH) is a low-signal control char, only detected with --include-cc
        let content = "Text with \u{0001}control";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
    }

    #[test]
    fn skips_low_signal_controls_by_default() {
        let rule = NonPrintableCharRule::new();
        // U+0001 (SOH) should NOT be flagged without --include-cc
        let content = "Text with \u{0001}control";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn allows_standard_whitespace() {
        let rule = NonPrintableCharRule::new();
        let content = "Line with tabs\tand spaces\nAnd newlines\r\n";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn no_false_positives_on_clean_text() {
        let rule = NonPrintableCharRule::new();
        let content = "This is completely normal text\nWith standard ASCII characters only";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn detects_mid_line_carriage_return() {
        let rule = NonPrintableCharRule::new();
        let issues = rule.check("Safe text\rEvil text\n");

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].column, Some(10));
        assert!(issues[0].message.contains("U+000D"));
    }

    #[test]
    fn allows_crlf_line_endings() {
        let rule = NonPrintableCharRule::new();
        assert!(rule.check("one\r\ntwo\r\nthree").is_empty());
    }
}
