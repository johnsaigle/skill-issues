use super::{Issue, Rule, Severity};

/// Warns when a skill markdown file exceeds a threshold line count.
///
/// Skill marketplaces often truncate long files, which is a known vector for
/// hiding exploits. Even locally, oversized skills are harder to audit and
/// may indicate bundled payloads or obfuscation attempts.
///
/// Default threshold: 500 lines. This catches abnormally large skills while
/// allowing reasonably detailed documentation.
pub struct ExcessiveLengthRule {
    pub max_lines: usize,
}

impl ExcessiveLengthRule {
    pub const fn new() -> Self {
        Self { max_lines: 500 }
    }
}

impl Default for ExcessiveLengthRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for ExcessiveLengthRule {
    fn name(&self) -> &'static str {
        "excessive-length"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        let line_count = content.lines().count();

        if line_count > self.max_lines {
            issues.push(Issue {
                severity: Severity::Warning,
                line: line_count,
                column: None,
                message: format!(
                    "File has {line_count} lines (threshold: {}) — oversized files may hide \
                     bundled payloads or obfuscated content",
                    self.max_lines
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
    fn short_file_no_issue() {
        let rule = ExcessiveLengthRule::new();
        let content = "# Title\n\nA short skill file.\n";
        assert!(rule.check(content).is_empty());
    }

    #[test]
    fn at_threshold_no_issue() {
        let rule = ExcessiveLengthRule { max_lines: 500 };
        let content = "line\n".repeat(500);
        assert!(rule.check(&content).is_empty());
    }

    #[test]
    fn over_threshold_warns() {
        let rule = ExcessiveLengthRule { max_lines: 500 };
        let content = "line\n".repeat(501);
        let issues = rule.check(&content);
        assert!(!issues.is_empty());
        let issue = &issues[0];
        assert!(issue.message.contains("501"));
        assert_eq!(issue.severity, Severity::Warning);
    }

    #[test]
    fn severely_oversized_warns() {
        let rule = ExcessiveLengthRule { max_lines: 500 };
        let content = "line\n".repeat(2000);
        let issues = rule.check(&content);
        assert!(!issues.is_empty());
        let issue = &issues[0];
        assert!(issue.message.contains("2000"));
    }

    #[test]
    fn custom_threshold() {
        let rule = ExcessiveLengthRule { max_lines: 100 };
        let content = "line\n".repeat(101);
        let issues = rule.check(&content);
        assert!(!issues.is_empty());
        assert!(issues[0].message.contains("100"));
    }

    #[test]
    fn empty_file_no_issue() {
        let rule = ExcessiveLengthRule::new();
        assert!(rule.check("").is_empty());
    }
}
