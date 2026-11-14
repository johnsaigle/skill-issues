use super::{Issue, Rule, Severity};

pub struct ExcessiveWhitespaceRule {
    pub max_empty_lines: usize,
}

impl Rule for ExcessiveWhitespaceRule {
    fn name(&self) -> &'static str {
        "excessive-whitespace"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut empty_count = 0;
        let mut empty_start = 0;

        for (i, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                if empty_count == 0 {
                    empty_start = i + 1;
                }
                empty_count += 1;
            } else {
                if empty_count > self.max_empty_lines {
                    issues.push(Issue::new(
                        self.name(),
                        Severity::Warning,
                        empty_start,
                        None,
                        format!(
                            "{} consecutive empty lines (max: {})",
                            empty_count, self.max_empty_lines
                        ),
                    ));
                }
                empty_count = 0;
            }
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_excessive_empty_lines() {
        let rule = ExcessiveWhitespaceRule { max_empty_lines: 2 };
        let content = "Line 1\n\n\n\nLine 2";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].rule, "excessive-whitespace");
        assert_eq!(issues[0].severity, Severity::Warning);
        assert_eq!(issues[0].line, 2);
        assert!(issues[0].message.contains("3 consecutive empty lines"));
    }

    #[test]
    fn allows_acceptable_empty_lines() {
        let rule = ExcessiveWhitespaceRule { max_empty_lines: 3 };
        let content = "Line 1\n\n\n\nLine 2";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn detects_multiple_violations() {
        let rule = ExcessiveWhitespaceRule { max_empty_lines: 1 };
        let content = "Line 1\n\n\nLine 2\n\n\n\nLine 3";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn no_issues_on_no_empty_lines() {
        let rule = ExcessiveWhitespaceRule { max_empty_lines: 1 };
        let content = "Line 1\nLine 2\nLine 3";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }
}
