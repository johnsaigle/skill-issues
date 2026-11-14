use super::{Issue, Rule, Severity};

pub struct MixedScriptRule;

impl Rule for MixedScriptRule {
    fn name(&self) -> &'static str {
        "mixed-scripts"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let mut has_latin = false;
            let mut has_cyrillic = false;
            let mut has_greek = false;

            for ch in line.chars() {
                if ch.is_alphabetic() {
                    let cp = ch as u32;
                    if (0x0041..=0x007A).contains(&cp) || (0x00C0..=0x024F).contains(&cp) {
                        has_latin = true;
                    } else if (0x0400..=0x04FF).contains(&cp) || (0x0500..=0x052F).contains(&cp) {
                        has_cyrillic = true;
                    } else if (0x0370..=0x03FF).contains(&cp) || (0x1F00..=0x1FFF).contains(&cp) {
                        has_greek = true;
                    }
                }
            }

            let script_count = [has_latin, has_cyrillic, has_greek]
                .iter()
                .filter(|&&x| x)
                .count();
            if script_count > 1 {
                issues.push(Issue::new(
                    self.name(),
                    Severity::Warning,
                    line_num + 1,
                    None,
                    "Mixed scripts detected on same line (possible homoglyph attack)".to_string(),
                ));
            }
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_latin_and_cyrillic_mix() {
        let rule = MixedScriptRule;
        let content = "Hello мир"; // Latin and Cyrillic
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert_eq!(issues[0].rule, "mixed-scripts");
        assert_eq!(issues[0].severity, Severity::Warning);
    }

    #[test]
    fn detects_latin_and_greek_mix() {
        let rule = MixedScriptRule;
        let content = "Hello κόσμος"; // Latin and Greek
        let issues = rule.check(content);

        assert!(!issues.is_empty());
    }

    #[test]
    fn no_issues_on_pure_latin() {
        let rule = MixedScriptRule;
        let content = "This is purely Latin text";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn no_issues_on_pure_cyrillic() {
        let rule = MixedScriptRule;
        let content = "Это чисто кириллический текст";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn detects_on_same_line_only() {
        let rule = MixedScriptRule;
        let content = "Latin text\nКириллица\nLatin and Кириллица mixed";
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].line, 3);
    }
}
