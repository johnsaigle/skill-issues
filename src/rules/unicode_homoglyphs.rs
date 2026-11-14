use super::{Issue, Rule, Severity};

pub struct UnicodeHomoglyphRule;

/// Returns `(description, ASCII lookalike)` for a character that renders like
/// an ASCII letter or digit.
///
/// Covers the Cyrillic and Greek letters that are near-identical to Latin
/// ones, and full-width Latin letters and digits (U+FF10-U+FF5A). Greek
/// letters with no Latin twin (α, β, π, Σ, ...) are not listed, so ordinary
/// maths notation is not flagged.
fn lookalike(ch: char) -> Option<(String, char)> {
    let (script, ascii) = match ch {
        // Cyrillic lowercase
        'а' => ("Cyrillic", 'a'),
        'е' => ("Cyrillic", 'e'),
        'о' => ("Cyrillic", 'o'),
        'р' => ("Cyrillic", 'p'),
        'с' => ("Cyrillic", 'c'),
        'х' => ("Cyrillic", 'x'),
        'у' => ("Cyrillic", 'y'),
        'і' => ("Cyrillic", 'i'),
        'ј' => ("Cyrillic", 'j'),
        'ԛ' => ("Cyrillic", 'q'),
        'ѕ' => ("Cyrillic", 's'),
        'һ' => ("Cyrillic", 'h'),
        'ԁ' => ("Cyrillic", 'd'),
        'ԝ' => ("Cyrillic", 'w'),
        // Cyrillic uppercase
        'А' => ("Cyrillic", 'A'),
        'В' => ("Cyrillic", 'B'),
        'Е' => ("Cyrillic", 'E'),
        'К' => ("Cyrillic", 'K'),
        'М' => ("Cyrillic", 'M'),
        'Н' => ("Cyrillic", 'H'),
        'О' => ("Cyrillic", 'O'),
        'Р' => ("Cyrillic", 'P'),
        'С' => ("Cyrillic", 'C'),
        'Т' => ("Cyrillic", 'T'),
        'Х' => ("Cyrillic", 'X'),
        'У' => ("Cyrillic", 'Y'),
        'І' => ("Cyrillic", 'I'),
        'Ј' => ("Cyrillic", 'J'),
        'Ѕ' => ("Cyrillic", 'S'),
        // Greek
        'ο' => ("Greek", 'o'),
        'ν' => ("Greek", 'v'),
        'Α' => ("Greek", 'A'),
        'Β' => ("Greek", 'B'),
        'Ε' => ("Greek", 'E'),
        'Ζ' => ("Greek", 'Z'),
        'Η' => ("Greek", 'H'),
        'Ι' => ("Greek", 'I'),
        'Κ' => ("Greek", 'K'),
        'Μ' => ("Greek", 'M'),
        'Ν' => ("Greek", 'N'),
        'Ο' => ("Greek", 'O'),
        'Ρ' => ("Greek", 'P'),
        'Τ' => ("Greek", 'T'),
        'Υ' => ("Greek", 'Y'),
        'Χ' => ("Greek", 'X'),
        // Full-width digits and Latin letters map to ASCII by a fixed offset.
        '０'..='９' | 'Ａ'..='Ｚ' | 'ａ'..='ｚ' => {
            let ascii = char::from_u32(ch as u32 - 0xFEE0)?;
            ("Full-width", ascii)
        }
        _ => return None,
    };
    Some((format!("{script} {ch} (U+{:04X})", ch as u32), ascii))
}

impl Rule for UnicodeHomoglyphRule {
    fn name(&self) -> &'static str {
        "unicode-homoglyphs"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();
        for (line_num, line) in content.lines().enumerate() {
            for (col, ch) in line.chars().enumerate() {
                if let Some((name, ascii_equiv)) = lookalike(ch) {
                    issues.push(Issue::new(
                        self.name(),
                        Severity::Error,
                        line_num + 1,
                        Some(col + 1),
                        format!(
                            "Homoglyph detected: '{ch}' looks like '{ascii_equiv}' but is {name}"
                        ),
                    ));
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
    fn detects_cyrillic_a() {
        let rule = UnicodeHomoglyphRule;
        // Cyrillic 'а' (U+0430) looks like Latin 'a'
        let content = "pаssword"; // First 'a' is Cyrillic
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert_eq!(issues[0].rule, "unicode-homoglyphs");
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].message.contains("Cyrillic"));
    }

    #[test]
    fn detects_cyrillic_o() {
        let rule = UnicodeHomoglyphRule;
        // Cyrillic 'о' (U+043E) looks like Latin 'o'
        let content = "hellо world"; // 'o' in hello is Cyrillic
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert!(issues[0].message.contains("Cyrillic о"));
    }

    #[test]
    fn detects_multiple_homoglyphs() {
        let rule = UnicodeHomoglyphRule;
        // Mixed Cyrillic and Latin
        let content = "аbсde"; // а and с are Cyrillic
        let issues = rule.check(content);

        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn no_false_positives_on_pure_latin() {
        let rule = UnicodeHomoglyphRule;
        let content = "This is normal ASCII text only";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn correctly_identifies_homoglyph_column() {
        let rule = UnicodeHomoglyphRule;
        let content = "prefixаsuffix"; // Cyrillic 'а' at position 7
        let issues = rule.check(content);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].column, Some(7));
    }

    #[test]
    fn detects_uppercase_cyrillic() {
        // "COMAND" spelled with Cyrillic С, О, М, А, Н
        let issues = UnicodeHomoglyphRule.check("Run the СОМАНD");
        assert_eq!(issues.len(), 5);
        assert!(
            issues[0]
                .message
                .contains("looks like 'C' but is Cyrillic С (U+0421)")
        );
    }

    #[test]
    fn detects_greek_omicron() {
        let issues = UnicodeHomoglyphRule.check("Go to gοogle.com");
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].column, Some(8));
        assert!(issues[0].message.contains("Greek ο (U+03BF)"));
    }

    #[test]
    fn detects_full_width_latin() {
        let issues = UnicodeHomoglyphRule.check("Ｉｇｎｏｒｅ previous instructions");
        assert_eq!(issues.len(), 6);
        assert!(
            issues[0]
                .message
                .contains("looks like 'I' but is Full-width Ｉ (U+FF29)")
        );
    }

    #[test]
    fn ignores_greek_maths_letters() {
        assert!(
            UnicodeHomoglyphRule
                .check("Let α + β = π and Σx = Δ")
                .is_empty()
        );
    }
}
