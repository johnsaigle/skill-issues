use std::collections::HashMap;

use regex::Regex;

use super::{Issue, Rule, Severity};

/// Calculate Shannon entropy of a string in bits per character
#[expect(
    clippy::cast_precision_loss,
    reason = "Precision loss at 2^52 is irrelevant for entropy math"
)]
fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts: HashMap<char, usize> = HashMap::new();
    let total_chars = s.chars().count();

    for ch in s.chars() {
        *char_counts.entry(ch).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for count in char_counts.values() {
        let probability = *count as f64 / total_chars as f64;
        entropy = probability.mul_add(-probability.log2(), entropy);
    }

    entropy
}

/// Calculate chi-square statistic for character distribution
/// Compares observed distribution against expected uniform distribution
#[expect(
    clippy::cast_precision_loss,
    reason = "Precision loss at 2^52 is irrelevant for chi-square math"
)]
fn calculate_chi_square(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut char_counts: HashMap<char, usize> = HashMap::new();

    for ch in &chars {
        *char_counts.entry(*ch).or_insert(0) += 1;
    }

    let unique_chars = char_counts.len();
    if unique_chars == 0 {
        return 0.0;
    }

    let expected = len as f64 / unique_chars as f64;
    let mut chi_square = 0.0;

    for count in char_counts.values() {
        let diff = *count as f64 - expected;
        chi_square += (diff * diff) / expected;
    }

    chi_square
}

/// Check if a string is likely a legitimate high-entropy pattern
fn is_likely_legitimate(s: &str) -> bool {
    // UUID pattern
    if Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .expect("valid regex")
        .is_match(s)
    {
        return true;
    }

    // SHA-256 or similar hashes (64 hex chars)
    if Regex::new(r"^[0-9a-fA-F]{64}$")
        .expect("valid regex")
        .is_match(s)
    {
        return true;
    }

    // SHA-1 (40 hex chars)
    if Regex::new(r"^[0-9a-fA-F]{40}$")
        .expect("valid regex")
        .is_match(s)
    {
        return true;
    }

    // MD5 (32 hex chars)
    if Regex::new(r"^[0-9a-fA-F]{32}$")
        .expect("valid regex")
        .is_match(s)
    {
        return true;
    }

    // Common hash prefixes
    if s.starts_with("sha256:") || s.starts_with("sha1:") || s.starts_with("md5:") {
        return true;
    }

    // Git commit hashes (7-40 hex chars often abbreviated)
    if Regex::new(r"^[0-9a-f]{7,40}$")
        .expect("valid regex")
        .is_match(s)
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return true;
    }

    false
}

pub struct HighEntropyRule;

impl Rule for HighEntropyRule {
    fn name(&self) -> &'static str {
        "high-entropy"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Look for long alphanumeric strings that might be encoded
        let re = Regex::new(r"[A-Za-z0-9+/=]{20,}").expect("valid regex");

        for (line_num, line) in content.lines().enumerate() {
            for mat in re.find_iter(line) {
                let candidate = mat.as_str();

                // Skip if it looks like a legitimate pattern
                if is_likely_legitimate(candidate) {
                    continue;
                }

                let entropy = calculate_entropy(candidate);
                let chi_square = calculate_chi_square(candidate);

                // High entropy (>4.2 bits/char) and uniform distribution (low chi-square)
                // indicates encoded/encrypted content
                if entropy > 4.2 && chi_square < 50.0 {
                    issues.push(Issue {
                        severity: Severity::Warning,
                        line: line_num + 1,
                        column: Some(mat.start() + 1),
                        message: format!(
                            "High-entropy string detected (entropy: {entropy:.2} bits/char, chi²: {chi_square:.1}) - possible encoded/obfuscated content"
                        ),
                        rule: self.name().to_string(),
                    });
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
    fn detects_high_entropy_base64_like_string() {
        let rule = HighEntropyRule;
        // High entropy string (not valid base64 but high entropy)
        let content = "dQw4w9WgXcQvXhGGXTthx6z8JG4Z3L6vX9T3z7K9P8N";
        let issues = rule.check(content);

        assert!(!issues.is_empty());
        assert_eq!(issues[0].rule, "high-entropy");
        assert_eq!(issues[0].severity, Severity::Warning);
        assert!(issues[0].message.contains("entropy:"));
    }

    #[test]
    fn ignores_low_entropy_natural_text() {
        let rule = HighEntropyRule;
        let content = "This is normal natural language text with regular words";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn allows_uuid_patterns() {
        let rule = HighEntropyRule;
        let content = "550e8400-e29b-41d4-a716-446655440000";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn allows_sha256_hashes() {
        let rule = HighEntropyRule;
        let content = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn allows_git_commit_hashes() {
        let rule = HighEntropyRule;
        let content = "abc1234def5678";
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }

    #[test]
    fn calculates_entropy_correctly() {
        // Test with uniform distribution (should be high entropy)
        let uniform = "ABCDEFGHIJ"; // 10 different chars
        let entropy = calculate_entropy(uniform);
        assert!(entropy > 3.0); // Should be close to log2(10) ≈ 3.32

        // Test with low entropy
        let repetitive = "AAAAAAAAAB"; // Mostly same char
        let entropy_low = calculate_entropy(repetitive);
        assert!(entropy_low < 1.0);
    }

    #[test]
    fn calculates_chi_square_correctly() {
        // Uniform distribution should have low chi-square
        let uniform = "ABCDEFGHIJ";
        let chi_uniform = calculate_chi_square(uniform);
        assert!(chi_uniform < 10.0);

        // Non-uniform should have higher chi-square
        let skewed = "AAAAAAAABC";
        let chi_skewed = calculate_chi_square(skewed);
        assert!(chi_skewed > chi_uniform);
    }

    #[test]
    fn detects_high_entropy_random_content() {
        let rule = HighEntropyRule;
        // Random-looking high-entropy string (not valid base64 but clearly encoded)
        let content = "9xK2vQm4nP8wL7bJ5hYfRt3cE6aZ9dQ2wS4eX7uI0oP";
        let issues = rule.check(content);

        // Should detect this as high entropy (>4.2 bits/char)
        assert!(!issues.is_empty());
        assert!(
            issues[0].message.contains("high-entropy") || issues[0].message.contains("entropy")
        );
    }

    #[test]
    fn ignores_short_strings() {
        let rule = HighEntropyRule;
        let content = "abc123"; // Too short (less than 20 chars)
        let issues = rule.check(content);

        assert!(issues.is_empty());
    }
}
