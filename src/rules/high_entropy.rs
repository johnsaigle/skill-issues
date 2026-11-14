use std::sync::LazyLock;

use regex::Regex;

use super::{Issue, Rule, Severity};

/// Shannon entropy (bits per character) and chi-square statistic against a
/// uniform distribution, computed from one pass of byte counts.
///
/// `s` must be ASCII, which [`CANDIDATE`] matches always are, so each byte is
/// one character. A fixed array of counts replaces the per-call hash maps
/// this used to build, which dominated the rule's run time.
#[expect(
    clippy::cast_precision_loss,
    reason = "Precision loss at 2^52 is irrelevant for entropy math"
)]
fn entropy_and_chi_square(s: &str) -> (f64, f64) {
    debug_assert!(s.is_ascii(), "candidates are ASCII");
    if s.is_empty() {
        return (0.0, 0.0);
    }

    let mut counts = [0_usize; 128];
    for byte in s.bytes() {
        counts[usize::from(byte & 0x7F)] += 1;
    }

    let len = s.len() as f64;
    let present = counts.iter().filter(|&&c| c > 0);
    let unique = present.clone().count() as f64;
    let expected = len / unique;

    let mut entropy = 0.0;
    let mut chi_square = 0.0;
    for &count in present {
        let count = count as f64;
        let probability = count / len;
        entropy = probability.mul_add(-probability.log2(), entropy);
        let diff = count - expected;
        chi_square += (diff * diff) / expected;
    }
    (entropy, chi_square)
}

/// Check if a string is likely a legitimate high-entropy pattern.
///
/// Candidates come from [`CANDIDATE`], which excludes `-` and `:`, so UUIDs
/// and `sha256:`-style prefixes never reach this check; only bare hex digests
/// and commit hashes need recognising.
fn is_likely_legitimate(s: &str) -> bool {
    // SHA-256, SHA-1 and MD5 digests
    if matches!(s.len(), 32 | 40 | 64) && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    // Git commit hashes (7-40 lowercase hex chars, often abbreviated)
    (7..=40).contains(&s.len()) && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// Long runs of base64-alphabet characters that might be encoded data.
static CANDIDATE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=]{20,}").expect("valid regex"));

pub struct HighEntropyRule;

impl Rule for HighEntropyRule {
    fn name(&self) -> &'static str {
        "high-entropy"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for mat in CANDIDATE.find_iter(line) {
                let candidate = mat.as_str();

                // Skip if it looks like a legitimate pattern
                if is_likely_legitimate(candidate) {
                    continue;
                }

                let (entropy, chi_square) = entropy_and_chi_square(candidate);

                // High entropy (>4.2 bits/char) and uniform distribution (low chi-square)
                // indicates encoded/encrypted content
                if entropy > 4.2 && chi_square < 50.0 {
                    issues.push(Issue::new(self.name(), Severity::Warning, line_num + 1, Some(mat.start() + 1), format!(
                            "High-entropy string detected (entropy: {entropy:.2} bits/char, chi²: {chi_square:.1}) - possible encoded/obfuscated content"
                        )));
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
        let (entropy, _) = entropy_and_chi_square(uniform);
        assert!(entropy > 3.0); // Should be close to log2(10) ≈ 3.32

        // Test with low entropy
        let repetitive = "AAAAAAAAAB"; // Mostly same char
        let (entropy_low, _) = entropy_and_chi_square(repetitive);
        assert!(entropy_low < 1.0);
    }

    #[test]
    fn calculates_chi_square_correctly() {
        // Uniform distribution should have low chi-square
        let uniform = "ABCDEFGHIJ";
        let (_, chi_uniform) = entropy_and_chi_square(uniform);
        assert!(chi_uniform < 10.0);

        // Non-uniform should have higher chi-square
        let skewed = "AAAAAAAABC";
        let (_, chi_skewed) = entropy_and_chi_square(skewed);
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
