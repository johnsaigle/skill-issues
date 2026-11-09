use serde::{Deserialize, Serialize};

pub mod base64_encoded;
pub mod bundled_scripts;
pub mod excessive_backticks;
pub mod excessive_length;
pub mod excessive_whitespace;
pub mod frontmatter_hooks;
pub mod frontmatter_validation;
pub mod high_entropy;
pub mod html_comments;
pub mod inline_commands;
pub mod invisible_chars;
pub mod mixed_scripts;
pub mod non_printable;
pub mod suspicious_keywords;
pub mod unicode_homoglyphs;
pub mod url_encoding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issue {
    pub severity: Severity,
    pub line: usize,
    pub column: Option<usize>,
    pub message: String,
    pub rule: String,
}

pub trait Rule: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, content: &str) -> Vec<Issue>;

    /// Like [`Rule::check`], for rules that also need the file's location
    /// (e.g. to apply only to `SKILL.md` or compare against the directory).
    fn check_file(&self, _path: &std::path::Path, content: &str) -> Vec<Issue> {
        self.check(content)
    }
}

/// Suspicion level classification based on invisible character density,
/// following aid's severity model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SuspicionLevel {
    Info,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SuspicionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Computes the suspicion level for a file based on invisible character analysis.
///
/// Classification order (matching aid):
/// 1. `longest_consecutive_run >= 40` => Critical
/// 2. `longest_consecutive_run >= 10` => High
/// 3. `total_invisible > 100` => High
/// 4. `total_invisible < 10` => Info
/// 5. Otherwise => Medium
pub fn compute_suspicion_level(content: &str) -> (SuspicionLevel, usize, usize) {
    let mut total_invisible: usize = 0;
    let mut longest_consecutive_run: usize = 0;
    let mut current_run: usize = 0;
    let mut prev_char: Option<char> = None;

    for ch in content.chars() {
        // Skip VS-15/VS-16 after emoji base (standard emoji presentation)
        if is_emoji_variation_selector(ch)
            && let Some(prev) = prev_char
            && invisible_chars::InvisibleCharactersRule::is_emoji_base(prev)
        {
            prev_char = Some(ch);
            continue;
        }

        if is_invisible_codepoint(ch) {
            total_invisible += 1;
            current_run += 1;
            if current_run > longest_consecutive_run {
                longest_consecutive_run = current_run;
            }
        } else {
            current_run = 0;
        }
        prev_char = Some(ch);
    }

    let level = if longest_consecutive_run >= 40 {
        SuspicionLevel::Critical
    } else if longest_consecutive_run >= 10 || total_invisible > 100 {
        SuspicionLevel::High
    } else if total_invisible < 10 {
        SuspicionLevel::Info
    } else {
        SuspicionLevel::Medium
    };

    (level, total_invisible, longest_consecutive_run)
}

/// Returns true if `ch` is VS-15 or VS-16 (emoji text/presentation selectors).
const fn is_emoji_variation_selector(ch: char) -> bool {
    matches!(ch, '\u{FE0E}' | '\u{FE0F}')
}

/// Returns true if the character is one of the invisible/smuggling codepoints
/// that we track for suspicion scoring.
fn is_invisible_codepoint(ch: char) -> bool {
    let cp = ch as u32;
    matches!(ch,
        // Zero-width and joiners
        '\u{034F}' | '\u{180E}' | '\u{200B}' | '\u{200C}' | '\u{200D}' |
        '\u{2060}' | '\u{FEFF}' |
        // Directional marks
        '\u{061C}' | '\u{200E}' | '\u{200F}' |
        '\u{202A}'..='\u{202E}' |
        '\u{2066}'..='\u{2069}' |
        // Invisible operators
        '\u{2061}'..='\u{2064}' |
        // Deprecated format controls
        '\u{206A}'..='\u{206F}' |
        // Variation selectors 1-16
        '\u{FE00}'..='\u{FE0F}'
    )
    // Unicode tags (U+E0000-U+E007F)
    || (0xE0000..=0xE007F).contains(&cp)
    // Variation selectors 17-256 (U+E0100-U+E01EF)
    || (0xE0100..=0xE01EF).contains(&cp)
}

#[cfg(test)]
mod suspicion_tests {
    use super::*;

    #[test]
    fn clean_text_is_info() {
        let (level, total, _) = compute_suspicion_level("Clean text with no invisible chars");
        assert_eq!(level, SuspicionLevel::Info);
        assert_eq!(total, 0);
    }

    #[test]
    fn few_invisible_is_info() {
        // 3 zero-width spaces scattered
        let content = "a\u{200B}b\u{200B}c\u{200B}d";
        let (level, total, _) = compute_suspicion_level(content);
        assert_eq!(level, SuspicionLevel::Info);
        assert_eq!(total, 3);
    }

    #[test]
    fn moderate_invisible_is_medium() {
        // 15 zero-width spaces scattered (total >= 10, runs < 10)
        let mut content = String::new();
        for i in 0..15 {
            content.push_str(&format!("word{}\u{200B}", i));
        }
        let (level, total, run) = compute_suspicion_level(&content);
        assert_eq!(level, SuspicionLevel::Medium);
        assert_eq!(total, 15);
        assert_eq!(run, 1); // each is separated by text
    }

    #[test]
    fn consecutive_run_10_is_high() {
        let content = format!("prefix{}suffix", "\u{200B}".repeat(10));
        let (level, _, run) = compute_suspicion_level(&content);
        assert_eq!(level, SuspicionLevel::High);
        assert_eq!(run, 10);
    }

    #[test]
    fn over_100_scattered_is_high() {
        let mut content = String::new();
        for i in 0..101 {
            content.push_str(&format!("w{}\u{200B}", i));
        }
        let (level, total, _) = compute_suspicion_level(&content);
        assert_eq!(level, SuspicionLevel::High);
        assert!(total > 100);
    }

    #[test]
    fn consecutive_run_40_is_critical() {
        let content = format!("prefix{}suffix", "\u{200B}".repeat(40));
        let (level, _, run) = compute_suspicion_level(&content);
        assert_eq!(level, SuspicionLevel::Critical);
        assert_eq!(run, 40);
    }

    #[test]
    fn unicode_tags_counted_for_suspicion() {
        // 50 Unicode tag characters in a row => critical
        let mut content = String::from("prefix");
        for i in 0x20..0x52u32 {
            // 50 tag chars
            if let Some(c) = char::from_u32(0xE0000 + i) {
                content.push(c);
            }
        }
        content.push_str("suffix");
        let (level, _, _) = compute_suspicion_level(&content);
        assert_eq!(level, SuspicionLevel::Critical);
    }
}
