use std::borrow::Cow;

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
pub mod markdown_comments;
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

impl Issue {
    pub fn new(
        rule: &str,
        severity: Severity,
        line: usize,
        column: Option<usize>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            line,
            column,
            message: message.into(),
            rule: rule.to_string(),
        }
    }
}

/// Returns the YAML frontmatter body as `(0-based line index, line)` pairs.
///
/// The first line must be `---`. The body ends at the next `---`; an unclosed
/// block runs to the end of the file, so its contents are still scanned.
pub fn frontmatter_lines(content: &str) -> Option<Vec<(usize, &str)>> {
    let mut lines = content.lines().enumerate();
    if lines.next()?.1.trim() != "---" {
        return None;
    }
    Some(lines.take_while(|(_, line)| line.trim() != "---").collect())
}

/// Converts a byte offset into `content` to a 1-based `(line, column)`, with
/// the column counted in bytes like the other rules' columns.
pub fn line_col(content: &str, offset: usize) -> (usize, usize) {
    let before = &content[..offset];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    (line, offset - line_start + 1)
}

/// Shortens `text` to `max` characters for quoting in a message, marking a
/// cut with `…` and showing line breaks as `\n`.
pub fn quote_excerpt(text: &str, max: usize) -> String {
    let mut quoted: String = text.chars().take(max).collect();
    if quoted.len() < text.len() {
        quoted.push('…');
    }
    quoted.replace('\n', "\\n")
}

/// Returns, for each line (0-based), whether it belongs to a fenced code
/// block, fence lines included.
///
/// Fences open with three or more backticks or tildes and close with a line
/// of the same character, at least as long, and nothing else. Unlike
/// `CommonMark`, an unclosed fence marks nothing: otherwise one stray
/// fence could hide every later line from rules that skip code blocks.
pub fn fenced_code_lines(content: &str) -> Vec<bool> {
    let lines: Vec<&str> = content.lines().collect();
    let mut in_code = vec![false; lines.len()];
    let mut open: Option<(usize, char, usize)> = None; // (line, fence char, fence length)

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let Some(ch) = trimmed.chars().next().filter(|c| matches!(c, '`' | '~')) else {
            continue;
        };
        let len = trimmed.chars().take_while(|&c| c == ch).count();
        if len < 3 {
            continue;
        }
        let rest = &trimmed[len..];
        match open {
            Some((start, open_ch, open_len))
                if ch == open_ch && len >= open_len && rest.trim().is_empty() =>
            {
                in_code[start..=idx].fill(true);
                open = None;
            }
            Some(_) => {}
            // A backtick fence's info string may not contain backticks.
            None if ch == '`' && rest.contains('`') => {}
            None => open = Some((idx, ch, len)),
        }
    }

    in_code
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
        if is_emoji_presentation(prev_char, ch) {
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

/// Returns true when `ch` is VS-15/VS-16 following an emoji base: standard
/// emoji presentation (e.g. `❤\u{FE0F}`), not hidden content.
pub fn is_emoji_presentation(prev: Option<char>, ch: char) -> bool {
    matches!(ch, '\u{FE0E}' | '\u{FE0F}')
        && prev.is_some_and(invisible_chars::InvisibleCharactersRule::is_emoji_base)
}

/// Returns true for a Unicode tag character (U+E0000-U+E007F), used for
/// ASCII smuggling.
pub const fn is_unicode_tag(ch: char) -> bool {
    matches!(ch, '\u{E0000}'..='\u{E007F}')
}

/// Describes an invisible/smuggling codepoint, or returns `None` for any
/// other character.
///
/// This is the single list of invisible characters: the
/// `invisible-characters` rule, suspicion scoring and terminal escaping all
/// use it.
pub fn invisible_char_description(ch: char) -> Option<Cow<'static, str>> {
    let name = match ch {
        // Zero-width characters
        '\u{200B}' => "ZERO WIDTH SPACE",
        '\u{200C}' => "ZERO WIDTH NON-JOINER",
        '\u{200D}' => "ZERO WIDTH JOINER",
        '\u{FEFF}' => "ZERO WIDTH NO-BREAK SPACE (BOM)",
        '\u{2060}' => "WORD JOINER",
        '\u{00AD}' => "SOFT HYPHEN",
        '\u{180E}' => "MONGOLIAN VOWEL SEPARATOR",
        '\u{034F}' => "COMBINING GRAPHEME JOINER",

        // Directional marks
        '\u{200E}' => "LEFT-TO-RIGHT MARK",
        '\u{200F}' => "RIGHT-TO-LEFT MARK",
        '\u{061C}' => "ARABIC LETTER MARK",
        '\u{202A}' => "LEFT-TO-RIGHT EMBEDDING",
        '\u{202B}' => "RIGHT-TO-LEFT EMBEDDING",
        '\u{202C}' => "POP DIRECTIONAL FORMATTING",
        '\u{202D}' => "LEFT-TO-RIGHT OVERRIDE",
        '\u{202E}' => "RIGHT-TO-LEFT OVERRIDE",
        '\u{2066}' => "LEFT-TO-RIGHT ISOLATE",
        '\u{2067}' => "RIGHT-TO-LEFT ISOLATE",
        '\u{2068}' => "FIRST STRONG ISOLATE",
        '\u{2069}' => "POP DIRECTIONAL ISOLATE",

        // Invisible operators
        '\u{2061}' => "FUNCTION APPLICATION (invisible operator)",
        '\u{2062}' => "INVISIBLE TIMES",
        '\u{2063}' => "INVISIBLE SEPARATOR",
        '\u{2064}' => "INVISIBLE PLUS",

        // Deprecated format controls
        '\u{206A}' => "INHIBIT SYMMETRIC SWAPPING (deprecated)",
        '\u{206B}' => "ACTIVATE SYMMETRIC SWAPPING (deprecated)",
        '\u{206C}' => "INHIBIT ARABIC FORM SHAPING (deprecated)",
        '\u{206D}' => "ACTIVATE ARABIC FORM SHAPING (deprecated)",
        '\u{206E}' => "NATIONAL DIGIT SHAPES (deprecated)",
        '\u{206F}' => "NOMINAL DIGIT SHAPES (deprecated)",

        ch if is_unicode_tag(ch) => "UNICODE TAG (ASCII smuggling)",

        // Variation selectors 1-16 and 17-256
        '\u{FE00}'..='\u{FE0F}' => {
            let n = ch as u32 - 0xFE00 + 1;
            return Some(Cow::Owned(format!("VARIATION SELECTOR-{n}")));
        }
        '\u{E0100}'..='\u{E01EF}' => {
            let n = ch as u32 - 0xE0100 + 17;
            return Some(Cow::Owned(format!("VARIATION SELECTOR-{n}")));
        }

        _ => return None,
    };
    Some(Cow::Borrowed(name))
}

/// Returns true if the character is one of the invisible/smuggling codepoints
/// that we track for suspicion scoring.
pub fn is_invisible_codepoint(ch: char) -> bool {
    invisible_char_description(ch).is_some()
}

#[cfg(test)]
mod suspicion_tests {
    use super::*;
    use std::fmt::Write;

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
            let _ = write!(content, "word{i}\u{200B}");
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
            let _ = write!(content, "w{i}\u{200B}");
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

#[cfg(test)]
mod fence_tests {
    use super::fenced_code_lines;

    #[test]
    fn closed_backtick_and_tilde_fences() {
        let content = "a\n```sh\nx\n```\nb\n~~~\ny\n~~~\nc";
        assert_eq!(
            fenced_code_lines(content),
            [false, true, true, true, false, true, true, true, false]
        );
    }

    #[test]
    fn unclosed_fence_marks_nothing() {
        let content = "a\n```\nx\ny\n";
        assert_eq!(fenced_code_lines(content), [false; 4]);
    }

    #[test]
    fn closing_fence_must_match_char_and_length() {
        // ``` and ~~~ inside a ```` block do not close it.
        let content = "````\n```\n~~~\n````\nafter";
        assert_eq!(fenced_code_lines(content), [true, true, true, true, false]);
    }

    #[test]
    fn closing_fence_cannot_have_info_string() {
        let content = "```\nx\n```rust\ny\n```";
        assert_eq!(fenced_code_lines(content), [true; 5]);
    }

    #[test]
    fn backtick_fence_info_with_backtick_does_not_open() {
        let content = "``` a`b\nx\n```\ny\n```";
        assert_eq!(fenced_code_lines(content), [false, false, true, true, true]);
    }
}
