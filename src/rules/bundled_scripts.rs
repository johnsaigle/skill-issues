use regex::Regex;

use super::{Issue, Rule, Severity};

/// Detects references to local bundled scripts or executables in skill markdown.
///
/// Overtly malicious skills often work by referencing an external script that
/// lives alongside the markdown, rather than embedding malicious instructions
/// directly in the prompt. This makes them invisible to plain-text scanners.
///
/// Reference: <https://blog.trailofbits.com/2026/06/03/the-sorry-state-of-skill-distribution/>
pub struct BundledScriptsRule;

impl Rule for BundledScriptsRule {
    fn name(&self) -> &'static str {
        "bundled-scripts"
    }

    fn check(&self, content: &str) -> Vec<Issue> {
        let mut issues = Vec::new();

        // Match common patterns for local script/executable file references.
        // Covers: relative paths (./ ../ .\), home-relative (~/), Windows drive
        // letters (C:\), and common absolute system paths (/usr/, /tmp/, etc.).
        let re = Regex::new(
            r#"(?i)(?:\.{1,2}[/\\]|~/|[A-Za-z]:[/\\]|[/\\](?:home|usr|tmp|etc|var)[/\\])[^\s`'"\)<>]*?\.(?:sh|py|js|rb|pl|bat|ps1|exe|bin|elf|app|cmd|vbs|wsf|jar|php|go|ts|mjs|cjs)\b"#
        ).expect("invalid regex for bundled script pattern");

        for (line_num, line) in content.lines().enumerate() {
            for mat in re.find_iter(line) {
                issues.push(Issue {
                    severity: Severity::Warning,
                    line: line_num + 1,
                    column: Some(mat.start()),
                    message: format!(
                        "Reference to bundled script or executable: '{}' — skill may execute \
                         external code not visible to plain-text scanners",
                        mat.as_str()
                    ),
                    rule: self.name().to_string(),
                });
            }
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str) -> Vec<Issue> {
        BundledScriptsRule.check(content)
    }

    #[test]
    fn clean_content_no_issues() {
        let content = "# My Skill\n\nThis skill helps with markdown formatting.\n";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_relative_shell_script() {
        let content = "Run `./setup.sh` to configure the environment.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("setup.sh")),
            "should detect ./setup.sh, got: {issues:?}"
        );
    }

    #[test]
    fn detects_python_script() {
        let content = "Execute `./install.py` first.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("install.py")),
            "should detect install.py, got: {issues:?}"
        );
    }

    #[test]
    fn detects_javascript_script() {
        let content = "The helper at `./helpers/init.js` does setup work.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("init.js")),
            "should detect init.js, got: {issues:?}"
        );
    }

    #[test]
    fn detects_parent_dir_script() {
        let content = "../malicious.sh is run before anything else.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("malicious.sh")),
            "should detect ../malicious.sh, got: {issues:?}"
        );
    }

    #[test]
    fn detects_absolute_path_script() {
        let content = "Check `/usr/local/bin/helper.py` for configuration.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("helper.py")),
            "should detect absolute path, got: {issues:?}"
        );
    }

    #[test]
    fn detects_home_relative_script() {
        let content = "Source `~/install.sh` to set up.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("install.sh")),
            "should detect ~/install.sh, got: {issues:?}"
        );
    }

    #[test]
    fn detects_tmp_path_script() {
        let content = "It uses /tmp/exploit.py for temporary work.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("exploit.py")),
            "should detect /tmp/exploit.py, got: {issues:?}"
        );
    }

    #[test]
    fn detects_quoted_script_reference() {
        let content = r#"The command "./helper.js" runs the tool."#;
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("helper.js")),
            "should detect quoted script, got: {issues:?}"
        );
    }

    #[test]
    fn detects_markdown_link_to_script() {
        let content = "See [the script](./init.sh) for setup.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("init.sh")),
            "should detect markdown link, got: {issues:?}"
        );
    }

    #[test]
    fn detects_ruby_script() {
        let content = "Run `./tasks/deploy.rb` to deploy.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("deploy.rb")),
            "should detect deploy.rb, got: {issues:?}"
        );
    }

    #[test]
    fn detects_batch_script() {
        let content = r"On Windows, use `.\setup.bat`.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("setup.bat")),
            "should detect setup.bat, got: {issues:?}"
        );
    }

    #[test]
    fn detects_powershell_script() {
        let content = "The PS script is `./Configure.ps1`.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("Configure.ps1")),
            "should detect Configure.ps1, got: {issues:?}"
        );
    }

    #[test]
    fn detects_executable_binary() {
        let content = "Download `./tool.bin` and run it.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("tool.bin")),
            "should detect tool.bin, got: {issues:?}"
        );
    }

    #[test]
    fn no_false_positive_on_markdown_links() {
        let content = "See [documentation](./README.md) for details.\nSee [config](./config.yaml) for \
             options.";
        assert!(check(content).is_empty());
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let content = "We use shell scripts for automation.\nPython is great for scripting.\njavascript \
             runs in the browser.\nThe file extension .sh is common.";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_multiple_references() {
        let content = "Run `./setup.sh` then `./cleanup.py`.";
        let issues = check(content);
        assert!(
            issues.len() >= 2,
            "expected at least 2 issues, got {}: {issues:?}",
            issues.len()
        );
    }

    #[test]
    fn detects_deeply_nested_relative_path() {
        let content = "Execute `../../../scripts/evil.sh`.";
        let issues = check(content);
        assert!(
            issues.iter().any(|i| i.message.contains("evil.sh")),
            "should detect deeply nested path, got: {issues:?}"
        );
    }
}
