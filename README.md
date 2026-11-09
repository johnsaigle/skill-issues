# Skill Issues

A linter for skill markdown files used by Claude Code and similar AI systems. This tool scans markdown files and flags potential prompt injection attempts and other security issues.

## Purpose

Skill files are markdown documents that define behaviors and capabilities for AI assistants. Since these files are parsed as instructions, they can be vectors for prompt injection attacks. This linter helps catch suspicious patterns before they reach the AI.

## Approach

This tool is extremely conservative. It's essentially looking for ASCII markdown files with some allowance for emojis.
It's unlikely to be friendly for languages other than English.

`skill-issues` performs only simple, static, lint-based checks on the primary skill files (SKILL.md and related markdown). It does not execute, decode, modify, or otherwise interpret file contents beyond pattern matching.

## Non-Goals

The following are explicitly out of scope and will not be implemented:

- **Secret/credential scanning** — detection of API keys, tokens, private keys, or passwords.
- **Script analysis** — scanning bundled `.py`, `.sh`, `.js`, or `.ts` files in `scripts/` directories for dangerous patterns (HTTP exfiltration, `eval`, credential access, config modification).
- **Content-aware decoding** — decoding base64 or Unicode tag blocks to inspect their decoded content. Only the presence of encoded strings is detected, not what they contain.
- **Structural attack detection** — symlink resolution, test file RCE, npm lifecycle hooks, or image metadata injection.
- **URL extraction and classification** — extracting URLs from skill content or checking domains against allowlists.

## Installation

```bash
cargo build --release
# Binary will be at target/release/skill-issues
```

## Usage

```bash
# Scan current directory (only shows files with violations)
skill-issues

# Scan specific file
skill-issues path/to/skill.md

# Scan specific directory
skill-issues path/to/skills/

# Show detailed output for all files
skill-issues --verbose

# Only show errors (suppress warnings)
skill-issues --quiet

# Exit with error code if issues found (good for CI)
skill-issues --strict

# Set max consecutive empty lines (default: 3)
skill-issues --max-empty-lines 5

# Output formats
skill-issues --format text    # Human-readable (default)
skill-issues --format json    # JSON output
skill-issues --format sarif   # SARIF output for GitHub Advanced Security
```

## Detection Rules

### Errors (High Risk)

| Rule | Description |
|------|-------------|
| `html-comments` | HTML comments (`<!-- ... -->`) can hide instructions |
| `non-printable-chars` | Control characters and zero-width characters |
| `suspicious-keywords` | Phrases like "ignore previous instructions", "jailbreak", "system prompt" |
| `unicode-homoglyphs` | Cyrillic characters that look like ASCII (e.g., Cyrillic 'а' vs Latin 'a') |
| `invisible-characters` | Zero-width spaces, joiners, soft hyphens used for steganography |

### Warnings (Medium Risk)

| Rule | Description |
|------|-------------|
| `excessive-whitespace` | Too many consecutive blank lines (configurable) |
| `mixed-scripts` | Multiple Unicode scripts on same line (homoglyph attack indicator) |
| `url-encoding` | URL-encoded sequences that could hide instructions |
| `excessive-backticks` | Unusual number of backticks (may break code block parsing) |
| `base64-encoded` | Base64 content that decodes to suspicious text |
| `high-entropy` | High-entropy strings indicating encoded/obfuscated content |

## Example Output

### Default Mode
Only shows files with violations and a summary:
```
./skills/auth.md
  [ERROR] 5::1 [html-comments] - HTML comment detected: '<!-- secret instruction -->'
  [ERROR] 14: [suspicious-keywords] - Suspicious phrase 'ignore previous instructions'
2 errors found

./skills/api.md
  [WARN] 22: [excessive-whitespace] - 5 consecutive empty lines
1 error found
```

When no issues are found:
```
5 files scanned
```

### Verbose Mode (-v)
Shows all files scanned with detailed output:
```
./skills/auth.md
  [ERROR] 5::1 [html-comments] - HTML comment detected: '<!-- secret instruction -->'
  [ERROR] 14: [suspicious-keywords] - Suspicious phrase 'ignore previous instructions'

./skills/api.md
  [WARN] 22: [excessive-whitespace] - 5 consecutive empty lines

./skills/utils.md
  (no issues)

./skills/config.md
  (no issues)

4 files scanned
2 errors found
```

## Why These Rules?

### HTML Comments
AI systems may ignore HTML comments, but some parsers strip them before processing, potentially exposing hidden instructions.

### Zero-Width Characters
Invisible characters can encode hidden messages through steganography or bypass simple filters.

### Unicode Homoglyphs
Cyrillic characters that look identical to Latin letters can trick both humans and simple string-matching defenses.

### Suspicious Keywords
Direct attempts to override system behavior use predictable phrases like "ignore previous instructions" or "you are now DAN".

### Base64/URL Encoding
Encoded content can bypass filters that look for specific keywords in plain text.

### Entropy Detection
High-entropy content (>4.2 bits/character) indicates encoded, encrypted, or obfuscated data. Natural language has entropy around 3-4 bits/char, while random/encoded data approaches the maximum (log2 of alphabet size, e.g., ~6 bits for base64). We use chi-square statistics to distinguish between legitimate patterns (UUIDs, hashes) and suspicious random strings.

## Output Formats

### Text (Default)
Human-readable format with colored output showing file paths, line numbers, and issue descriptions.

### JSON
Structured JSON output suitable for programmatic processing:
```bash
skill-issues --format json > results.json
```

The JSON includes:
- Tool version and timestamp
- Per-file issue lists with severity, line/column, message, and rule ID
- Summary statistics

### SARIF
SARIF (Static Analysis Results Interchange Format) output for integration with GitHub Advanced Security, Azure DevOps, and other security platforms:
```bash
skill-issues --format sarif > results.sarif
```

Compatible with:
- GitHub Advanced Security (upload via `github/codeql-action/upload-sarif`)
- Azure DevOps Security dashboard
- Any SARIF 2.1.0 compliant tool

## CI Integration

### GitHub Actions

```yaml
- name: Install skill-issues
  run: cargo install --path .

- name: Lint skill files
  run: skill-issues --strict --format sarif skills/ > skill-issues.sarif
  continue-on-error: true

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skill-issues.sarif
```

### Generic CI

```yaml
- name: Lint skill files
  run: |
    cargo install --path .
    skill-issues --strict skills/
```

## Acknowledgments

Unicode tag detection, variation selector coverage, suspicion level scoring, and confusable space detection were inspired by [aid](https://github.com/wunderwuzzi23/aid) by [@wunderwuzzi23](https://github.com/wunderwuzzi23).

## License

AGPLv3
