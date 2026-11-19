# Suspicious package report: `stacktrace-cli` 0.26.1 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `stacktrace-cli` |
| Version | `0.26.1` |
| Ecosystem | pypi |
| Risk score | 84 / 100 (high) |
| Published | 2026-11-18T16:33:59Z |
| Scanned | 2026-11-19T18:42:17Z |
| Registry page | https://pypi.org/project/stacktrace-cli/0.26.1/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `stacktrace/detector/deterministic.py`:

  ```text
  # An inline script's own words: `open('/home/dev/.aws/credentials')`.
  ```

- **unsafe-archive** (high, +40): Archive contains absolute or parent-directory paths and was not unpacked.

  Evidence in `(archive)`:

  ```text
  unsafe: link escapes archive: 'stacktrace_cli-0.26.1/.claude/skills/release-stacktrace/SKILL.md' -> '../../../.agents/skills/release-stacktrace/SKILL.md'
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `stacktrace-cli` version `0.26.1` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Archive contains absolute or parent-directory paths and was not unpacked.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fstacktrace-cli%400.26.1&package=pypi%2Fstacktrace-cli%400.26.1
