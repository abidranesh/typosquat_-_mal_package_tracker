# Suspicious package report: `spellwarden` 1.21.0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `spellwarden` |
| Version | `1.21.0` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-23T22:26:10Z |
| Scanned | 2026-11-25T02:26:28Z |
| Registry page | https://pypi.org/project/spellwarden/1.21.0/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `spellwarden-1.21.0/tests/test_rules_skill.py`:

  ````text
  assert findings({"SKILL.md": md("```python", "exec(base64.b64decode(blob))", "```")}, "SW-SKL-004")[0].location.line == 12
  ````

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `spellwarden_scan/rules/skill.py`:

  ```text
  P.Piped(r"(curl|wget|fetch|Invoke-WebRequest|iwr)\b",
  ```

- **binary-dropper** (medium, +20): Compiled executable or library in a package that is not declared as native.

  Evidence in `spellwarden-1.21.0/fixtures/skills/SW-SKL-010/positive/tools/helper.exe`:

  ```text
  spellwarden-1.21.0/fixtures/skills/SW-SKL-010/positive/tools/helper.exe (binary by extension)
  ```


## Suggested text for an upstream report

The pypi package `spellwarden` version `1.21.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Code downloads a file and then executes it or marks it executable.
- Compiled executable or library in a package that is not declared as native.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fspellwarden%401.21.0&package=pypi%2Fspellwarden%401.21.0
