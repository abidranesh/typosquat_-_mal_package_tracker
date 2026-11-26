# Suspicious package report: `@bayersito/frida-rea` 17.23.2 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@bayersito/frida-rea` |
| Version | `17.23.2` |
| Ecosystem | npm |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-25T06:41:29Z |
| Scanned | 2026-11-26T12:59:41Z |
| Registry page | https://www.npmjs.com/package/@bayersito/frida-rea/v/17.23.2 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/releng/meson/mesonbuild/wrap/wrap.py`:

  ```text
  self.netrc = netrc()
  ```

- **npm-install-hook** (medium, +25): 'install' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "install": "node scripts/install.js"
  ```

- **binary-dropper** (medium, +20): Compiled executable or library in a package that is not declared as native.

  Evidence in `package/test/data/unixvictim-linux-x86`:

  ```text
  package/test/data/unixvictim-linux-x86 (ELF), package/test/data/unixvictim-linux-x86_64 (ELF)
  ```


## Suggested text for an upstream report

The npm package `@bayersito/frida-rea` version `17.23.2` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- 'install' script runs a bundled JavaScript file at install time.
- Compiled executable or library in a package that is not declared as native.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40bayersito%2Ffrida-rea%4017.23.2&package=npm%2F%40bayersito%2Ffrida-rea%4017.23.2
