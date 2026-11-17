# Suspicious package report: `dsh-zterm` 0.2.2 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `dsh-zterm` |
| Version | `0.2.2` |
| Ecosystem | npm |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-16T06:25:40Z |
| Scanned | 2026-11-17T12:17:23Z |
| Registry page | https://www.npmjs.com/package/dsh-zterm/v/0.2.2 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/lib/index.js`:

  ```text
  const paths = configured ? [configured.startsWith("~/") ? join2(home, configured.slice(2)) : configured] : DEFAULT_KEY_FILES.map((file) => join2(home, ".ssh", file));
  ```

- **npm-install-hook** (medium, +25): 'postinstall' script runs a bundled JavaScript file at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node scripts/prepare-native.mjs"
  ```

- **obfuscation** (medium, +20): Strings are assembled from long character-code chains.

  Evidence in `package/lib/client.js`:

  ```text
  WARNING: This link could potentially be dangerous`)){let t=window.open();if(t){try{t.opener=null}catch{}t.location.href=i}else console.warn("Opening link blocked as opener could not be cleared")}}r.O…
  ```


## Suggested text for an upstream report

The npm package `dsh-zterm` version `0.2.2` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- 'postinstall' script runs a bundled JavaScript file at install time.
- Strings are assembled from long character-code chains.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fdsh-zterm%400.2.2&package=npm%2Fdsh-zterm%400.2.2
