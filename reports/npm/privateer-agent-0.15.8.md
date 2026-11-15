# Suspicious package report: `privateer-agent` 0.15.8 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `privateer-agent` |
| Version | `0.15.8` |
| Ecosystem | npm |
| Risk score | 87 / 100 (high) |
| Published | 2026-11-15T12:57:09Z |
| Scanned | 2026-11-15T22:45:36Z |
| Registry page | https://www.npmjs.com/package/privateer-agent/v/0.15.8 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/bin/privateer-launch.mjs`:

  ```text
  // from local state only: no network, nothing sent anywhere, and no secret printed.
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/bin/privateer-verify.mjs`:

  ```text
  dim(" curl -fsSL https://privateer.pro/install.sh | sh\n") +
  ```

- **obfuscation** (low, +12): Long high-entropy string literal (entropy above 5.0 bits per character). (in 2 files)

  Evidence in `package/dist-boot/c-YUSTRATJ.mjs`:

  ```text
  ewogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiNmYyNjAwODlkNTkyM2RhZjIwMTY2Y2E2NTdjNTQzYWY2MTgzNDZhYjk3MTg4NGE5OTk2MmIwMTk4OGJiZTBjMyIsCiAgICJzaWciOiAiIgogIH0sCiAgewogICAia2V5aWQiOiAiZTcxYTU0ZDU0Mzg…
  ```


## Suggested text for an upstream report

The npm package `privateer-agent` version `0.15.8` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Long high-entropy string literal (entropy above 5.0 bits per character). (in 2 files)

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fprivateer-agent%400.15.8&package=npm%2Fprivateer-agent%400.15.8
