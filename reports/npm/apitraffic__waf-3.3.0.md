# Suspicious package report: `@apitraffic/waf` 3.3.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@apitraffic/waf` |
| Version | `3.3.0` |
| Ecosystem | npm |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-25T13:47:13Z |
| Scanned | 2026-11-26T22:16:29Z |
| Registry page | https://www.npmjs.com/package/@apitraffic/waf/v/3.3.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/engine/detectors/rce.js`:

  ```text
  // A bare command with flags or a system path argument (e.g. `cat /etc/passwd`)
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/engine/detectors/rce.js`:

  ```text
  * locale list `en\nid\nms`, a docs snippet `curl https://…`). `detectRCE` (and
  ```

- **exfiltration** (medium, +30): Code serialises the whole process environment in a file that makes network calls.

  Evidence in `package/dist/engine/detectors/rce.js`:

  ```text
  const BINARIES = 'cat|tac|nl|head|tail|less|more|ls|dir|pwd|id|whoami|uname|hostname|ifconfig|ipconfig|netstat|ss|ps|top|env|printenv|set|export|echo|printf|wget|curl|fetch|nc|ncat|netcat|socat|telne…
  ```


## Suggested text for an upstream report

The npm package `@apitraffic/waf` version `3.3.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Code serialises the whole process environment in a file that makes network calls.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40apitraffic%2Fwaf%403.3.0&package=npm%2F%40apitraffic%2Fwaf%403.3.0
