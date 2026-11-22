# Suspicious package report: `fullshield` 3.11.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `fullshield` |
| Version | `3.11.0` |
| Ecosystem | npm |
| Risk score | 79 / 100 (high) |
| Published | 2026-11-20T07:28:48Z |
| Scanned | 2026-11-22T07:16:07Z |
| Registry page | https://www.npmjs.com/package/fullshield/v/3.11.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/cli/index.js`:

  ```text
  `).length}function He(e){return {id:L(e.ruleId,e.file,`${e.line??0}|${e.message}`),ruleId:e.ruleId,module:e.module,title:e.title,severity:e.severity,confidence:e.confidence,cwe:e.cwe,file:e.file,line…
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/cli/index.js`:

  ```text
  `,n);return t===-1?e.length:t+1}function YH(e,n){let t=e.indexOf("*/",n+2);return t===-1?e.length:t+2}function JH(e,n,t){let r=n+1;for(;r<e.length;){if(e[r]==="\\"){r+=2;continue}if(t==="`"&&e[r]==="…
  ```

- **sparse-metadata** (info, +4): Missing or placeholder README.

## Suggested text for an upstream report

The npm package `fullshield` version `3.11.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder README.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Ffullshield%403.11.0&package=npm%2Ffullshield%403.11.0
