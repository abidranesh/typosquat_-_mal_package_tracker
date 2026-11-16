# Suspicious package report: `@willbooster/wb` 23.4.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@willbooster/wb` |
| Version | `23.4.0` |
| Ecosystem | npm |
| Risk score | 75 / 100 (high) |
| Published | 2026-11-15T14:47:38Z |
| Scanned | 2026-11-16T10:06:48Z |
| Registry page | https://www.npmjs.com/package/@willbooster/wb/v/23.4.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/dist/index.js`:

  ```text
  `),n=[];for(let e=0;e<t.length;e++){let r=t[e]??``,i=/^\s*([A-Za-z]+)\s+(.*)$/.exec(r);if(!i?.[1]||!i[2])continue;let a=i[1].toUpperCase(),o=i[2].trim();if(n.push([a,o]),a===`RUN`||a===`COPY`||a===`A…
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/docker/bash/install-litestream.sh`:

  ```text
  curl -fsSLO "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/${DEB_FILE}"
  ```


## Suggested text for an upstream report

The npm package `@willbooster/wb` version `23.4.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40willbooster%2Fwb%4023.4.0&package=npm%2F%40willbooster%2Fwb%4023.4.0
