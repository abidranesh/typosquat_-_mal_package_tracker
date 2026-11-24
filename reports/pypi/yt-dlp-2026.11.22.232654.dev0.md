# Suspicious package report: `yt-dlp` 2026.11.22.232654.dev0 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `yt-dlp` |
| Version | `2026.11.22.232654.dev0` |
| Ecosystem | pypi |
| Risk score | 72 / 100 (high) |
| Published | 2026-11-22T23:31:53Z |
| Scanned | 2026-11-24T06:16:30Z |
| Registry page | https://pypi.org/project/yt-dlp/2026.11.22.232654.dev0/ |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `yt_dlp/cookies.py`:

  ```text
  path = _newest(_find_files(browser_root, 'Local State', logger))
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `yt_dlp/extractor/presstv.py`:

  ```text
  base_url = 'http://192.99.219.222:82/presstv'
  ```

- **obfuscation** (low, +12): Long high-entropy string literal (entropy above 5.0 bits per character). (in 5 files)

  Evidence in `yt_dlp/extractor/mangomolo.py`:

  ```text
  base_url=aHR0cHM6Ly9heW4ub20vdmlkZW8vMjk0MzEyNDIvJUQ4JUE3JUQ5JTg0JUQ4JUEzJUQ5JTg1JUQ5JTg2JUQ5JThBJUQ4JUE3JUQ4JUFBLSVEOCVBNyVEOSU4NCVEOCVCMyVEOCVBOCVEOCVCOS0lRDglQTclRDklODQlRDglQUQlRDklODQlRDklODIlRD…
  ```


## Suggested text for an upstream report

The pypi package `yt-dlp` version `2026.11.22.232654.dev0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- URL with a raw IP address instead of a hostname.
- Long high-entropy string literal (entropy above 5.0 bits per character). (in 5 files)

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fyt-dlp%402026.11.22.232654.dev0&package=pypi%2Fyt-dlp%402026.11.22.232654.dev0
