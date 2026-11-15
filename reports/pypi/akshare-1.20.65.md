# Suspicious package report: `akshare` 1.20.65 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `akshare` |
| Version | `1.20.65` |
| Ecosystem | pypi |
| Risk score | 85 / 100 (high) |
| Published | 2026-11-15T13:27:21Z |
| Scanned | 2026-11-15T14:43:12Z |
| Registry page | https://pypi.org/project/akshare/1.20.65/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it.

  Evidence in `akshare/data/jm.js`:

  ```text
  var ynfqt = '__0x2fb9f'
  ```

- **obfuscation** (medium, +20): Strings are assembled from long character-code chains. (in 2 files)

  Evidence in `akshare/data/crypto.js`:

  ```text
  for (a = a.replace(/[^A-Za-z0-9\+\/\=]/g, ""); j < a.length;) f = _keyStr.indexOf(a.charAt(j++)), g = _keyStr.indexOf(a.charAt(j++)), h = _keyStr.indexOf(a.charAt(j++)), i = _keyStr.indexOf(a.charAt(…
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `akshare-1.20.65/akshare/alternative/alternative_air_hebei.py`:

  ```text
  https://110.249.223.67/publish
  ```


## Suggested text for an upstream report

The pypi package `akshare` version `1.20.65` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it.
- Strings are assembled from long character-code chains. (in 2 files)
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fakshare%401.20.65&package=pypi%2Fakshare%401.20.65
