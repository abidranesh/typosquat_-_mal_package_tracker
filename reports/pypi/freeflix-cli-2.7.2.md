# Suspicious package report: `freeflix-cli` 2.7.2 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `freeflix-cli` |
| Version | `2.7.2` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-24T20:45:11Z |
| Scanned | 2026-11-26T03:13:00Z |
| Registry page | https://pypi.org/project/freeflix-cli/2.7.2/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 4 files)

  Evidence in `freeflix_cli-2.7.2/tests/test_premium_players.py`:

  ```text
  "eval(function(p,a,c,k,e,d){while(c--)if(k[c])p=p.replace("
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `freeflix_cli-2.7.2/scripts/install-mac.sh`:

  ```text
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `freeflix_cli-2.7.2/src/freeflix_cli/cloudflare.py`:

  ```text
  _CurlOpt.DOH_URL: "https://1.1.1.1/dns-query",
  ```


## Suggested text for an upstream report

The pypi package `freeflix-cli` version `2.7.2` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 4 files)
- Code downloads a file and then executes it or marks it executable.
- URL with a raw IP address instead of a hostname.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Ffreeflix-cli%402.7.2&package=pypi%2Ffreeflix-cli%402.7.2
