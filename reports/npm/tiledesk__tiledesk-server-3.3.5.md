# Suspicious package report: `@tiledesk/tiledesk-server` 3.3.5 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@tiledesk/tiledesk-server` |
| Version | `3.3.5` |
| Ecosystem | npm |
| Risk score | 74 / 100 (high) |
| Published | 2026-11-17T10:14:30Z |
| Scanned | 2026-11-18T11:32:27Z |
| Registry page | https://www.npmjs.com/package/@tiledesk/tiledesk-server/v/3.3.5 |

## Indicators

- **suspicious-endpoint** (medium, +30): Hardcoded request-capture service in package code.

  Evidence in `package/utils/httpUtil.js`:

  ```text
  var res = await httpUtil.call("https://webhook.site/bd710929-9b43-4065-88db-78ee17f84aec", undefined, {c:1}, "POST")
  ```

- **suspicious-endpoint** (medium, +20): URL with a raw IP address instead of a hostname.

  Evidence in `package/services/trainingService.js`:

  ```text
  let training_api_url = process.env.CHATBOT_TRAINING_API_URL || "http://34.65.210.38/model/enqueuetrain";
  ```

- **npm-install-hook** (low, +12): 'preinstall' script runs automatically at install time.

  Evidence in `package.json`:

  ```text
  "preinstall": "if [ $ENABLE_ENTERPRISE_MODULE ]; then npm run enable-ent; fi"
  ```

- **obfuscation** (low, +12): Long high-entropy string literal (entropy above 5.0 bits per character).

  Evidence in `package/services/emailService.js`:

  ```text
  p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAunT2EopDAYnHwAOHd33KhlzjUXJfhmA+fK+cG85i9Pm33oyv1NoGrOynsni0PO6j7oRxxHqs6EMDOw4I/Q0C7aWn20oBomJZehTOkCV2xpuPKESiRktCe/MIZqbkRdypis4jSkFfFFkBHwgkAg5tb11E9…
  ```


## Suggested text for an upstream report

The npm package `@tiledesk/tiledesk-server` version `3.3.5` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Hardcoded request-capture service in package code.
- URL with a raw IP address instead of a hostname.
- 'preinstall' script runs automatically at install time.
- Long high-entropy string literal (entropy above 5.0 bits per character).

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40tiledesk%2Ftiledesk-server%403.3.5&package=npm%2F%40tiledesk%2Ftiledesk-server%403.3.5
