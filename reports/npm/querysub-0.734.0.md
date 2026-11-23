# Suspicious package report: `querysub` 0.734.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `querysub` |
| Version | `0.734.0` |
| Ecosystem | npm |
| Risk score | 91 / 100 (high) |
| Published | 2026-11-22T05:30:18Z |
| Scanned | 2026-11-23T22:15:55Z |
| Registry page | https://www.npmjs.com/package/querysub/v/0.734.0 |

## Indicators

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `package/src/deployManager/setupMachineMain.ts`:

  ```text
  await runPromise(`ssh ${sshRemote} "ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ''"`);
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/src/deployManager/setupMachineMain.ts`:

  ```text
  await runPromise(`ssh ${sshRemote} "curl -fsSL https://deb.nodesource.com/setup_${minimumNodeMajor}.x | sudo -E bash -"`);
  ```

- **sparse-metadata** (info, +8): Missing or placeholder description, README.
- **obfuscation** (low, +8): Long base64 or hex blob embedded in source code.

  Evidence in `package/src/misc/lz4_wasm_nodejs.js`:

  ```text
  AGFzbQEAAAABmwEWYAJ/fwF/YAN/f38Bf2ACf38AYAF/AGADf39/AGAEf39/fwBgAAJ/f2AFf39/f38Bf2AAAGAFf39/f38AYAF/AX9gBH9/f38Bf2ACf38Cf39gAAR/f39/YAJ/fwFvYAd/f39/f39/AGAGf39/f39/AX9gAX8BfmALf39/f39/f39/f38Bf2AAAX9…
  ```


## Suggested text for an upstream report

The npm package `querysub` version `0.734.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder description, README.
- Long base64 or hex blob embedded in source code.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2Fquerysub%400.734.0&package=npm%2Fquerysub%400.734.0
