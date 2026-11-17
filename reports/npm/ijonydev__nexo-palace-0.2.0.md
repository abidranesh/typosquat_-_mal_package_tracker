# Suspicious package report: `@ijonydev/nexo-palace` 0.2.0 (npm)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `@ijonydev/nexo-palace` |
| Version | `0.2.0` |
| Ecosystem | npm |
| Risk score | 79 / 100 (high) |
| Published | 2026-11-16T06:11:42Z |
| Scanned | 2026-11-17T12:17:23Z |
| Registry page | https://www.npmjs.com/package/@ijonydev/nexo-palace/v/0.2.0 |

## Indicators

- **npm-install-hook** (high, +40): 'postinstall' script runs a shell, downloader or inline code at install time.

  Evidence in `package.json`:

  ```text
  "postinstall": "node -e "import('node:fs').then(fs => { if (fs.existsSync('dist/installer.js')) import('./dist/installer.js'); })" || true"
  ```

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `package/dist/setup.js`:

  ```text
  parts.push("\n🐋 Alternativa: Ollama (más fácil, sin Python)", "", " # macOS:", " brew install ollama && ollama serve &", " ollama pull nomic-embed-text", "", " # Linux/Docker:", " curl -fsSL https://…
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The npm package `@ijonydev/nexo-palace` version `0.2.0` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- 'postinstall' script runs a shell, downloader or inline code at install time.
- Code downloads a file and then executes it or marks it executable.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via https://www.npmjs.com/support (choose "Report malware"), or the "Report malware" link on the package page.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20npm%2F%40ijonydev%2Fnexo-palace%400.2.0&package=npm%2F%40ijonydev%2Fnexo-palace%400.2.0
