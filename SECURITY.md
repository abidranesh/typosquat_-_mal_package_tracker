# Security policy

## Reporting a vulnerability in PkgWatch

PkgWatch processes hostile input by design: package names, metadata and archives published
by anyone. If you find a way for that input to do something it should not, please report it
privately:

- Use **GitHub's private vulnerability reporting** for this repository
  (Security tab → "Report a vulnerability").
- Please do not open a public issue for an unpatched vulnerability.

Useful reports include: an archive or metadata document that makes the scanner execute
code, write outside its output directories, exhaust memory or time beyond the configured
limits, or inject markup or script into the dashboard, the feeds, or a triage issue.

You can expect an acknowledgement within a week. Fixes are released on `main`; there are no
maintained release branches.

## What is in scope

- The scanner (`pkgwatch/`), its workflows, and the dashboard under `docs/`.
- The safety properties this project promises:
  - scanned packages are never installed, imported or executed;
  - archives are read in memory with download, size and file-count limits, and entries
    with absolute or parent-directory paths are rejected;
  - registry-supplied text is only ever inserted into the dashboard as text;
  - the workflows use no secret other than the built-in `GITHUB_TOKEN`.

## What is not a vulnerability

- **A false positive or a missed package.** Use the false-positive issue template, or
  propose a detector.
- **A suspicious package you found on npm or PyPI.** Report it to the registry:
  npm via the "Report malware" link on the package page, PyPI via "Report project as
  malware" on the project page or `security@pypi.org`.
- **Detection evasion.** The heuristics are public and can be evaded; improvements are
  welcome as ordinary pull requests.

## Fixtures

The test fixtures imitate attack patterns but are inert: they are JSON strings, reference
only `example.invalid` and documentation-range addresses, and are never executed. If an
antivirus product flags a file in this repository, please open an issue so the fixture can
be reworded.
