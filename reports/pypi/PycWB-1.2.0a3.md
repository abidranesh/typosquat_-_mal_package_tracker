# Suspicious package report: `PycWB` 1.2.0a3 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `PycWB` |
| Version | `1.2.0a3` |
| Ecosystem | pypi |
| Risk score | 84 / 100 (high) |
| Published | 2026-11-25T17:38:30Z |
| Scanned | 2026-11-26T22:16:29Z |
| Registry page | https://pypi.org/project/PycWB/1.2.0a3/ |

## Indicators

- **binary-dropper** (medium, +35): Code downloads a file and then executes it or marks it executable.

  Evidence in `pycwb-1.2.0a3/pycwb/post_production/diagram.py`:

  ```text
  requires ``d2`` binary (``brew install d2`` / ``curl -fsSL https://d2lang.com/install.sh | sh``).
  ```

- **python-install-code** (medium, +25): setup.py subprocess.check_call() starts a process at install time.

  Evidence in `pycwb-1.2.0a3/setup.py:86`:

  ```text
  subprocess.check_call(['cmake', ext.sourcedir] + cmake_args, cwd=self.build_temp, env=env)
  ```

- **binary-dropper** (medium, +20): Compiled executable or library in a package that is not declared as native.

  Evidence in `pycwb-1.2.0a3/cwb-core/watasm_elf64.o`:

  ```text
  pycwb-1.2.0a3/cwb-core/watasm_elf64.o (ELF)
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `PycWB` version `1.2.0a3` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code downloads a file and then executes it or marks it executable.
- setup.py subprocess.check_call() starts a process at install time.
- Compiled executable or library in a package that is not declared as native.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2FPycWB%401.2.0a3&package=pypi%2FPycWB%401.2.0a3
