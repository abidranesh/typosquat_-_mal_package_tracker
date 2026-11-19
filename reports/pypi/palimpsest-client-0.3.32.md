# Suspicious package report: `palimpsest-client` 0.3.32 (pypi)

> Generated automatically by PkgWatch from static analysis. The package was **not** installed or executed. This is a lead for human review, not a verdict: false positives happen.

| | |
|---|---|
| Package | `palimpsest-client` |
| Version | `0.3.32` |
| Ecosystem | pypi |
| Risk score | 100 / 100 (high) |
| Published | 2026-11-18T04:23:49Z |
| Scanned | 2026-11-19T09:32:29Z |
| Registry page | https://pypi.org/project/palimpsest-client/0.3.32/ |

## Indicators

- **obfuscation** (high, +45): Code decodes or unpacks a hidden payload and executes it. (in 3 files)

  Evidence in `palimpsest_local/benchmark_openstack.py`:

  ```text
  bootstrap = "exec(__import__('base64').b64decode(" + repr(base64.b64encode(code.encode()).decode()) + "))"
  ```

- **exfiltration** (high, +40): Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.

  Evidence in `palimpsest_local/nova_ceph_boot.py`:

  ```text
  passwd = Path("/etc/passwd").read_text() if Path("/etc/passwd").exists() else ""
  ```

- **binary-dropper** (medium, +20): Compiled executable or library in a package that is not declared as native.

  Evidence in `palimpsest_client-0.3.32/src/palimpsest_local/assets/oci-stage1-init.x86_64`:

  ```text
  palimpsest_client-0.3.32/src/palimpsest_local/assets/oci-stage1-init.x86_64 (ELF), palimpsest_client-0.3.32/tests/kvm/assets/inputs/lower1/.__palimpsest_workload_proof_v1 (ELF), palimpsest_client-0.3…
  ```

- **sparse-metadata** (info, +4): Missing or placeholder repository URL.

## Suggested text for an upstream report

The pypi package `palimpsest-client` version `0.3.32` shows indicators consistent with a supply-chain attack. Static analysis (no execution) found:

- Code decodes or unpacks a hidden payload and executes it. (in 3 files)
- Code reads credential, browser, chat-token or wallet files and also makes network calls in the same file.
- Compiled executable or library in a package that is not declared as native.
- Missing or placeholder repository URL.

Please review the package and remove it if it violates registry policy.

## Before forwarding

1. Open the registry page and read the flagged files yourself.
2. Confirm the behaviour is not a legitimate feature of the package.
3. If it holds up, report it via the "Report project as malware" link on the project page, or security@pypi.org.
4. If it does not, record it here: https://github.com/abidranesh/typosquat_-_mal_package_tracker/issues/new?template=false-positive.yml&labels=false-positive&title=False%20positive%3A%20pypi%2Fpalimpsest-client%400.3.32&package=pypi%2Fpalimpsest-client%400.3.32
