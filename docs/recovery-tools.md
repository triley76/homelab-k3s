# Recovery Tools

## Status

The `recovery-tools` Ansible role, the controlled installation playbook and the read-only validation playbook are implemented and checked locally: syntax checks, structure checks and expression tests. See [Expression Tests](#expression-tests) and [validation.md](validation.md#repository-validation).

**They have not been run against any node.** Installing on the existing cluster's first server is a live change. It needs separate, explicit approval, and its results are recorded only after it has run.

## Purpose

Phase 7 of the [home-cluster backup and disaster recovery design](https://github.com/triley76/home-cluster/blob/main/docs/design/backup-disaster-recovery.md) encrypts recovery material, such as the K3s server token, with [age](https://github.com/FiloSottile/age), on the server that holds it. Its helper scripts run on the first server and require exactly `age` v1.3.2. They fail closed on any other version, and they never install or download software themselves.

This role provides that prerequisite. It installs `age` and `age-keygen` on the first server (`servers[0]`, `k3s01`) only.

## Why age Is Pinned

- **Exact version.** The recovery helpers accept only v1.3.2, so the encrypted files and their verification come from one known release.
- **Not from apt.** Ubuntu's packaged `age` may be a different version, and it changes with package updates. The role never uses apt for `age`.
- **Verified download.** The role downloads the official release archive, `age-v1.3.2-linux-amd64.tar.gz`, from the [FiloSottile/age GitHub release](https://github.com/FiloSottile/age/releases/tag/v1.3.2). It verifies the archive's SHA-256 before extracting anything:

  `cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10`

  The same value is pinned by home-cluster's recovery-material CI job, merged into home-cluster `main` in pull request #19.
- **The pin is not a tunable.** The version, checksum, URL and install path are role `vars`, which inventory and play variables cannot override. The role also asserts the exact pin, so an extra-vars override fails closed instead of installing something else. Changing the version is a reviewed change to `roles/recovery-tools/vars/main.yml` and to that assertion.

## What the Role Does

1. **Platform guard.** It requires Linux, Ubuntu 24.04 and x86_64, and fails closed on anything else.
2. **Pin guard.** It asserts the exact version, checksum, URL, install path and binary list.
3. **Inspection** (read-only), for `/usr/local/bin/age` and `/usr/local/bin/age-keygen`:
   - `stat`, without following links and without reading checksums or contents;
   - `--version`, only for a regular, root-owned file that group and others cannot write. A symbolic link or any other file is never executed.
4. **Decision.**
   - If both binaries are regular files, not symbolic links, owned by `root:root`, mode `0755`, and report exactly `v1.3.2`, nothing is changed.
   - Otherwise both are installed from the pinned release.
   - A symbolic link at an install path is replaced. Anything else that is not a regular file, such as a directory, makes the role fail; it is never removed automatically.
5. **Installation**, only when needed:
   - creates a private working directory (`tempfile`, then `root:root` mode `0700`);
   - downloads the archive into it with `get_url`, verifying the SHA-256;
   - extracts only `age/age` and `age/age-keygen` with `unarchive`;
   - **validates both extracted binaries before anything under `/usr/local/bin` changes.** Each expected path must exist and be a regular file, not a symbolic link. Each must run successfully from the private working directory with `--version` and report exactly `v1.3.2`. If either fails, the role stops with the destination untouched;
   - only then removes any symbolic link at an install path, and installs both binaries into `/usr/local/bin` with `copy`, as `root:root` mode `0755`.

   The working directory is removed in an `always` section, whether or not any step failed. Download, checksum verification, extraction and installation use their Ansible modules (`get_url`, `unarchive`, `copy`). The only commands the role runs are the two `--version` reads.

   **The pair is not installed as one transaction.** `copy` replaces each file atomically, but `age` and `age-keygen` are separate tasks. An interrupted or failed run during installation can therefore leave a partial or mixed pair: one new and one old binary, or a binary missing where a symbolic link had been removed. Final verification fails closed in that case. **Do not use the tools until validation passes.** A controlled rerun repairs the installation.
6. **Verification.** It inspects both binaries again, and requires each to be a regular, non-link, `root:root`, mode `0755` file reporting exactly `v1.3.2`.

The role changes no service. It does not touch K3s, etcd, Chrony, VMware Tools or any cluster workload.

The first server needs outbound HTTPS to `github.com`, and to the host it redirects release downloads to.

## Fresh Builds

[`ansible/site.yml`](../ansible/site.yml) applies the role to `servers[0]` only, after common server preparation and before K3s is initialized.

## Existing Cluster: Controlled Installation

**Requires separate approval for each live run.** Run all commands from the `ansible/` directory.

1. **Report the current state** (read-only; no privilege escalation):

   ```bash
   ansible-playbook validate-recovery-tools.yml
   ```

2. **Install.** [`configure-recovery-tools.yml`](../ansible/configure-recovery-tools.yml) runs only with an explicit limit of exactly `k3s01`:

   ```bash
   ansible-playbook configure-recovery-tools.yml --limit k3s01
   ```

   The playbook refuses each of these, before any change:
   - an omitted limit;
   - a pattern or wildcard (`k3s0*`, `k3s01*`, `~k3s01$`), even when it resolves to `k3s01` alone;
   - a list (`k3s01,k3s02`, `k3s01,`);
   - a group (`servers`, `all`);
   - another host;
   - an inventory in which `k3s01` is not the first server.

   It uses `serial: 1`, `any_errors_fatal` and `max_fail_percentage: 0`.

3. **Validate and enforce:**

   ```bash
   ansible-playbook validate-recovery-tools.yml -e recovery_tools_enforce_acceptance=true
   ```

   The report contains only metadata for each binary: whether it exists, its file type, symbolic-link status, owner and group IDs, mode and version. It also contains the platform and the pinned version, with no file contents or checksums. Acceptance requires the supported platform and both binaries compliant.

4. **Idempotence check.** Running step 2 again must report `nothing to change` and no changed install tasks.

### Stop Conditions

Stop, and record the outcome, if:
- the guard refuses the run;
- the platform or pin assertion fails;
- the download fails or its checksum does not match;
- an install path is refused;
- an extracted binary is missing, not a regular file, fails to run or reports another version (the destination is then unchanged);
- verification or enforced validation fails.

A failed run leaves no working directory behind. If it failed before installation began, the previous binaries are unchanged. If it failed or was interrupted during installation, it may have left a partial or mixed pair. **Until enforced validation passes, treat the tools as unusable.** Do not run the recovery helpers, and repair the installation with a controlled rerun of step 2, followed by step 3.

The `always` cleanup cannot run if the run is killed outright, for example when the controller process or the SSH connection dies. The working directory holds only the public release archive and its extracted binaries. After an interrupted run, check by name only, and remove anything listed:

```bash
ansible k3s01 -b -m ansible.builtin.find -a 'paths=/tmp patterns=recovery-tools-age.* file_type=directory'
```

### Rollback

The tools are self-contained. To remove them (a live change, separately approved):

```bash
ansible k3s01 -b -m ansible.builtin.file -a 'path=/usr/local/bin/age state=absent'
ansible k3s01 -b -m ansible.builtin.file -a 'path=/usr/local/bin/age-keygen state=absent'
```

The recovery helpers then fail closed until the tools are reinstalled.

## Expression Tests

[`ansible/tests/recovery_tools_expressions.py`](../ansible/tests/recovery_tools_expressions.py) contacts no node, downloads nothing and installs nothing.

1. **Structure checks.** It checks:
   - the pinned version, checksum and URL, and that defaults cannot override them;
   - the exact-pin assertion;
   - the platform facts used;
   - the task order;
   - the absence of apt, package, shell, raw, script and service tasks;
   - that the only commands are the two `--version` reads: one for the installed binaries, one for the extracted binaries in the working directory;
   - the working directory (`tempfile`, `root:root` `0700`) and its removal in `always`;
   - the `get_url` checksum, the `unarchive` scope and the `copy` permissions;
   - that the extracted binaries are inspected, type-checked, run and version-checked, in that order, after extraction;
   - that no task touches the install directory before both extracted binaries pass;
   - that only symbolic links are removed;
   - the inspection trust gate and the verification criteria;
   - the installation playbook's settings and guard;
   - the `site.yml` scope;
   - that the validation playbook is read-only.
2. **Expression scenarios.** It runs the role's real tasks on localhost against mocked results.

| Area | Scenarios |
| --- | --- |
| Inspection and decision | A correct installation (no change, verification passes); a version with a trailing newline; a missing `age-keygen`; older, newer, pre-release, unprefixed and empty versions; a failed version read; a symbolic link (replaced, not refused); a directory (refused); modes `0775`, `0700` and `0777`; a non-root owner or group. Every non-compliant case also fails verification |
| Version-read trust gate | Executed only for a trusted regular root file; skipped for a symbolic link, a non-root owner, group- or other-writable, non-executable, a directory and a missing file. Paths point nowhere, so nothing real is executed |
| Platform | Ubuntu 24.04 x86_64 passes; Ubuntu 22.04 and 24.10, Debian, aarch64, i686 and non-Linux fail closed |
| Pin | The reviewed pin passes; another version, checksum, URL, install directory or binary list fails closed |
| Single-host guard | The real guard, against a throwaway local inventory with real `--limit` values: only `--limit k3s01` passes; the omitted, wildcard, regex, list, group, `all` and wrong-host limits, and a reordered inventory, are refused |
| Extracted-binary validation | The role's real extracted-binary tasks, against stand-in binaries in a local temporary directory. Both correct passes, and a marker standing in for the first destination change runs. A wrong `age` version, a wrong or pre-release `age-keygen` version, a symbolic link (even to a correct binary), a directory, a missing binary, a non-executable binary and a non-zero exit are each rejected, and the marker never runs |
| Cleanup | The role's own working-directory tasks and `always` cleanup, in a local temporary directory: removed after success, removed after a failure, and no error when the failure precedes the directory |

```bash
python3 ansible/tests/recovery_tools_expressions.py
```

## Evidence Boundaries

The local checks show the structure, the decision logic, the guard, the extracted-binary validation and the cleanup. They do not show any of the following:
- a real download;
- checksum verification against the real archive;
- extraction;
- installation as root;
- the exact result of `age --version` on the server;
- outbound access from the server;
- idempotence on a real node.

These are shown only by the separately approved live run and its enforced validation.
