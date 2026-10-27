# Validation

## Overview

This document records the validation performed against the V2 Kubernetes platform.

The purpose is to distinguish between:

- Architecture that has been implemented

- Behavior that has been directly observed

- Capabilities that remain planned or require additional testing

The validation described here applies to the specific lab configuration and test scenarios exercised. It is not intended to represent production certification, exhaustive resilience testing, or a guarantee of application-level availability.

## Validated Platform

The tested platform consists of:

| Component | Validated Configuration |

| --- | --- |

| Kubernetes distribution | K3s |

| K3s version | `v1.36.4+k3s1` |

| Control-plane nodes | 3 |

| Datastore | Embedded etcd |

| API high availability | kube-vip |

| GitOps | Flux 2.9.5 |

| VM platform | VMware Workstation |

| Guest operating system | Ubuntu Server 24.04 |

The public repository substitutes RFC 5737 documentation addresses for the private addressing used by the working lab.

## Automation Validation

The automation has been exercised across the major stages required to construct the cluster.

### Packer

The Packer workflow has been used to create the reusable Ubuntu VMware base image used by the Kubernetes nodes.

The build establishes a consistent operating-system foundation before Kubernetes-specific configuration is applied.

### PowerShell

The PowerShell automation has been used for:

- VM cloning

- Guest discovery

- Bootstrap inventory generation

- Node bootstrap coordination

- Post-bootstrap validation

The scripts consume the common cluster configuration from `nodes.py`.

### Ansible

Ansible has been used to:

- Prepare Kubernetes server nodes

- Initialize the first K3s server

- Deploy kube-vip

- Join additional K3s servers

- Configure the three-node control plane

The top-level Ansible playbooks have also been syntax-checked as part of repository validation.

## Cluster Formation

The V2 automation successfully constructed a three-node K3s server cluster using embedded etcd.

Expected cluster members:

```text

k3s01

k3s02

k3s03

```

All three servers successfully joined the cluster.

K3s was pinned to:

```text

v1.36.4+k3s1

```

rather than allowing the build to select an unspecified latest version.

## Sequential Control-Plane Join Validation

An important finding during development involved the process used to add the additional K3s servers.

An earlier workflow attempted control-plane joins concurrently.

Testing exposed an etcd learner issue during this process.

The join workflow was changed to:

```yaml

serial: 1

```

This causes additional control-plane nodes to join sequentially.

The cluster subsequently formed successfully using the serialized workflow.

This behavior is retained in the automation as an engineering decision derived from observed cluster behavior.

## Kubernetes API Validation

kube-vip provides a virtual address for the Kubernetes API.

Rather than requiring clients to connect directly to one control-plane server, the API is accessed through the virtual endpoint.

Validation confirmed that:

- The VIP was present on a control-plane server.

- The Kubernetes API was reachable through the VIP.

- A single server owned the VIP during normal operation.

- VIP ownership could transfer during the controlled failure test.

## Controlled Single-Node Failure Test

A controlled failure test was performed against the running three-node cluster.

### Initial State

Before the test:

- Three K3s server VMs were running.

- The Kubernetes nodes were participating in the cluster.

- kube-vip had a single active owner.

- The Kubernetes API was available through the virtual address.

### Failure Injection

The entire VM hosting the kube-vip address was powered off.

This tested more than a Kubernetes process restart. From the cluster's perspective, the server itself disappeared.

### Observed Behavior

After the VM was powered off:

- The kube-vip address moved to another control-plane server.

- The surviving Kubernetes nodes remained available.

- The Kubernetes API continued to be served through the virtual endpoint.

- Workloads were able to reschedule onto surviving capacity.

This demonstrated successful control-plane API failover for the specific single-node failure scenario tested.

## Node Recovery Test

The powered-off server was subsequently restarted.

Observed behavior included:

- The server returned to the network.

- K3s restarted.

- The server rejoined the existing cluster.

- The cluster returned to three participating server nodes.

- kube-vip remained on the surviving server that had assumed ownership.

- Only one server owned the VIP.

The returning node therefore did not cause competing VIP ownership during the observed recovery.

## What the Failure Test Demonstrates

The controlled test provides direct evidence for the following scenario:

```text

Healthy three-node cluster

          |

          v

Current VIP owner fails

          |

          v

VIP moves to surviving server

          |

          v

API remains available

          |

          v

Failed server returns

          |

          v

Server rejoins cluster

          |

          v

Single VIP owner remains

```

The result supports the architecture's intended behavior under the tested loss of one control-plane VM.

## What Has Not Been Claimed

The validation scope is intentionally narrow.

The test does **not** establish that the platform can tolerate every possible failure condition.

In particular, this validation does not claim:

- Arbitrary multi-node failure tolerance

- Survival of simultaneous loss of two control-plane servers

- Zero application downtime

- Zero interrupted client connections

- Storage-level application resilience

- Production-scale performance

- Production security certification

- Disaster recovery across physical sites

- Automated recovery from every etcd failure mode

Those scenarios require separate tests and, in some cases, additional architecture.

The distinction between configured capability and observed behavior is intentional.

## Flux GitOps Validation

Flux 2.9.5 has been bootstrapped against the V2 cluster.

The validated GitOps foundation includes:

- Flux controllers installed and healthy

- Git source reconciliation

- Kustomization reconciliation

- Synchronization from the V2 GitOps branch

A validated reconciliation reached revision:

```text

feature/v2-cluster@sha1:153da6ff

```

This demonstrates that the GitOps control plane can retrieve and reconcile the desired state from the companion repository.

It does not imply that every planned Kubernetes platform service has already been deployed.

## Time Synchronization Validation

Chrony remediation was deployed to the live three-node embedded-etcd cluster on 2026-10-14.

### Procedure

1. A pre-change embedded-etcd snapshot was created and its file checksum verified.
2. The nodes were processed individually in the order `k3s01`, `k3s02`, `k3s03`; every Ansible invocation used an explicit one-node `--limit`.
3. Cluster and workload health were checked between nodes.
4. Each changed node received an observation period before the next node was touched.
5. After all nodes converged, acceptance was enforced seven times, with sample starts ten minutes apart.

### Observed Result

- All three nodes ran Chrony with the distinct `-R` argument and reported normal synchronization.
- `systemd-timesyncd` was inactive and masked on every node.
- VMware Tools periodic time synchronization was disabled on every node.
- No enforced sample found a time offset beyond the accepted threshold or a frequency pinned at ±500 ppm.
- No sample found an etcd high-clock-drift warning in its 15-minute lookback.
- All three Kubernetes nodes and etcd remained ready.
- The six required Flux Kustomizations remained present exactly once and ready.
- All Deployments remained available.
- Monitoring Pods, StatefulSets and the node-exporter DaemonSet remained healthy.
- Both replicas of `platform-canary` remained healthy.
- A separate 30-minute LAN monitor completed 3,397 successful requests with zero failures and observed both canary replicas.
- A repeat run against the already compliant `k3s02` reported zero changes, providing live idempotency evidence for that node.

### Evidence Inventory

| Evidence | Result | SHA-256 |
| --- | --- | --- |
| Pre-change etcd snapshot | Created and verified | `0e808a766136a04a771eb8d8d5f013f90568e2c115b409012ec218766b4bbb15` |
| `k3s01` apply | Passed | `4e8870f0c9963cb8ba867c6433167c6f46b195dc300ff1241a3b09cf62b69fd2` |
| `k3s01` post-change validation | Passed | `21b9763e9b5cdff5863c7591906e5f41c57830ed3b8d1673a13d918138f2ee5a` |
| `k3s01` 30-minute LAN monitor | 3,397 successes; 0 failures | `20d64ab03d9dcbbdb51c7c53e5b2bd0947d820a350efdd74907a331d6a5b18a6` |
| `k3s02` pre-change report | Passed | `72c1e02f4a9fecaa7022cabf145c8ec09653d5262a2cc733ed032ca6663a1726` |
| `k3s02` compliant re-run | Passed; 0 changes | `fa750adcddc37c821e2d489386006c66c35c29300dd1b6ceed98fb76c0e38a42` |
| `k3s02` post-change validation | Passed | `86d911826fc14997586263bb57ec167de65f0a114216bcfdf32469d3b42a9b30` |
| `k3s03` apply | Passed | `0d041fd3dc50e0c19d431e7f3bf6c249753e8531a380ac45b6a40eacec3cdd4e` |
| First enforced all-cluster acceptance | Passed | `640d9956e34d1f6fd3a4e09cddb829770d9332b56589d02ed5b8471046e0893b` |
| Seven-sample stability window | All samples passed | `41086676c2c89b53e162d47b8e35ea260cbced4335708f090fdc2ac3bbd8aa64` |

The raw evidence files are retained outside the public repository because they include environment-specific runtime details. The checksums bind this validation record to those retained artifacts.

### Remaining Boundary

This demonstrates the observed serial rollout and a one-hour stability window. It does not yet demonstrate persistence across reboot, suspend/resume, snapshot restore or a future Chrony package upgrade, and it is not a production-duration reliability test.

## Repository Validation

Before preparing the public portfolio version of this repository, the automation was subjected to additional static validation.

### Python

The Python configuration and inventory-generation code was compiled with Python's `py_compile` mechanism.

The inventory generator was also executed against the sanitized public configuration and successfully generated the expected three-node inventory.

### PowerShell

The PowerShell scripts were parsed to detect syntax errors.

The scripts validated include:

```text

bootstrap_nodes.ps1

clone_nodes.ps1

discover_nodes.ps1

generate_bootstrap_inventory.ps1

config/workstation.example.ps1

```

### Ansible

The Ansible environment used for repository validation reported:

```text

ansible-core 2.16.3

Python 3.12.3

Jinja 3.1.2

```

The top-level playbooks were syntax-checked:

```text

bootstrap.yml

deploy-kube-vip.yml

init-first-server.yml

join-servers.yml

preflight.yml

site.yml

```

The bootstrap playbook depends on the temporary bootstrap inventory generated during VM discovery. Static syntax validation therefore confirms the playbook structure but does not substitute for a live bootstrap execution.

The time-synchronization playbooks were later syntax-checked the same way, with ansible-core 2.16.3:

```text

configure-time-sync.yml

validate-time-sync.yml

```

`ansible/tests/time_sync_expressions.py` also checks the time-synchronization playbook and role structure, including the post-K3s no-startup-step play in every build playbook. It exercises the decision logic of the `time-sync` role and the acceptance playbook locally, against mocked command output.

Syntax checks and expression tests alone do not show live convergence. That gap was closed by the serial rollout and enforced acceptance exercise recorded in [Time Synchronization Validation](#time-synchronization-validation) and described in [time-synchronization.md](time-synchronization.md).

The recovery-tools playbooks were syntax-checked the same way, with ansible-core 2.16.3 and a dummy inventory, together with `site.yml`:

```text

configure-recovery-tools.yml

validate-recovery-tools.yml

```

`ansible/tests/recovery_tools_expressions.py` checks the `recovery-tools` role and playbook structure. It runs the role's inspection, decision, platform, pin and verification tasks against mocked results. It runs the extracted-binary validation against local stand-in binaries, and checks that nothing reaches the destination unless both pass. It runs the real single-host guard against a throwaway local inventory with real `--limit` values, and the role's own working-directory cleanup locally. It downloads and installs nothing.

The Stage 3 secrets-encryption playbooks were syntax-checked the same way, with ansible-core 2.16.3 and a dummy inventory:

```text

snapshot-etcd.yml

secrets-encryption-enable.yml

secrets-encryption-restart.yml

secrets-encryption-rotate.yml

secrets-encryption-canary.yml

validate-secrets-encryption.yml

install-etcdctl-rehearsal.yml

```

`ansible/tests/secrets_encryption_expressions.py` checks:

- the role and playbook structure;
- the guard, using the real phase playbooks with real `--limit` values, confirmations and environments. Refused cases must stop inside the guard, before facts or privilege escalation. They include rehearsal-only work against an inventory containing a live host name, not-yet-rehearsal-approved drop-in removal, and injected approvals or rollback phases;
- the rollback model. No phase runs `secrets-encrypt disable`, `reencrypt`, `prepare` or `rotate`, and no rollback playbook exists. `enable` requires the recorded pre-enable checkpoint p0 (newest Stage 3 snapshot, name and SHA-256 recorded, token presence confirmed by `lstat` only, taken by the last accepted invocation), and the enabling rotation requires it too. `rotate-keys` is never a plaintext rollback, and `disable` is not accepted or used. `Disabled` is still parsed for diagnosis, but `configured-disabled` validation passes only before activation. After activation the only rollback is a snapshot restore of p0, a documented manual procedure that rolls back all Kubernetes and etcd state after p0 and requires a written operator impact acknowledgment;
- status parsing, which fails closed, and the narrowly defined `unavailable` status that only the enable restart round tolerates;
- the health, preservation and snapshot gates;
- every phase decision, including the fixed restart order and confirmation replay;
- the corrected step 1: the exact `enable` result before the marker, no status read afterwards, and the enable restart round. That round must be strictly ordered and not replayed, and requires a consistent marker, ledger and pre-enable checkpoint. It ends with a required `Disabled`/`start`/matching-hashes status before rotation;
- the exclusive enable restart round. While it is incomplete, the next restart is the only phase admitted, even when status is readable and settled. Every other phase, including enforced validation, is refused until all three servers are durably verified after the converged status check. Inconsistent ledger, marker or checkpoint evidence fails closed;
- mutation tests: each reintroduced defect must change the outcome of the regression test it targets;
- state-directory and ledger link safety;
- the etcdctl installer's check-before-install order;
- the exact single-key raw canary verification pipeline, with a stub etcdctl;
- the canary lifecycle, with a stub k3s;
- that no canary value, raw etcd record, hash-mismatch node name or protected path appears in the output.

The required disposable k3d rehearsal **passed on 2026-10-26 (run 8)**, after earlier attempts that each led to a correction:

- **2026-10-23:** stopped at step 1. After `k3s secrets-encrypt enable`, `k3s secrets-encrypt status` failed on every server until restarts, which the encoded procedure did not allow for.
- **2026-10-24:** stopped after `k3s01`'s restart. Status then became readable and settled on every server, so a gate that relied on the unavailable status no longer blocked checkpoint p1 mid-round.
- **2026-10-25 and 2026-10-26:** passed enablement, the exclusive restart round, rotation, the second restart round and the encrypted canary checks. They stopped at the rollback re-encryption: K3s `v1.36.4+k3s1` rejects `reencrypt` for secretbox ("use rotate-keys instead"), and `rotate-keys` always re-encrypts.
- **2026-10-26 (complete lifecycle):** passed every forward step through the post-encryption checkpoint. It stopped at the restore: the reset, delivered as configuration-file fields followed by an ordinary start of the S1 container, did not complete within 600 seconds.
- **2026-10-26 (run 8, passed):**
  - every forward phase passed, including all 11 p0 negative checks and exactly one rotation;
  - the explicit p0 restore passed, with exit status 0, the documented message at ERROR level and the reset flag;
  - S1 recovered as a healthy single member, then S2 and S3 rejoined one at a time to 3/3 healthy etcd;
  - the restored p0 controls matched byte-for-byte, the post-p0 canaries were absent, and the restored Secret was plaintext in raw etcd;
  - the lifecycle audit and teardown passed;
  - the Flux and workload acceptance checks were not applicable in disposable k3d and are not claimed as passed;
  - during the planned concurrent stop, S1 exited 1 while S2 and S3 exited 143. The cause was not determined, and it remains an open observation.
- **2026-10-26 (restore-mechanism diagnostic, not a complete rehearsal):** the explicit `k3s server --cluster-reset --cluster-reset-restore-path=<p0>` restored p0 and exited 0, with the documented message at ERROR level and the reset flag present. S1 was recovered with its network identity, and S2 and S3 rejoined one at a time. The generated encryption files stayed on disk while the status returned to not-configured.

All findings are corrected and statically re-tested:

- phase transitions are gated by the durable state of the enable restart round, not by status readability;
- the in-place rollback is removed;
- after activation, the only rollback is a snapshot restore of the pre-enable checkpoint;
- the restore is delivered by explicit invocation, accepted only with exit status 0, the documented message and the reset flag, and judged by status, readbacks and raw records rather than by the retained encryption files; the k3d rehearsal reproduces it with an auxiliary runner and a controlled network handoff that are rehearsal tooling only.

The three-VM rehearsal **passed on 2026-10-27** at commit `825b09b`, under systemd: both cycles, the p2 and p0 restores, and the ordered drop-in removal. It found and corrected two repository defects: the service probe's split property argument (`0dea720`) and the removal round refused after its first server (`825b09b`). See the [three-VM record](secrets-encryption.md#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed).

Passing the static tests is not Stage 3 completion, and neither are the rehearsals: the live rollout is not approved and not performed, and Stage 3 is not complete or applied to the real cluster. See [secrets-encryption.md](secrets-encryption.md#rollback).

The recovery-tools role has not been run against a node. Downloading, checksum verification against the real archive, installation, the server's `age --version` result and idempotence on a real node remain to be shown by a separately approved live run. See [recovery-tools.md](recovery-tools.md).

### Packer

The Packer configuration was processed with `packer fmt` and passed `packer fmt -check`.

A validation run using placeholder workstation paths progressed through HCL/configuration parsing and produced expected environmental errors for deliberately nonexistent example inputs.

This repository therefore does not claim that the sanitized public example values themselves constitute a complete Packer build environment.

## Public Repository Sanitization

The public portfolio tree was rebuilt separately from the original repository history.

Validation of the clean tree included checks for:

- Private lab addressing

- Private DNS names

- Personal filesystem paths

- Personal email references

- SSH private-key material

- Password hashes from the original environment

- GitHub token patterns

- Other obvious credential material

The tracked public configuration uses documentation/example values instead.

Runtime-sensitive values such as the K3s cluster token are obtained during deployment rather than committed to source control.

Generated inventories and workstation-specific configuration are excluded through `.gitignore`.

## Current Validation Boundary

The following foundation has direct implementation and validation evidence:

```text

Packer Ubuntu VM foundation

            |

            v

PowerShell VM automation

            |

            v

Node bootstrap

            |

            v

Generated Ansible inventory

            |

            v

Three-node K3s control plane

            |

            v

Embedded etcd

            |

            v

kube-vip API endpoint

            |

            v

Single-node failover/recovery test

            |

            v

Flux GitOps reconciliation

```

## Planned Validation

As additional platform layers are introduced, validation can expand to include:

- MetalLB address allocation and failover behavior

- Ingress routing

- Persistent-storage behavior

- Workload recovery with persistent data

- Observability and alerting

- Application-level availability measurements

- Reboot and maintenance scenarios

- Additional control-plane failure scenarios

- Backup and restore

- etcd recovery procedures

- Full rebuild testing from a clean environment

The intent is to keep validation evidence alongside the platform as it evolves.

## Validation Philosophy

A configured feature is not automatically considered a validated capability.

For this project, the preferred progression is:

```text

Design

  |

  v

Automate

  |

  v

Deploy

  |

  v

Observe

  |

  v

Test failure

  |

  v

Document evidence

  |

  v

Iterate

```

This keeps the project focused on observable engineering behavior rather than a checklist of installed technologies.
