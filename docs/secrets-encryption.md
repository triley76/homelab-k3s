# Secrets Encryption at Rest (Phase 7, Stage 3)

## Status

Kubernetes Secrets encryption at rest is **active on the live cluster**. The automation was implemented, statically tested, rehearsed on a disposable k3d cluster and on three disposable VMs under systemd, and then run on the live servers:

- **The live rollout ran from 2026-10-28 to 2026-10-29 and reached every completion condition** (see the [live rollout record](#live-rollout-record-2026-10-28-to-2026-10-29-complete)). All three servers report `Enabled`, `reencrypt_finished` and matching hashes. The p2 snapshot is recorded, and the off-node encryption-configuration recovery copy passed all four checks.
- **Two live findings changed this repository.** The post-restart counter check was corrected in `6cfa7fd` (merged in `7fd364f`), and the window after `rotate-keys` in which unrestarted servers cannot decode Secrets is now part of the [procedure](#live-rollout).
- **The required disposable k3d rehearsal passed on 2026-10-26** (see the [run-8 record](#k3d-rehearsal-record-2026-10-26-run-8-passed)). Every forward phase and the explicit p0 restore passed every [acceptance criterion](#k3d-required-before-merge). Earlier attempts stopped at step 1 (2026-10-23), after `k3s01`'s restart (2026-10-24), at the in-place rollback that K3s rejects for secretbox (2026-10-25 and 2026-10-26), and at a reset delivered through configuration-file fields (2026-10-26).
- **The three-VM rehearsal passed on 2026-10-27** at commit `825b09b` (see the [three-VM record](#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed)). It covered both cycles, the p2 and p0 restores and the ordered drop-in removal under systemd, after two repository defects found during it were corrected.
- **The behavioral references are the [live rollout record](#live-rollout-record-2026-10-28-to-2026-10-29-complete) and the [three-VM record](#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed).** Where they differ, the live record wins. The k3d records remain historical evidence; in particular, k3d's readable status on every server after S1 alone is **not** a live expectation (under systemd, each server's status changed only with its own restart).
- A passing static test run is not completion. Neither are the rehearsals: completion was established on the live servers.
- **Still open:**
  - the template flip for fresh builds ([Fresh Builds and Replacement Joins](#fresh-builds-and-replacement-joins));
  - the cleanup of the Stage 3 state directories;
  - any restore rehearsal from the off-node recovery material. None was performed;
  - Stage 4's scheduled K3s snapshot uploads. The [interim manual p2 copy](#key-material-and-the-off-node-recovery-copy) of 2026-10-30 is not Stage 4.
- [`site.yml`](../ansible/site.yml) does not run any of it.

Statements about K3s behavior below are the documented or source-code behavior of K3s `v1.36.4+k3s1`, except where they are marked as observed in a rehearsal or in the live record. Behavior under systemd is as observed in the [three-VM record](#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed) and on the live servers.

Stage 3 is the prerequisite stage of the backup and disaster-recovery design in the companion `home-cluster` repository: no etcd snapshot may leave the cluster until Secrets are encrypted at rest. That design also fixes the rehearsal requirement, the single key rotation and the recovery-material question answered below.

## Sources

Primary sources only. Each phase encodes the procedure exactly as written there; a deviation is a stop condition, not an improvisation.

| Topic | Source |
| --- | --- |
| Existing-cluster enable procedure (HA): `enable` on S1, restart all servers with `--secrets-encryption`, `rotate-keys` on S1, restart all servers. Key rotation (HA): restart S1 first, then S2 and S3. Disable/re-enable (HA). | [K3s `secrets-encrypt` CLI](https://docs.k3s.io/cli/secrets-encrypt) |
| `--secrets-encryption`, `--secrets-encryption-provider` (`aescbc` default, `secretbox`), configuration path | [K3s Secrets Encryption](https://docs.k3s.io/security/secrets-encryption) |
| `config.yaml.d` drop-ins; critical flags must match on every server | [K3s Configuration Options](https://docs.k3s.io/installation/configuration) |
| etcdctl client certificates | [K3s Advanced Options: Using etcdctl](https://docs.k3s.io/advanced) |
| Existing objects are encrypted only when rewritten; stored prefix `k8s:enc:<provider>:v1:<key name>:`; `aescbc` rated weak; key loss means data loss | [Kubernetes: Encrypting Confidential Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) |
| Feature: "Allow k3s secrets-encrypt enable on existing clusters" (#13403, a backport of #13370) | [k3s PR #13403](https://github.com/k3s-io/k3s/pull/13403) |
| Status output, stage names, `rotate-keys` behavior, critical arguments, `compareConfig` | K3s `release-1.36` source: `pkg/cli/secretsencrypt`, `pkg/server/handlers/secrets-encrypt.go`, `pkg/secretsencrypt/config.go`, `pkg/daemons/config/types.go`, `pkg/cluster/bootstrap.go` |
| Embedded etcd version (v3.6.14, used for the etcdctl pin) | `go.mod` at tag `v1.36.4+k3s1` |

The K3s documentation lists the existing-cluster procedure as available from the March 2026 releases (v1.33.10, v1.34.6, v1.35.3). It does not list v1.36. The feature reached `master` before the v1.36 releases, so `v1.36.4+k3s1` is expected to include it. **This is an inference until the rehearsal confirms it.**

## Five Distinct Operations

These operations are separate in K3s, in this automation and in every claim made about them.

| Operation | What does it | Restarts | Effect on stored data |
| --- | --- | --- | --- |
| **1. Configuration enablement** | `k3s secrets-encrypt enable` on S1 (on a cluster without encryption configuration), then the `secrets-encryption: true` drop-in on every server | Every server, S1 first | K3s writes an **identity-only** configuration. Nothing is encrypted, and no Secret is rewritten. Status is unavailable until the first restart round has completed (observed); afterwards it is expected to be `Disabled`, stage `start`. |
| **2. Activation for new writes** | `k3s secrets-encrypt rotate-keys` on S1 | Every server afterwards, S1 first | Generates a secretbox key and puts it first. From then on, every Secret written is stored encrypted. |
| **3. Rewriting existing Secrets** | Part of the same `rotate-keys` call: K3s re-encrypts every Secret, about 5 per second, before reporting `reencrypt_finished` | — | Every existing Secret is written again, so its **current** etcd record becomes encrypted. Resource versions change and watches fire. |
| **4. Key rotation** | A later `rotate-keys` | Every server afterwards, S1 first | New key; every Secret rewritten; the retired key removed. **The approved procedure performs no rotation beyond step 2** (see [Exactly One Rotation](#exactly-one-rotation)). |
| **5. Rollback after activation** | **Not available in place.** With secretbox, K3s `v1.36.4+k3s1` cannot convert encrypted Secrets back to plaintext. The only rollback is a controlled cluster restore of the pre-enable snapshot (see [Rollback](#rollback)). | Every server is stopped, restored and restarted | The cluster returns to the state of checkpoint p0. Every write after p0 is lost. |

Merely turning on the server flag does **not** rewrite existing Secrets, and in this procedure it does not even activate encryption; steps 2 and 3 do.

## What Stays Plaintext

Encryption at rest protects Secrets written to etcd after activation, and the current records of the Secrets rewritten in step 3. It does **not** reach copies that already exist. After Stage 3, these still contain plaintext Secrets:

- **Etcd snapshots taken before step 2.** This includes every scheduled and on-demand snapshot on the servers, the Stage 3 checkpoint snapshots taken before rotation, and the Stage 2 snapshots.
- **The Stage 2 recovery artifacts:**
  - the preserved pre-restore peer database directories;
  - the encrypted off-node copies of pre-restoration and post-recovery snapshots. Their `age` encryption protects the files, but the Secrets inside them are plaintext once decrypted.
- **Historical etcd data in the live database.** etcd keeps earlier revisions of a key until compaction, and freed database pages can retain old bytes until they are reused or the database is defragmented. A rewrite creates a new encrypted revision; it does not scrub the earlier plaintext revisions or pages.

This automation **deletes none of these**, and nothing here claims they are gone. In particular, the canary checks below examine only the **current** record of one canary key. They say nothing about historical revisions or free pages. Whether, when and how older plaintext copies are retired is a separate decision with its own approval; until then they remain as protected as they are today.

Stage 4 must upload only snapshots taken **after** step 3 has completed and the servers have restarted.

## Exactly One Rotation

The backup design calls for one key rotation, so that the key in use did not coexist with plaintext data. In the K3s v1.36 existing-cluster procedure, the `rotate-keys` call that activates encryption is that rotation: it creates the first real key at the moment all existing Secrets are rewritten. No second rotation is part of the procedure.

[`secrets-encryption-rotate.yml`](../ansible/secrets-encryption-rotate.yml) therefore:

- runs the enabling rotation only after `enable` and the restarts, when every server reports `Disabled` at stage `start` with matching hashes;
- refuses any further rotation unless `secrets_encryption_additional_rotation_reason` records why it is needed (at least ten characters). An additional rotation is added to the procedure only if the K3s documentation or the rehearsal shows a concrete need, and that need is documented here;
- requires, for every rotation, a new confirmation naming the current UTC time (`secrets_encryption_confirm=rotate-keys:k3s01:YYYYMMDDTHHMMSSZ`, at most 30 minutes old). Each confirmation is recorded in a ledger on the first server before the rotation starts and is never accepted again.

## Encoded Procedure

`S1` is the first server, `k3s01`. Every step is a separate invocation, with an exact one-host `--limit` and its own confirmation.

| Step | K3s procedure | Playbook | Expected status afterwards |
| --- | --- | --- | --- |
| 0 | Canary controls, then the recovery point p0 immediately before step 1 | `secrets-encryption-canary.yml` (`create-control`), then `snapshot-etcd.yml --limit k3s01` with checkpoint `p0-pre-enable` | Unchanged |
| 1 | Verify encryption is disabled; `k3s secrets-encrypt enable` on S1 | `secrets-encryption-enable.yml --limit k3s01` | Not readable: status fails on every server until step 2 completes (observed). The only accepted result of step 1 is exit status 0 with exactly `secrets-encryption enabled`. |
| 2 | Restart all servers with `--secrets-encryption` | `secrets-encryption-restart.yml`, once per server: `k3s01`, `k3s02`, `k3s03` | All: `Disabled`, `start`, all hashes match. Required, in the run that restarts `k3s03`, before that server's restart is recorded as verified; until then neither checkpoint p1 nor rotation can run. |
| 3 | `k3s secrets-encrypt rotate-keys` on S1 | `secrets-encryption-rotate.yml --limit k3s01` | S1: `Enabled`, `reencrypt_finished`, active key `XSalsa20-POLY1305` |
| 4 | Restart all servers with the same arguments | `secrets-encryption-restart.yml`, once per server: `k3s01`, `k3s02`, `k3s03` | All: `Enabled`, `reencrypt_finished`, all hashes match |

There is no in-place rollback step after step 3; see [Rollback](#rollback). The automation contains no `disable`, `reencrypt`, `prepare` or `rotate` (legacy) phase. Its only rollback action is drop-in removal **before activation** (`-e secrets_encryption_flag_state=absent` on the restart playbook):

- **When:** only while the last change is `enable` and every server reports `Disabled`, that is after step 2 and before step 3. Status is unreadable between step 1 and the end of step 2, and during the enable restart round the exclusive gate refuses drop-in removal.
- **The removal round.** A server whose drop-in was removed reports `Disabled, no configuration file found`. That state is never settled in general. The three-VM rehearsal of 2026-10-27 found the round stuck after `k3s01` for that reason. It is accepted only in a removal run (`flag_state=absent`) for the next server of a consistent removal round, computed from recorded state (`secrets_encryption_removal_round` in `summarize.yml`):
  - the last change is `enable`, and the enable restart round is complete and consistent;
  - every earlier server, in the fixed order, has no drop-in, a drop-in change after the `enable` marker, a restart after that change and a recorded post-restart gate, and reports `Disabled, no configuration file found`. Each removal began after the previous server's recorded gate;
  - the target and every later server still carry the drop-in, last changed and verified before the first removal, and report `Disabled`, stage `start` and matching hashes.

  Any other mixed state admits no restart. That includes a missing or out-of-sequence record, a later server without its drop-in, a target already without configuration, and a removal run on any other server. The tolerance never applies to `flag_state=present`, to the enable restart round or after `rotate-keys`. A removal interrupted after the target's drop-in change but before its recorded gate leaves the round inconsistent and needs manual investigation.
- **Approval:** it is not part of the K3s procedure. The three-VM rehearsal of 2026-10-27 completed it in order from its recorded prefix, and `flag-removal` is listed in `secrets_encryption_rehearsal_approved_paths`, its only entry, so the guard admits it live. Every other gate applies unchanged: the removal round's order and recorded-prefix rules, health, snapshot freshness, a single-use confirmation, the exact live inventory and `secrets_encryption_environment=live`. An extra-vars override of the approved list is refused, like every other committed value.

**Restart order.** The documentation's HA tabs say "restart all servers" for steps 2 and 4 without an order, and "S1 first, then S2 and S3" for key rotation and disable. The automation uses one fixed order for every restart round, `k3s01`, `k3s02`, `k3s03`, which is the inventory order the live guard requires. Each server is refused until every server before it has restarted after the last change and passed its post-restart gate.

### Between enable and the first restart round

The k3d rehearsal showed that `k3s secrets-encrypt status` fails on every server after `enable` and before any restart (see [k3d rehearsal record](#k3d-rehearsal-record-2026-10-23)). Status is therefore no postcondition of step 1. Every gate still fails closed on an unparsed status, with one narrowly defined exception, the **enable restart round**:

- **Step 1 accepts one result only.** `enable` must exit 0 and print exactly `secrets-encryption enabled` (one line on standard output). The `enable` marker in `last-change` is written only after that check passes. Any other result stops without recording a change. Step 1 never reads status afterwards.
- **What the round is.** The first restart round after the `enable` marker, until all three servers have reached the checkpoint. Only `secrets-encryption-restart.yml` with the drop-in requested (`flag_state=present`) can use it, and only while all of the following hold:
  - the marker is `enable`, and the confirmation ledger on the first server records an `enable` for the first server, preceded by a `snapshot` for the first server, and no `rotate-keys`, `disable` or `reencrypt-after-disable`, which would make the marker stale;
  - a recorded p0 snapshot (see [The pre-enable checkpoint](#the-pre-enable-checkpoint-p0)) older than the `enable` marker exists on the first server, in addition to the usual freshness and preservation gates;
  - the servers that reached the checkpoint are exactly a prefix of the order `k3s01`, `k3s02`, `k3s03`, and no later server shows a restart, a drop-in, a drop-in change or a verified restart since `enable`;
  - the target is the next server in that order. A server that already passed is refused (no replayed restart), and so is any server after the next one (no skipped or out-of-order restart).
- **What it tolerates.** Only a status result that failed, printed nothing on standard output and reported exactly the observed server error (`Internal error occurred: secret-encrypt error ID <n>`). That result is recorded as `unavailable`. It is never parsed, and it is never treated as evidence of health or of the encryption state. Every other part of the gate is unchanged: service, version, local `/readyz` and `/readyz/etcd`, node readiness and pressure, etcd members, workloads, Chrony, swap, free space, state-directory safety, preservation and snapshot freshness. A status that does parse must still be settled, and may not report `Enabled`.
- **The round is exclusive.** Status availability is independent of the round's progress. In the k3d rehearsal of 2026-10-24 (see [the 2026-10-24 record](#k3d-rehearsal-record-2026-10-24)), status became readable on every server after `k3s01` alone had restarted, and reported `Disabled`, stage `start` and matching hashes while `k3s02` and `k3s03` still ran without the drop-in. Phase transitions are therefore gated by the **durable round state**, never by status readability. While the marker is `enable` and the round is incomplete, the gate refuses every phase except `secrets-encryption-restart.yml` with the drop-in requested, which then admits only the next server in the order. That includes:
  - snapshots and checkpoints after p0;
  - canary create, verify and cleanup;
  - enforced validation (`validate-secrets-encryption.yml -e secrets_encryption_enforce=true`, which reports `enable_round_blocking: true`);
  - rotation;
  - drop-in removal (`flag_state=absent`);
  - a repeated `enable`;
  - the rehearsal-only etcdctl installation.

  A readable status during the round is parsed and checked like any other: it must be settled and may not report `Enabled`. It does not count towards completion.
- **How it ends.** In the run that restarts `k3s03`, after its post-restart gate, status must be readable on every server and parse as `Disabled`, stage `start`, with matching hashes. It is polled for up to `secrets_encryption_ready_retries` × `secrets_encryption_ready_delay_seconds`. Only then is `k3s03` recorded as verified. The round is complete when all three servers have a durable `restart-verified` record after the `enable` marker, in order. If the convergence check fails, the round stays incomplete: `k3s03` can be re-run, and every other phase stays refused.
- **After completion.** Checkpoint p1, rotation and the other phases become eligible under their normal prerequisites. While the marker is still `enable`, they also require the round's ledger, pre-enable checkpoint and order evidence to be consistent. Interrupted or inconsistent evidence fails closed, for example a ledger that records `rotate-keys` while the marker still says `enable` because a rotation stopped before recording its change. Such a state needs manual investigation; the automation offers no way forward from it.
- **The p0 latch.** `enable` requires p0 to be at most 120 minutes old, and the round refuses every new snapshot, so a round that outlasted that limit would refuse its own next restart with no way forward. Once `enable` is accepted, the round latches that p0. The restart of the next server in a consistent round, with the drop-in requested, passes the freshness check with the latched p0 even when it is older than the limit, provided that p0:
  - is still the newest Stage 3 snapshot on the first server;
  - is recorded exactly once as p0, by name and size, in well-formed checkpoint records;
  - predates the `enable` marker.

  Preservation, health and every other condition apply unchanged. The latch never applies to `enable`, rotation, snapshots, canary or validation phases, drop-in removal, a skipped or replayed server, an inconsistent round, or a completed round; those keep the 120-minute limit.
- **No option.** The exception is computed from recorded state. There is no variable that turns it on, and the guard refuses any attempt to inject the round, the parsed status or the gathered server state as extra variables.

## Implementation

### Files

| Path | Purpose |
| --- | --- |
| [`roles/secrets-encryption/`](../ansible/roles/secrets-encryption) | The phases as separate task files; no default entry point |
| [`snapshot-etcd.yml`](../ansible/snapshot-etcd.yml) | On-demand checkpoint snapshot on the first server |
| [`secrets-encryption-enable.yml`](../ansible/secrets-encryption-enable.yml) | Step 1 |
| [`secrets-encryption-restart.yml`](../ansible/secrets-encryption-restart.yml) | Steps 2 and 4, one server per run; drop-in removal before activation |
| [`secrets-encryption-rotate.yml`](../ansible/secrets-encryption-rotate.yml) | Step 3 |
| [`secrets-encryption-canary.yml`](../ansible/secrets-encryption-canary.yml) | Canary controls, verification and cleanup |
| [`validate-secrets-encryption.yml`](../ansible/validate-secrets-encryption.yml) | Read-only report, with optional enforcement |
| [`install-etcdctl-rehearsal.yml`](../ansible/install-etcdctl-rehearsal.yml) | Pinned etcdctl and the verifier, **rehearsal environments only** |
| [`tests/secrets_encryption_expressions.py`](../ansible/tests/secrets_encryption_expressions.py) | Static, expression and safety tests |

### Server configuration

The drop-in `/etc/rancher/k3s/config.yaml.d/20-secrets-encryption.yaml` (root, `0600`) carries exactly two keys:

```yaml
secrets-encryption: true
secrets-encryption-provider: secretbox
```

K3s reads `config.yaml.d/*.yaml` after `config.yaml`. Both keys are **critical arguments** (`CriticalControlArgs` in K3s), which must match on every server:

- **Restarts:** the K3s source compares them only when a server joins or rejoins (its etcd database is not yet initialized), not when an existing member restarts. That is why a rolling restart can add the flag one server at a time.
- **Rejoins mid-procedure:** a server that has to *rejoin* while the flags differ, for example after its database was moved aside as in the Stage 2 incident, is refused with "critical configuration value mismatch". Its flags must match those of the server it joins through (`k3s01`).

The provider is `secretbox` (decision D1): Kubernetes rates `aescbc` as weak because of padding-oracle attacks.

### Every mutating invocation

Each mutating playbook is one play on `servers` with `serial: 1`, `any_errors_fatal: true`, `max_fail_percentage: 0` and **no automatic fact gathering**. It runs, in this order:

1. **Guard**, imported as the first pre-task with privilege escalation off. Every check runs on the controller, so a refused invocation stops before facts, privilege escalation, downloads or any other task. It refuses unless all of the following hold:
   - **Phase:** the phase is bound to the running play. `secrets_encryption_play_phases` (committed in the role's `vars`) maps each guarded play's exact name to its own phase, and the guard compares it with `ansible_play_name`, a magic variable that extra vars and inventory cannot override. An unmapped play, a canary action without a committed phase, or a phase supplied on the command line, such as `-e secrets_encryption_phase=restart`, is refused before anything else is checked.
   - **Limit:** `--limit` is exactly one inventory host name: no pattern, group, list, regex or exclusion, even one that resolves to a single host. Phases on the first server require that host to be `groups['servers'][0]`.
   - **Confirmation:** `secrets_encryption_confirm` is `<phase>:<target host>:<UTC time YYYYMMDDTHHMMSSZ>`, at most 30 minutes old and not in the future. A value for another phase or another host is refused. The phases are `snapshot`, `enable`, `restart`, `rotate-keys`, `canary-create-control`, `canary-verify`, `canary-cleanup` and `install-etcdctl`. There is no `disable` or rollback re-encryption phase; any other phase name is refused.
   - **Environment:** `secrets_encryption_environment` is declared. `live` is accepted only with the exact inventory `k3s01`, `k3s02`, `k3s03`, in that order. `rehearsal` is accepted only with three servers and no live host name anywhere in the inventory.
   - **Rehearsal-only work:** etcdctl installation and raw etcd verification are refused for any inventory or target containing `k3s01`, `k3s02` or `k3s03`, whatever environment is declared.
   - **Committed values:** every role var (pins, paths, live host list, approvals) equals the committed `vars/main.yml`; extra vars cannot override them. In a live environment, the gate defaults (Flux, HelmRelease, monitoring, canary, Chrony, freshness and free-space settings, raw verification off) must also equal the committed `defaults/main.yml`.
   - **Protected artifacts:** in a live environment, `secrets_encryption_protected_paths` names the preserved Stage 2 artifacts as absolute paths on known servers. Set it in local, uncommitted inventory.
   - **Rehearsal approval:** paths not yet rehearsal-approved are refused live (see [Encoded Procedure](#encoded-procedure)).
   - **Gathered state:** none of the facts that the gate builds from the servers (`secrets_encryption_gathered_facts` in the role's vars, including the enable restart round and the parsed status) may already be defined. Extra vars outrank facts, so an injected value would otherwise replace what the gate reads.
2. **Facts:** minimal fact gathering, only after the guard.
3. **Gate.** Read-only until every check has passed:
   - **Each server, through its own local API:** `k3s.service` is active at exactly `v1.36.4+k3s1`; local `/readyz` and `/readyz/etcd` are `ok`; `secrets-encrypt status` parses and is in a settled stage (`start` or `reencrypt_finished`), never during re-encryption or in a legacy stage; Chrony is synchronized with an offset below 100 ms; swap is unchanged since the baseline; free space is sufficient; the state directory and its files are root-owned regular paths, not symbolic links.
   - **Cluster:** exactly the three servers are nodes, each once, Ready and without memory, disk or PID pressure, and exactly those three carry the etcd role. The six Flux Kustomizations are present once and Ready, and every Kustomization present is Ready. At least two HelmReleases exist, all Ready. Every Deployment, StatefulSet and DaemonSet is fully ready; the monitoring namespaces hold their StatefulSets and DaemonSets; `platform-demo/platform-canary` is fully available.
   - **Fail closed:** empty, missing, null, duplicated or unparsable results are failures.
   - **Preservation:** every protected Stage 2 artifact exists and is unchanged, and no recorded on-demand snapshot or database directory has disappeared (see [Snapshots and preservation](#snapshots-and-preservation)).
   - **Snapshot:** a Stage 3 snapshot on the first server is at most 120 minutes old. Only the next restart of an active enable restart round may instead rely on [the p0 latch](#between-enable-and-the-first-restart-round). For rotate, it must also be newer than the last recorded change. `enable` additionally requires the newest one to be the recorded pre-enable checkpoint p0, taken by the last accepted invocation. The enabling rotation requires that recorded p0, the only rollback after activation, with a consistent ledger (see [The pre-enable checkpoint](#the-pre-enable-checkpoint-p0)).
   - **Replay:** the confirmation was never used before.

   Then the gate writes, and nothing else:
   - the root-only state directory (`0700`), checked again after creation;
   - the preservation baseline;
   - the confirmation, recorded as used in the ledger on the first server.
4. **The phase.**

Reports contain metadata only: no addresses, peer IDs, encryption hashes, Secret names other than the fixed canary names, or protected-artifact paths (only their counts).

### Confirmation ledger

Every accepted confirmation is appended to `/var/lib/homelab-secrets-encryption/confirmations` on the first server before the phase acts, whatever its outcome. A value already in the ledger is refused for every phase and host, so repeating a command, including a completed `rotate-keys`, never acts again.

The ledger and every other state file are refused if they are a symbolic link or not root-owned, and the directory must be root-owned `0700`. State files are written with `follow: false`, replacing rather than following a link. The ledger is appended with `lineinfile`, which would follow a link, only after those checks, inside a directory only root can write to.

### Restart order and checkpoints

The role records each procedure change (`enable`, `rotate-keys`) with its time in `last-change` on the first server. Any other recorded phase, such as a legacy `disable`, is a malformed marker and fails the gate. It records each drop-in change on the server concerned, in `dropin-change`. After each restart's post-restart gate passes, the server records `restart-verified`.

A server reaches the checkpoint of the last change when both hold:

- `k3s.service` became active after the later of the last procedure change and its own last drop-in change;
- `restart-verified` was recorded after that.

[`secrets-encryption-restart.yml`](../ansible/secrets-encryption-restart.yml):

- refuses while any server is re-encrypting or in an unsettled stage;
- enforces the fixed order `k3s01`, `k3s02`, `k3s03`. A server is refused until every server before it has reached the checkpoint with the requested drop-in state;
- restarts nothing if the target already runs with the current configuration (a no-op that only repeats the post-restart gate and its record). In the [enable restart round](#between-enable-and-the-first-restart-round) only the next server in the order is accepted, so a server that has already passed is refused instead;
- in the enable restart round, requires every server to report `Disabled`, `start` and matching hashes in the `k3s03` run before recording it as verified;
- contains the role's only K3s restart, an explicit `systemd_service` task. No handler restarts K3s.

After the restart it waits for:

- the service;
- the local API and etcd readiness;
- the node to be Ready.

It then re-runs the full gate and checks each server's `NRestarts`. This is systemd's count of automatic (`Restart=`) restarts, and systemd resets it when the service is restarted explicitly. After a restart by this run, the target's counter must be exactly 0: any higher value is an automatic restart since the controlled one. Every other server's counter, and the target's when the run restarts nothing, must be unchanged. Only then does it record `restart-verified`.

### Status parsing without exposure

`k3s secrets-encrypt status` output is read with `no_log` and reduced to allowlisted fields:

- `encryption`
- `stage`
- `hashes_match` (a boolean)
- `key_count`
- `active_key_type`
- `active_key_name`

Every line must be recognized, and every field must appear exactly once where required, or the result is "not parsed" and every gate fails closed. One unparsed result is also marked `unavailable` (a boolean): the observed failure between `enable` and the end of the first restart round. Only the [enable restart round](#between-enable-and-the-first-restart-round) tolerates it. The hash line names nodes when hashes differ; only the boolean is kept. No encryption hash, raw status, node annotation (which carries the encryption hash), Secret, token or encryption configuration is read into or printed by Ansible.

### Snapshots and preservation

[`snapshot-etcd.yml`](../ansible/snapshot-etcd.yml) runs `k3s etcd-snapshot save --name stage3-<checkpoint>-<UTC time>` on the first server.

**Retention.** In K3s v1.36 (`pkg/etcd/snapshot.go`), a successful save is followed by local retention pruning. It removes the oldest of the files whose names *start with* the snapshot name, beyond `--etcd-snapshot-retention`. The automation refuses a name that any existing file already starts with. That pruning can therefore only ever see the new file.

Whether a CLI save prunes with the CLI's `--name` or with the server's configured snapshot name is a [rehearsal question](#rehearsal-questions). Preservation is therefore checked, not assumed:

- **Before and after the save:** the size and time of every non-scheduled snapshot file are compared. Any missing or changed file stops the run. Changes among scheduled snapshots (`etcd-snapshot-*`), which K3s prunes by its own retention, are reported separately as scheduled retention and are not Stage 3 deletions.
- **After the save:** the full preservation gate runs again, including the protected Stage 2 artifacts.
- **Record:** the name, size, time and SHA-256 of the new snapshot file are reported, and appended with the checkpoint label to the `checkpoints` file in the state directory on the first server (decision D4). The file is never read into Ansible.
- **Token:** before the save, the server token file is checked by `lstat` alone (present, non-empty, root-owned, regular, not a link). Its content is never read, and the record holds only `token=present`.

**Preservation on every mutating run:**

- **Protected Stage 2 artifacts** (`secrets_encryption_protected_paths`, mandatory live) must exist, must not be symbolic links, and must keep their type. Files must also keep their size and modification time from the first baseline. They are inspected by `stat` alone: no content is read and no checksum is computed. Reports refer to them by number only.
- **Recorded entries:** every on-demand snapshot name and database directory name recorded in the baseline must still exist. Scheduled snapshots are excluded.
- **The baseline** lives in the state directory, only grows, and also records each server's swap size for the swap-invariance check.

The automation contains no snapshot deletion, prune, restore, cluster reset, rejoin, database removal or move.

## Canary Verification

No existing Secret is read. The canary values are random bytes generated on the first server into a root-only tmpfs directory (`/run/homelab-secrets-encryption-canary`). They are never printed, passed on a command line or returned to Ansible. All canary objects use fixed names in the `default` namespace.

| Action | When | What it does |
| --- | --- | --- |
| `create-control` | Before `rotate-keys` | Creates the positive controls: the disposable Secret `stage3-canary-pre-encryption`, written while encryption is not active, and the ConfigMap `stage3-canary-plaintext-control`, which is never encrypted. Compares the Secret's readback. Removes everything if it fails. |
| `verify` | After `rotate-keys` and all restarts | Creates `stage3-canary-post-encryption`. Compares the readback of both Secrets. In a rehearsal, also runs the raw checks below. **Always** removes every canary afterwards. |
| `cleanup` | Any time | Deletes the three fixed names (ignoring missing ones) and removes the value directory. Safe to repeat. |

**Readback comparison:** the decoded API readback is piped into `cmp -s` against the local value file. Only the exit status is recorded.

**Raw verification (rehearsal only, decision D2).** A pinned, checksum-verified `etcdctl` v3.6.14 queries the **current** record of exactly one canary key:

- **Which key:** one of the three fixed canary keys, checked before the query. Nothing else is accepted.
- **How it is queried:** `etcdctl get --write-out=json -- <key>`:
  - one exact key, with no `--prefix`, `--from-key` or range end;
  - only the local member, `--endpoints=https://127.0.0.1:2379`, with the K3s-documented client certificates under `/var/lib/rancher/k3s/server/tls/etcd`;
  - bounded by `--dial-timeout=5s`, `--command-timeout=15s` and an overall `timeout 30`.
- **Where the output goes:** directly into [`etcd_value_verify.py`](../ansible/roles/secrets-encryption/files/etcd_value_verify.py), with `pipefail` and `no_log`. The record is never stored in a fact, a file, a log or debug output. The verifier prints one token and nothing else.
- **What passes:** the response must hold exactly one record (count 1, one key-value, no more pending), with exactly the requested key. Then:
  - in `encrypted` mode, only `k8s:enc:secretbox:v1:<key name>:` followed by at least a secretbox nonce, tag and one byte;
  - in `plaintext` mode, only an unencrypted Kubernetes protobuf record (`k8s\0`).
- **Fail closed:** each failure has its own token.
  - non-JSON output: `FAIL-JSON`;
  - a missing key: `FAIL-MISSING`;
  - several records: `FAIL-MULTIPLE`;
  - another key: `FAIL-KEY`;
  - empty, oversize or malformed values: `FAIL-EMPTY`, `FAIL-OVERSIZE`, `FAIL-MALFORMED`;
  - the wrong prefix or provider: `FAIL-PREFIX`, `FAIL-ENCRYPTED`;
  - an etcdctl failure is a failure even if output looked valid; a token outside the allowlist is reported as `FAIL-UNEXPECTED`.

The rehearsal-only installer [`install-etcdctl-rehearsal.yml`](../ansible/install-etcdctl-rehearsal.yml) uses Ansible modules only. In order, it:

1. creates a private, root-only working directory;
2. downloads the pinned archive there, with the SHA-256 verified by `get_url`;
3. extracts only the `etcdctl` member;
4. requires the extracted path to be a regular file and not a symbolic link;
5. runs its `version` from the working directory and requires exactly `etcdctl version: 3.6.14`.

Only then does it change the destination. It removes the working directory on success and on failure. The URL, version and SHA-256 are committed role vars that the guard refuses to have overridden.

| Check | Mode | Shows |
| --- | --- | --- |
| Control ConfigMap, before and after | `plaintext` | The query reads the real current record of an object stored in clear |
| Pre-encryption Secret, before rotation | `plaintext` | A Secret written before activation is stored in clear, so the encrypted check below is not vacuous |
| Post-encryption Secret | `encrypted` | New writes are stored with the secretbox prefix |
| Pre-encryption Secret, after rotation | `encrypted` | An existing Secret's current record was rewritten encrypted |

Raw verification **does not** examine historical revisions, free pages, snapshots or other keys, and absence of plaintext elsewhere is not claimed. In a live environment the guard refuses raw verification. Live verification is the readback comparison plus K3s's own `reencrypt_finished` status, and the record must say so.

**If cleanup is interrupted:**

- Rerun `-e secrets_encryption_canary_action=cleanup`; `verify` also replaces a leftover post-encryption canary.
- The leftover objects hold only random throwaway values. The value directory is on tmpfs and disappears at reboot.
- After a reboot, the pre-encryption canary can no longer be compared, so `create-control` refuses it until cleanup has run.
- Deleted canary values remain in etcd history and in later snapshots until compaction and overwrite. That is harmless, because they are random.

## Live Rollout

Performed on 2026-10-28 and 2026-10-29; see the [live rollout record](#live-rollout-record-2026-10-28-to-2026-10-29-complete). This section is the procedure, corrected with what the live run found. Prerequisites for any repeat:

1. Both rehearsals have passed and are recorded, with their answers to the [rehearsal questions](#rehearsal-questions).
2. This branch is merged.
3. The live run is separately approved.
4. The off-node encryption-key recovery copy can be made and verified: the `home-cluster` recovery helper for the encryption configuration is implemented and reviewed (see [Key material](#key-material-and-the-off-node-recovery-copy)). Until then, step 3 (`rotate-keys`) must not run.

Run from `ansible/`. `secrets_encryption_protected_paths` must be set in local, uncommitted inventory: the absolute paths of the preserved Stage 2 database directories and snapshot files on each server.

Every command needs a new confirmation naming its phase, its host and the current UTC time; `c` below builds one. After every restart in the enable restart round:

- wait at least 10 minutes;
- run `validate-secrets-encryption.yml` and `validate-time-sync.yml -e time_sync_enforce_acceptance=true`;
- keep the LAN canary monitor running throughout.

The second restart round, after `rotate-keys`, is different; see [After rotate-keys](#after-rotate-keys-the-secret-decode-window).

During the enable restart round, `validate-secrets-encryption.yml` reports `enable_round_blocking: true`, and with `secrets_encryption_enforce=true` it fails, until the `k3s03` restart has completed with the converged status. The status it reports during the round may be unavailable (`unavailable: true`) or already readable. Neither means the round is complete.

```bash
E="-e secrets_encryption_environment=live"
c() { echo "secrets_encryption_confirm=$1:$2:$(date -u +%Y%m%dT%H%M%SZ)"; }

# 0. Baseline, canary controls, then p0 immediately before enable. The controls
#    must exist in p0, so that a restore can be checked against them.
ansible-playbook validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=not-configured
ansible-playbook snapshot-etcd.yml --limit k3s01 $E -e "$(c snapshot k3s01)" -e secrets_encryption_snapshot_checkpoint=baseline
ansible-playbook secrets-encryption-canary.yml --limit k3s01 $E -e secrets_encryption_canary_action=create-control \
  -e "$(c canary-create-control k3s01)"
ansible-playbook snapshot-etcd.yml --limit k3s01 $E -e "$(c snapshot k3s01)" -e secrets_encryption_snapshot_checkpoint=p0-pre-enable

# 1. Configuration enablement. Status stays unreadable until k3s03 has restarted;
#    the k3s03 run requires Disabled/start/matching hashes before it completes.
ansible-playbook secrets-encryption-enable.yml --limit k3s01 $E -e "$(c enable k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s01 $E -e "$(c restart k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s02 $E -e "$(c restart k3s02)"
ansible-playbook secrets-encryption-restart.yml --limit k3s03 $E -e "$(c restart k3s03)"
ansible-playbook validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=configured-disabled

# 2-3. Activation and rewrite (the one rotation). From rotate-keys until each server
#      restarts, Secrets cannot be decoded through that server: run the three
#      restarts promptly, without the 10-minute waits (see After rotate-keys).
ansible-playbook snapshot-etcd.yml --limit k3s01 $E -e "$(c snapshot k3s01)" -e secrets_encryption_snapshot_checkpoint=p1-pre-rotate
ansible-playbook secrets-encryption-rotate.yml --limit k3s01 $E -e "$(c rotate-keys k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s01 $E -e "$(c restart k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s02 $E -e "$(c restart k3s02)"
ansible-playbook secrets-encryption-restart.yml --limit k3s03 $E -e "$(c restart k3s03)"

# Verification and the post-change recovery point
ansible-playbook validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=enabled
ansible-playbook secrets-encryption-canary.yml --limit k3s01 $E -e secrets_encryption_canary_action=verify -e "$(c canary-verify k3s01)"
ansible-playbook snapshot-etcd.yml --limit k3s01 $E -e "$(c snapshot k3s01)" -e secrets_encryption_snapshot_checkpoint=p2-post-encryption

# 5. The off-node encryption-key recovery copy: the home-cluster helper (see Key material).
#    The rollout is not complete until the copy is made and verified.
```

Also confirm that existing Secrets still decrypt, without printing any of them:

- `helm list -A` succeeds;
- read-only Flux status: `flux get kustomizations -A` and `flux get helmreleases -A` (or `k3s kubectl get kustomizations.kustomize.toolkit.fluxcd.io,helmreleases.helm.toolkit.fluxcd.io -A`) report every object Ready. Do not run `flux reconcile`: a reconciliation is a change and needs its own approval;
- the Grafana login works.

The restart order is fixed: `k3s01`, `k3s02`, `k3s03`.

### After rotate-keys: the Secret-decode window

*Observed live (2026-10-29), not in either rehearsal:* `rotate-keys` rewrites every Secret with the new secretbox key on `k3s01`, but `k3s02` and `k3s03` keep the previous configuration in memory until they restart. Until then, any Secret read served by an unrestarted server fails with `Internal error occurred: no matching prefix found`. The Flux `GitRepository` then reports `AuthenticationFailed`, because it cannot read its credentials Secret, and stays NotReady. In the live run that lasted from 14:02:35 UTC, 17 seconds after the `rotate-keys` run ended, until `k3s03` decoded Secrets again after its restart at 14:29:50 UTC. Workloads stayed Ready and the LAN canary recorded no failures. Neither rehearsal could show it: the three-VM rehearsal had no Flux, and its readbacks went through S1.

Restarting the remaining servers closes the window, so the second restart round runs promptly:

1. Run `restart` for `k3s01`, `k3s02` and `k3s03` in order, without the 10-minute waits.
2. Each restart still requires:
   - exactly one controlled restart, with the target's `NRestarts` at 0 and every peer counter unchanged;
   - service, local API, local etcd and node readiness, the full etcd mesh, workloads, storage and the LAN canary;
   - that server's own local API now decoding the canary Secret (`k3s kubectl get secret stage3-canary-pre-encryption -n default -o name` on that server, name only).
3. During the round, and only then, two failures are tolerated:
   - the decode failure above, on servers not yet restarted;
   - `GitRepository` NotReady with that same decode failure as its reason.
   Any other failure is a stop condition.
4. After `k3s03`:
   - every local API decodes the canary Secret;
   - the `GitRepository` returns to Ready by itself, with no `flux reconcile`.
   Then observe for at least 10 minutes, with repeated health checks, and run `validate-secrets-encryption.yml` and `validate-time-sync.yml -e time_sync_enforce_acceptance=true`. Only then go on to the enforced `enabled` validation.

### Stop conditions

Stop immediately, and do not run another step, if:

- any playbook fails;
- quorum is lost, or etcd readiness fails on any server;
- a node is not Ready, or a local API is not ready;
- a K3s service fails to start or restarts unexpectedly;
- any server reports `Disabled` after `rotate-keys` (no supported phase creates that state);
- a status is not parsed (other than the `unavailable` result that the [enable restart round](#between-enable-and-the-first-restart-round) tolerates), a stage is unexpected, or hashes do not match where the table above expects them to;
- re-encryption does not finish within its timeout;
- any API error reads a Secret, except the [decode window](#after-rotate-keys-the-secret-decode-window) on servers not yet restarted after `rotate-keys`;
- a Flux Kustomization or HelmRelease is not Ready, or a GitRepository is not Ready for any reason other than that window;
- the LAN canary monitor records failures;
- a canary check fails;
- any result differs from the [live rollout record](#live-rollout-record-2026-10-28-to-2026-10-29-complete) or, where that record is silent, from the [three-VM record](#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed);
- the encryption-key recovery copy cannot be made and verified: the rollout is then not complete (see [Key material](#key-material-and-the-off-node-recovery-copy));
- any unplanned host change happens during the window (the Stage 2 incident followed a host swap-state change).

### Live rollout record (2026-10-28 to 2026-10-29: complete)

Live servers `k3s01`, `k3s02` and `k3s03`: K3s `v1.36.4+k3s1`, embedded etcd, Flux, a MetalLB-exposed platform canary. Every phase ran from committed playbooks with exact single-host limits and a fresh, single-use confirmation, approved step by step by the repository owner. An external LAN monitor fetched the platform canary once per second throughout each window. It saw a single replica throughout, so it shows reachability only, not load distribution.

This record contains no host addresses, MAC addresses, workstation paths, protected paths, key names, version IDs, bucket names or account identifiers. Sanitized evidence is kept outside this repository, identified by directory name and the SHA-256 of its `SHA256SUMS` manifest.

| Window (UTC) | Step | Result |
| --- | --- | --- |
| 2026-10-28 20:30 | Approved host change before the window: swap disabled on `k3s01` at runtime only (`swapoff -a`), because `verify` refuses active swap. It returns after a reboot, so a reboot invalidates the preflight | Swap off; cluster healthy |
| 2026-10-28 21:35–21:39 | Step 0 on `09ce4af`: enforced `not-configured`, baseline, canary controls, p0 `stage3-p0-pre-enable-20261028t213918z-k3s01-1793223582` | Passed |
| 2026-10-28 22:07–22:10 | `enable` on `k3s01` passed. **The `k3s01` restart then failed its own post-restart counter assertion**: `k3s01` restarted healthy, but systemd reset its `NRestarts` from 59 to 0 on the explicit restart, and the check required every counter unchanged. The rehearsal counters had all been 0. Stopped mid-round; nothing retried | Repository defect; corrected in `6cfa7fd` (pull request #7, merged in `7fd364f`) |
| 2026-10-29 01:25–01:58 | Enable round resumed on `7fd364f`. The repeated `k3s01` run restarted nothing and recorded its checkpoint. `k3s02` (141 to 0) and `k3s03` (0 to 0) restarted once each. Enforced `configured-disabled` passed. The owner waived p0's 120-minute age limit for this continuation; p0 remained the newest checkpoint | Passed |
| 2026-10-29 13:45 | Read-only continuity gate: no reboots, no restarts, swap off, controls and p0 intact, `configured-disabled` enforced | Passed |
| 2026-10-29 13:59–14:02 | p1 `stage3-p1-pre-rotate-20261029t135952z-k3s01-1793282417`; `rotate-keys` began 57 seconds after p1. Result: purpose `enabling`, the CLI reported success, `Enabled`, `reencrypt_finished`, one `XSalsa20-POLY1305` (secretbox) key | Passed |
| 2026-10-29 14:02–14:30 | **[Secret-decode window](#after-rotate-keys-the-secret-decode-window)**: unrestarted servers could not decode Secrets, and the Flux `GitRepository` was NotReady. With scoped waivers, the second round ran promptly: `k3s01` 14:21:58, `k3s02` 14:25:26, `k3s03` 14:27:52, each one restart with `NRestarts` 0 and peers unchanged, and its own local API decoding Secrets afterwards. The `GitRepository` was Ready again at 14:30:12 without reconciliation | Passed; procedure corrected |
| 2026-10-29 14:30–14:42 | One post-round observation (717 s, four repeated health, decode and state checks), report validation, enforced time synchronization | Passed |
| 2026-10-29 14:44–14:47 | Enforced `enabled` validation: `Enabled`, `reencrypt_finished`, matching hashes and reached checkpoints on all three servers, with no health or preservation problems. Canary `verify`: `readback_pre` and `readback_post` matched, and its built-in cleanup removed every canary and the value directory. Raw etcd checks were **not run**; they are refused live by design (D2). p2 `stage3-p2-post-encryption-20261029t144551z-k3s01-1793285175`, with baseline, p0, p1 and p2 all intact and recorded | Passed |
| 2026-10-29 15:30–16:50 | Off-node encryption-configuration recovery copy, made with the `home-cluster` helpers at `9f46215`, as described under [Key material](#key-material-and-the-off-node-recovery-copy). Upload, exact-version download `MATCH` and decryption comparison `MATCH` on `k3s01`; inventory updated; Recovery A and B verified | Passed |

**Afterwards:** all three servers have the drop-in and `encryption-config.json` (`600 root:root`). Every restart was planned and every `NRestarts` is 0. Flux, workloads and storage were healthy at every gate.

**LAN canary:** no failures in any window. Requests answered: 7,089 and 2,066 for the two enable-round windows, 2,971 for the activation.

**Deviations, all approved in advance:**
- **The per-node 10-minute waits in the second round** were consolidated into one post-round observation. The procedure above now prescribes this.
- **The Secret-decode and `GitRepository` tolerance** was scoped to unrestarted servers during that round.
- **The p0 age waiver.**
- **The ConfigMap control:** live `verify` does not compare it, so it was checked by a read-only API readback immediately before `verify`.
- **Operator tooling, not repository defects:** the operator's own evidence tooling produced three false stops, and none changed the cluster:
  - an extractor that missed the rotation result;
  - a loop variable reused after `k3s01`'s restart;
  - a health check run from the wrong working directory.

**Evidence (outside this repository):**

| Directory | `SHA256SUMS` SHA-256 |
| --- | --- |
| `k3s01-swapoff-20261028T203053Z` | `b4cc4d14bc0687cd5c40ee81b4bae05c306ffc307e76e5393baedf78555938b3` |
| `stage3-step0-20261028T213518Z` | `d7b93b6d4344e05dc382b2b6d7609b89dfbf18ee1b306c27eeef91fb70fc218a` |
| `stage3-step1-halt-20261028T221038Z` | `36a91fa094a8b28e2c7dd12abf8adbe077eda28b45e6d21d2b0eb28fc40ef159` |
| `stage3-step1-complete-20261029T015733Z` | `2a1e1995ac80ba7ec8f27767ceb4cb4a57d99c3a8c98e6cacf6aeb36d4f406fb` |
| `morning-gate-20261029T134636Z` | `8c8938d68cbf8f13c30a85e6edaf329e487e2bfc4cb2f2538dd30d7022102d8d` |
| `stage3-activation-p2-20261029T144755Z` | `6f7a54c20814228a0640029f9bb9e21f6f2db06c6770f7a8d7c11b44b532dab6` |
| `stage3-encryption-config-recovery-copy-20261029T165000Z` | `c9f0e9c3ee4c967fd7de8b71234ab70d716835cab85c885da61f9a69ce0baffc` |

**What this record does not show:**
- that any snapshot or the recovery material restores the encrypted cluster: no live restore was performed;
- the absence of plaintext from etcd history, free pages or older snapshots;
- raw etcd encryption of any live record.

## Rollback

In-place conversion back to plaintext **is not supported** by the tested combination of K3s `v1.36.4+k3s1` and the pinned secretbox provider. The evidence:

- **Observed.** The k3d R3 diagnostic of 2026-10-26 ran the documented HA disable procedure: `disable` on S1 (exit 0), then a restart of S1, S2 and S3 (all `Disabled`, `reencrypt_finished`, matching hashes). The documented final step `k3s secrets-encrypt reencrypt --force --skip` was then rejected with HTTP 400 and this server log line: `reencrypt does not support secretbox key type, use rotate-keys instead`. See the [R3 record](#k3d-rehearsal-records-2026-10-25-and-2026-10-26).
- **In the source** (`pkg/server/handlers/secrets-encrypt.go` at `v1.36.4+k3s1`): `encryptionReencrypt` returns that error for secretbox, and `prepare` and `rotate` do the same. `rotate-keys` (`encryptionRotateKeys`, then `addAndRotateKeys`) always writes the configuration with encryption enabled and the secretbox provider first, then rewrites every Secret under it. **`rotate-keys` cannot convert** encrypted Secrets to plaintext, and after a `disable` it would turn encryption back on. It is therefore never a rollback.
- **`disable` is not accepted or used.** This project makes no claim about what `disable` does to stored records, and does not accept its exit status or the `Disabled` status that follows as evidence that any Secret was rewritten to plaintext. No phase runs it. A `Disabled` status after activation is the **Disabled-but-not-rewritten** state: it is never a rollback, the stored records may still be encrypted, and only the snapshot restore below leaves it.
- **The documentation disagrees.** The K3s CLI documentation still lists `reencrypt --force --skip` as the last HA disable step. The tested behavior and the source take precedence.

**`Disabled` is still parsed and reported.** The status parser keeps `Disabled` as a recognized state, so that an unexpected or legacy state can be diagnosed from the report rather than only failing as unparsed. The one supported point where it is expected is between step 2 and step 3, while the last recorded change is `enable`. After activation, no supported mutating phase creates it:

- there is no `disable` phase;
- `rotate-keys` always ends `Enabled`;
- drop-in removal is refused once the last change is `rotate-keys`.

`validate-secrets-encryption.yml -e secrets_encryption_expect=configured-disabled` passes only while the last change is `enable`. A `Disabled` status after `rotate-keys` meets no expectation, and it is a stop condition.

**The rollback model:**

| Point reached | Rollback | Snapshot restore |
| --- | --- | --- |
| Before step 1 | Nothing to undo | No |
| Step 1 done, or step 2 incomplete | Stop. The automation offers no live path: the exclusive enable round admits only the next restart, which [the p0 latch](#between-enable-and-the-first-restart-round) keeps available beyond the 120-minute limit. Data is unchanged (nothing is encrypted). | No |
| Step 2 complete (`Disabled`, `start`), before step 3 | Drop-in removal in the fixed order (`flag_state=absent`), through the ordered removal round; approved for live by the three-VM rehearsal. Nothing is encrypted yet. | No |
| Step 3 running (`reencrypt_active`) | **Wait** for `reencrypt_finished`. Never restart during re-encryption. If it is stuck, stop; do not improvise. | Only if Secrets become unreadable |
| Step 3 done, restarts incomplete | Go forward: finish the restarts in order | No |
| Step 4 complete, or any time after step 3 | **Controlled cluster restore of the pre-enable snapshot (p0).** There is no in-place rollback. | **Yes. This is the rollback.** |
| Quorum lost and not recoverable by restarting members, or etcd corruption | Cluster restore from the latest checkpoint snapshot whose server configuration matches | Yes, last resort |

**The pre-enable snapshot is the authoritative rollback boundary.** Preservation checks refuse any run in which a recorded on-demand snapshot has disappeared. p0 contains plaintext Secrets as they were before Stage 3 (see [What Stays Plaintext](#what-stays-plaintext)).

### What a restore rolls back

**Restoring p0 rolls back all Kubernetes and etcd state created or changed after p0, not only the encryption configuration.** The whole etcd keyspace returns to the moment p0 was taken. Lost or reverted, among others:

- every object created, changed or deleted after p0, in every namespace: Secrets, ConfigMaps, workloads, Flux and Helm release state, leases, events, certificates and their Secrets;
- changes made by people, controllers and Flux after p0. Flux re-applies the Git state afterwards; anything not in Git stays lost;
- Node objects, labels, taints and cluster membership, as they were at p0;
- the encryption configuration and its key (p0 has none), and the post-encryption canary.

State outside etcd is **not** rolled back: persistent volume contents, container images, host files, this role's state directory and the snapshot files taken after p0. Where such state depends on etcd objects (for example a volume whose contents moved on while its claim reverts), the mismatch must be assessed before the restore. The longer the time since p0, the larger the loss; that is why p0 is taken immediately before `enable`.

**Operator impact acknowledgment.** No future live restore starts without a written acknowledgment, kept with the change record and the separate restore approval, that states:

1. the p0 snapshot file name, its recorded size and SHA-256, and the time it was taken;
2. that every Kubernetes and etcd change after that time, not only the encryption change, will be rolled back or lost, and the known changes affected (Flux revisions, Helm upgrades, Secrets created or rotated, workloads);
3. the expected outage: all three servers stopped, and the API and every control loop unavailable until the restore completes;
4. the approver of the restore;
5. the record of the passing disposable restore rehearsal of the same sequence.

The automation contains no restore, and no variable that stands in for this acknowledgment.

### The pre-enable checkpoint (p0)

p0 is the snapshot that meets all of the following. `secrets-encryption-enable.yml` refuses to run unless each machine-checkable condition holds:

- **Created immediately before `enable`.** It is taken with `snapshot-etcd.yml --limit k3s01 -e secrets_encryption_snapshot_checkpoint=p0-pre-enable`, after the canary controls exist. When `enable` runs, it must be the newest Stage 3 snapshot on `k3s01`, and its snapshot invocation must be the last accepted entry in the confirmation ledger. Any other invocation after it, including a refused or failed `enable`, requires a new p0.
- **Verified and fresh.** The snapshot phase requires exactly one new, non-empty, regular file, no missing or changed non-scheduled snapshot, and a passing preservation gate afterwards. The `enable` gate requires it to be at most 120 minutes old.
- **Stored on the designated first server.** `k3s01` (`groups['servers'][0]`), in `/var/lib/rancher/k3s/server/db/snapshots`. The automation never copies, moves or prunes it.
- **Name and checksum recorded as metadata.** One line appended to `/var/lib/homelab-secrets-encryption/checkpoints` (root, `0600`) on `k3s01`: time, checkpoint label, file name, size, SHA-256 and `token=present`. `enable` requires exactly one p0 record matching the newest snapshot's name and size, and the enabling rotation requires a recorded p0 older than the `enable` marker. A malformed record fails closed. Before a restore, the file's SHA-256 is compared with the record.
- **Matching server token availability confirmed, never read.** Before the save, the snapshot phase checks the K3s server token file on `k3s01` by `lstat` alone: it must exist as a non-empty, root-owned regular file, not a link. Its content is never read, displayed, copied or hashed, and no token value appears in any record, report or command line. `token=present` records only that check. Before a restore, the operator confirms from the change record, again without reading the file, that the server token has not been rotated since p0; otherwise the token in use at p0 must be taken from the approved secret store.

### Restore procedure (manual, separately approved)

This automation does not run it. It is the K3s embedded-etcd restore for HA clusters ([K3s `etcd-snapshot`: cluster reset and restore](https://docs.k3s.io/cli/etcd-snapshot)), with this project's additions marked. It requires the impact acknowledgment, a separate approval, and a passing disposable rehearsal of exactly this sequence.

**This is the procedure for the real servers** (K3s under systemd on `k3s01`, `k3s02` and `k3s03`). Every command runs from the console of the server named. The disposable k3d rehearsal reproduces the same sequence with container mechanics described in [Restore in the k3d rehearsal](#restore-in-the-k3d-rehearsal-rehearsal-tooling-only); those mechanics are rehearsal tooling and are **never** a recovery method for the real servers.

1. *(Project.)* **Preconditions:** the acknowledgment is recorded; the SHA-256 of p0 on `k3s01` matches its record (report only match or mismatch); the matching token is available; all three servers are reachable.
2. **Stop K3s on every server:** `systemctl stop k3s` on `k3s01`, `k3s02` and `k3s03`.
3. *(Project.)* **Return every server to the pre-enable configuration:** move the secrets-encryption drop-in out of `config.yaml.d` into a preserved directory, so that all three start with the critical arguments p0 was taken with. The generated encryption configuration and state files stay where they are (see [Encryption files during a restore](#encryption-files-during-a-restore)).
4. **Reset and restore on `k3s01`, by explicit invocation:** with `k3s.service` stopped, run `k3s server --cluster-reset --cluster-reset-restore-path=<p0 path>` in the foreground. K3s reads the server's normal configuration (`config.yaml` and `config.yaml.d`, now without the drop-in) as on any start. Never deliver the reset by writing `cluster-reset` fields into a configuration file and starting the service: in the k3d rehearsal that delivery did not complete (see the [2026-10-26 records](#k3d-rehearsal-record-2026-10-26-complete-lifecycle)). If the server's token has changed since p0, pass the token in use at p0 with `--token-file=<root-only file>`, never as `--token` on the command line. Accept the reset only as described in [Accepting the reset](#accepting-the-reset).
5. **Start K3s on `k3s01` normally:** `systemctl start k3s`, without any reset option. The start clears the reset flag. Wait until the node is Ready and etcd is healthy as a single member.
6. **Rejoin `k3s02`, then `k3s03`:** the K3s documentation deletes `/var/lib/rancher/k3s/server/db/` on each peer. This project **moves** it to a dated, preserved directory instead and never deletes it. Then `systemctl start k3s`, so that the server rejoins through `k3s01` as a new etcd member. Wait for the node to be Ready and for every etcd endpoint to be healthy before the next server.
7. **Rebuild a peer that does not rejoin.** If a peer is refused (for example "critical configuration value mismatch") or does not become healthy, stop it, preserve its K3s data directory, and rebuild it as a replacement join with this repository's playbooks (`k3s_secrets_encryption_enabled: false`, the cluster token and the same critical arguments as `k3s01`). If it registers under a different name, delete the stale Node object it left behind. Rejoin the other peer first, so that quorum never depends on the rebuilt one.
8. **Verify:**
   - three Ready nodes, and three healthy etcd endpoints;
   - `k3s secrets-encrypt status` reports `Disabled, no configuration file found` on all three servers, as before `enable`;
   - the drop-in is absent on all three servers;
   - the pre-enable plaintext controls are readable and unchanged; the post-enable canaries are absent;
   - every Flux Kustomization and HelmRelease reports Ready (read-only status; no `flux reconcile`);
   - `validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=not-configured` passes.
9. *(Project.)* **Afterwards:** this role's state directory is host data and is not rolled back. Its markers describe changes that no longer exist in etcd, so it is moved aside (preserved) before any new Stage 3 attempt, which starts again at step 0. The same applies to the retained encryption configuration and state files (see below). The snapshot files taken after p0 stay on disk and are protected as before; p1 contains plaintext Secrets, later ones contain encrypted Secrets.

A snapshot restore is never the response to a single failed server (it rejoins) or to an unexpected stage alone. This automation contains no snapshot restore, cluster reset, database move or removal, or rejoin logic.

#### Accepting the reset

Observed in the 2026-10-26 restore diagnostic on `v1.36.4+k3s1`, and consistent with the source (`pkg/etcd/etcd.go`, `Reset`): a successful reset restores the snapshot, starts etcd as a new single-member cluster, reconciles the bootstrap data, and then shuts down with **exit status 0**. It reports completion with the documented instruction, logged at **ERROR level**:

```text
level=error msg="Shutdown request received: \"Managed etcd cluster membership has been reset, restart without --cluster-reset flag now. ...
```

The reset is accepted **only** when all three hold:

1. the process exited with status 0;
2. its log contains the message `Managed etcd cluster membership has been reset, restart without --cluster-reset flag now`;
3. the reset flag `/var/lib/rancher/k3s/server/db/reset-flag` exists afterwards. K3s does not log its creation; check the file.

The ERROR level of that line is not a failure, and exit status 0 alone is not success. If any of the three is missing, the reset is not accepted: stop, keep every server stopped, and do not start `k3s01`.

#### Encryption files during a restore

Observed in the 2026-10-26 restore diagnostic, after `enable` and its restart round (an identity-only configuration; no rotation):

- the encryption drop-in is moved aside before the reset (step 3);
- the generated files `/var/lib/rancher/k3s/server/cred/encryption-config.json` and `encryption-state.json` **remain on disk** on every server. Their inode, size and modification time were unchanged through the stop, the reset, `k3s01`'s start and both rejoins: they were neither moved, regenerated nor removed;
- with the drop-in absent, every server reported `Disabled, no configuration file found`. In the source, K3s sets no encryption-configuration path when `secrets-encryption` is off (`pkg/daemons/control/deps/deps.go`), so the files are not read.

**Their presence alone must not be interpreted as active encryption**, and their absence from the status is not proof of plaintext either. The effective state after a restore is established only by the post-restore status on every server together with the API readbacks and raw etcd checks of the controls: the pre-enable Secret stored in plaintext and byte-for-byte as captured before p0, and the post-enable canaries absent.

The complete run-8 rehearsal, after a real rotation, confirmed that the generated files (then holding the secretbox key) were **present before and after** the restore on every server, while status, readbacks and raw records showed the restored, unencrypted p0 state. It recorded their presence only: it did not compare their inode or modification time after the restore. The unchanged metadata is established by the earlier restore diagnostic, which used an identity-only configuration.

In the source, a later `enable` reuses a non-empty encryption configuration file that already exists (`genEncryptionConfigAndState`). The retained files are therefore moved aside (preserved) before any new Stage 3 attempt (step 9).

### Restore in the k3d rehearsal (rehearsal tooling only)

k3d servers are containers whose main process is K3s. There is no systemd, and a stopped container cannot run a second command, so the rehearsal reproduces the real-server sequence with these mechanics. None of them is a recovery method for the real servers.

1. **Record S1's identity before the stop:** container identity, network, address, aliases, hostname, MAC address and endpoint metadata, and its volumes. Refuse before any shutdown if a disconnect and reconnect could not rebuild the network attachment exactly (more than one network, legacy links, endpoint driver options, an IPv6 address, or IPAM settings beyond an IPv4 address).
2. **Stop all three server containers concurrently**, with one bounded `docker stop` (30 seconds), so that no server is left waiting after quorum disappears.
3. **Move the drop-in aside** with a labelled throwaway helper container that mounts the stopped server's volumes. Each server's `config.yaml.d` is its own volume for this purpose.
4. **Disconnect only S1** from the k3d network. Its container and volumes are never deleted or recreated. Immediately before the runner attaches, prove that S1's recorded address is inside the network's subnet, held by no endpoint and reserved by no other container; otherwise stop. An address-allocation failure is a rehearsal-harness failure, not a restore result.
5. **Run the explicit reset** in a runner container built from S1's exact image ID, all of S1's volumes (`--volumes-from`), S1's hostname, recorded address and aliases, and S1's privilege, cgroup namespace, security options, tmpfs mounts and init setting. The command is `/bin/k3s server <S1's own server arguments> --cluster-reset --cluster-reset-restore-path=<p0> --token-file=<server token file>`. No token or join URL is passed in the environment or on the command line. S1 stays stopped.
6. **Accept the reset** as in [Accepting the reset](#accepting-the-reset), with the runner's numeric exit status. Its log is captured privately and bounded, and reported sanitized with the relevant INFO and ERROR lines: startup, snapshot restore, membership reset, bootstrap reconciliation, the restart instruction, waits, retries and timeouts.
7. **Remove the runner, prove the address is free again, and reconnect the original S1** with its recorded address and aliases, then start it normally. Compare its network identity with the record: the container identity, hostname, network, address, prefix, gateway, aliases and volumes must be unchanged. Expected network-endpoint differences of this k3d handoff are reported, not checked: the address becomes an explicit IPAM assignment, and the MAC address and endpoint ID differ from the record. In the 2026-10-26 diagnostic the MAC address and endpoint ID had also changed across one ordinary `docker restart` of S1, before any disconnect, so the difference is not specific to the handoff. Whether they change on every restart was not tested.
8. **Rejoin S2, then S3**, each after its database directory is moved aside by a helper and preserved.

The rehearsal harness also captures Docker events with two collectors (servers and runner by name; helpers by label), proves both collectors and the etcd member and endpoint-health queries before any shutdown, and reports every runner exit status as a number.

### Key material and the off-node recovery copy

- **What holds the key.** The secretbox key exists only in the encryption configuration that `rotate-keys` writes. That is `/var/lib/rancher/k3s/server/cred/encryption-config.json`, identical on every server after the second restart round (K3s's `All hashes match` confirms they agree), and the copy K3s keeps in its bootstrap data in etcd, encrypted with the server token. `encryption-state.json` holds the rotation stage and a hash, not the key.
- **What the rehearsals showed, and did not.** p0 predates the encryption configuration, so restoring it needs no key. The three-VM p2 restore decrypted p2's Secrets, but it ran on servers whose encryption files stayed on disk with unchanged inode, size and modification time. It does **not** show that a snapshot and the token restore the key onto servers that lost those files; that path is untested.
- **What must survive the loss of all three servers:**
  1. a post-activation snapshot (p2 or later) held off the node. Until Stage 4's scheduled uploads exist, this is the interim manual p2 copy below;
  2. the server token in use when that snapshot was taken, from the `home-cluster` recovery material;
  3. an independent copy of `encryption-config.json`, so that recovery does not depend on the untested bootstrap path.

  Without the key, every Secret encrypted under it is lost, whatever snapshots survive.
- **When the copy is made.** Once, after step 4's restart round, the enforced `enabled` validation and p2. No further rotation is approved, so the key does not change afterwards. Any later approved rotation needs a new verified copy before it counts as complete.
- **Who makes it (a `home-cluster` dependency).** The copy is encrypted with `age` v1.3.2 on `k3s01` to the committed recovery recipient, by the `home-cluster` recovery-material helpers that already handle the server token (see [recovery-tools.md](recovery-tools.md)). This repository has no helper for the encryption configuration, and none is added here. The helper's `encryption-config` item was merged into `home-cluster` `main` in pull request #21 (commit `3bb8199`), with its procedure and timing in that repository's runbook `docs/runbooks/encrypted-recovery-material.md`. It was run against the live cluster on 2026-10-29, at `home-cluster` `9f46215`; that repository's validation record holds the result. The [live rollout record](#live-rollout-record-2026-10-28-to-2026-10-29-complete) summarizes it.
- **The live copy (2026-10-29).** Made after the second restart round, the enforced `enabled` validation and p2:
  - object `recovery/encryption-config/2026-10-29.age`, 472 bytes of ciphertext;
  - source check PASS; exact-version download `MATCH`; controlled decryption on `k3s01` `MATCH`;
  - recovery-copy status `verified`, recorded in the updated recovery-material inventory, which was copied to Recovery A and Recovery B.
- **The interim p2 snapshot copy (2026-10-30, a `home-cluster` dependency).** p2 itself, selected from its single Stage 3 checkpoint record, was preserved once off the node by the `home-cluster` helpers at `39776b6` (pull request #25). That repository's validation record holds the result:
  - object `recovery/stage3-p2-snapshot/2026-10-29.age`, 10152584 bytes of ciphertext, uploaded once;
  - source check PASS; exact-version download `MATCH`; controlled decryption on `k3s01` `MATCH` against the checkpoint-bound p2, which was unchanged afterwards;
  - recorded in the recovery-material inventory of 2026-10-30, which was copied to Recovery A and Recovery B.

  **It is an interim manual Stage 3 copy, not Stage 4.** No `etcd-s3` setting was added and nothing was written under `etcd/`; Stage 4's scheduled snapshot uploads remain pending. No restore from it has been rehearsed.
- **How it is verified, without displaying key material.** The plaintext is never printed, logged, copied to the controller or held in an Ansible fact. The helpers report metadata only: the source check (a nonempty regular `root:root` file at exactly the expected path, its mode with no group or other access, and a `root:root` credential directory that group and others cannot write to), the ciphertext's size and SHA-256, and the object key. They never report the plaintext's size or hash, and the object's version ID is kept in a private receipt, never printed. Two comparisons follow, each reporting only `MATCH`, `DIFFER` or `ERROR`: the ciphertext downloaded from the off-node destination by that exact version against the uploaded one, and a controlled decryption on `k3s01` with a recovery identity, whose output is compared with the servers' file inside a private tmpfs. The copy is verified only when both report `MATCH`; `DIFFER` or `ERROR` stops the procedure.
- **If the copy cannot be completed.** Stop. The rollout is **not complete**: do not declare it complete, do not upload any snapshot off the node, and do not rotate again. The cluster keeps running encrypted, with the key on all three servers and in etcd. Resolve the problem and make the copy; restoring p0 instead is a separate decision with its own approval.

## Fresh Builds and Replacement Joins

[`roles/k3s-server`](../ansible/roles/k3s-server) has `k3s_secrets_encryption_enabled: false` by default.

**When true:**

- The role writes the same drop-in **only on a server where neither the K3s binary nor K3s data exists**, before K3s first starts.
- A new cluster then starts with secretbox encryption, the documented path for new servers.
- A replacement server joins with the critical arguments the cluster requires.

**On a server with K3s installed**, the role never writes or removes the drop-in, and never restarts K3s.

**Timing of the flip:**

- **It was left false until the live procedure completed**, because the servers ran without the flag and a server built with it could not have joined them. The live procedure completed on 2026-10-29.
- **Set it to true in the follow-up template-flip PR, not yet made.** Until then, a rebuilt or replacement server built from this repository could not join the encrypted cluster.

`site.yml` is unchanged by Stage 3.

## Rehearsals

### k3d (required before merge)

A disposable three-server k3d cluster at `rancher/k3s:v1.36.4-k3s1`. k3d nodes are containers, so the phase playbooks cannot drive them. The rehearsal executes the [encoded procedure](#encoded-procedure) step by step with `docker exec <server> k3s ...`:

- restarts are `docker restart <server>` in the fixed order, with each server confirmed ready before the next;
- etcdctl is the same pinned v3.6.14 binary, checksum-verified on the host, copied into the S1 container and used only on the canary keys through the same verifier;
- it records every server's parsed status and the restarts needed at each step;
- the canary value directory is a private volume on S1, so that it survives `docker restart` as `/run` survives `systemctl restart k3s`;
- Docker lifecycle events and container metadata are captured throughout, by two collectors (the servers and the reset runner by name; helper containers by label), both proven before any shutdown, and any unplanned restart stops the run;
- etcd member and endpoint-health queries pass the subcommand after the TLS options, and are proven to parse before any shutdown;
- the restore follows [Restore in the k3d rehearsal](#restore-in-the-k3d-rehearsal-rehearsal-tooling-only): concurrent bounded stop, network identity recorded, fail-closed address checks, the explicit reset runner, and the original S1 reconnected with its identity unchanged;
- every runner and phase exit status is reported as a number, and container logs are captured bounded and sanitized, keeping the relevant INFO and ERROR lines.

**Acceptance criteria.** The next complete k3d rehearsal passes only if every one of these holds, in order:

1. **Before p0:** the canary controls (the pre-encryption Secret and the plaintext ConfigMap control) exist, with their comparison values and raw records captured; p0 is then taken as defined in [The pre-enable checkpoint](#the-pre-enable-checkpoint-p0), its record written and the token presence confirmed without reading the token.
2. **Forward:** enablement through the exclusive restart round, then activation with the one rotation and its ordered restart round.
3. **Encryption:** after `enable`, the driver also creates a post-enable ConfigMap canary. The canaries' raw records show encryption where expected, and the comparison values persist across the restarts.
4. **Restore from p0**, following the [restore procedure](#restore-procedure-manual-separately-approved) as reproduced in [Restore in the k3d rehearsal](#restore-in-the-k3d-rehearsal-rehearsal-tooling-only): every server stopped concurrently, the drop-in moved aside, the explicit reset and restore of S1 with the matching token file, accepted only by [all three criteria](#accepting-the-reset), the original S1 reconnected with its recorded network identity and started normally, the database directories of S2 and S3 moved aside and preserved, S2 and then S3 started. The generated encryption files are recorded by metadata only, and the effective state is judged by status, readbacks and raw records, not by their presence.
5. **All three servers return Ready.**
6. **All three etcd endpoints are healthy.**
7. **The pre-enable plaintext controls return byte-for-byte:** API readbacks and raw records match the values captured before p0, reported as match or mismatch only.
8. **The post-enable Secret and ConfigMap canaries are absent.**
9. **Encryption status returns to the original not-configured state:** `Disabled, no configuration file found` on all three servers.
10. **The encryption drop-in is absent** on all three servers after the restore.
11. **The container lifecycle contains only planned events:** every Docker lifecycle event over the whole run is one of the planned restarts, stops and starts, and no container is replaced or restarted on its own.
12. **Teardown** removes the cluster, its volumes, the kubeconfigs, the temporary worktree and every rehearsal process, and the check for each is recorded.

The k3d rehearsal **passed** on 2026-10-26 (run 8) against all twelve criteria. The Flux, HelmRelease, monitoring and platform-canary checks of the gate do not apply to a disposable k3d cluster; they were not run and are not claimed as passed. Static tests do not count towards the rehearsal.

### k3d rehearsal record (2026-10-23)

A disposable three-server k3d cluster (k3d v5.9.0, Docker 29.1.3 under WSL2, image `rancher/k3s:v1.36.4-k3s1`, every server reporting `v1.36.4+k3s1`), driven from the pushed commit `cd4bbd1` with `docker exec`. The run **stopped at step 1** on a failed gate, as the stop conditions require. No drop-in was written and no server was restarted by the procedure. No rotation, re-encryption, encrypted canary check, rollback or snapshot restore ran. The cluster was deleted afterwards. The evidence was metadata only.

**Observed:**

- **Baseline:** `k3s secrets-encrypt status` printed `Encryption Status: Disabled, no configuration file found` on all three servers, and the parser accepted it. Local `/readyz`, `/readyz/etcd`, node readiness and etcd membership were healthy.
- **Checkpoint p0:** `k3s etcd-snapshot save --name stage3-p0-pre-enable-<time>` on S1 created exactly one new file, on S1 only. No other snapshot file existed, so pruning could not be observed.
- **Canary controls:** the API readback of `stage3-canary-pre-encryption` matched. The raw records of that Secret and of `stage3-canary-plaintext-control`, read with the pinned etcdctl 3.6.14 (`get --write-out=json -- <key>`), passed the verifier in `plaintext` mode, and the canary value was present in the Secret's raw record.
- **Step 1:** `k3s secrets-encrypt enable` on S1 exited 0 and printed exactly `secrets-encryption enabled`. A K3s CLI warning about the cluster CA appeared on standard error only.
- **After step 1, before any restart:** `k3s secrets-encrypt status` failed on **all three** servers: `level=fatal msg="Error: see server log for details: Internal error occurred: secret-encrypt error ID <n>"`. The S1 server log reported `missing annotation on node <S1>` for each request. Local `/readyz` and `/readyz/etcd` stayed `ok`, and no server restarted.
- **Consequence:** the committed `enable.yml` asserted that status parses as `Disabled` right after `enable`, so it would have failed at the same point. The common health gate would also have refused the first restart, because it treated any unparsed status as a failure. The encoded procedure could not have reached step 2.

**Corrected in the encoded procedure** (statically tested only, not yet rehearsed):

- Step 1 accepts only exit status 0 with exactly `secrets-encryption enabled`, records the marker only afterwards, and reads no status.
- The [enable restart round](#between-enable-and-the-first-restart-round) tolerates exactly the observed unavailable status, only in the restart phase, only in strict order, and only with a consistent marker, ledger and pre-enable checkpoint.
- The `k3s03` run requires every server to report `Disabled`, `start` and matching hashes before the round is complete. Until then, p1 and rotation are refused.

**Rehearsal-harness findings (k3d only):**

- In the `rancher/k3s` image, `k3s kubectl …` fails (`unknown command "kubectl" for "kubectl"`). The image's `kubectl` works. This does not apply to the VM rehearsal or the live servers, where the playbooks call `k3s kubectl`.
- A WSL2 host stops the distribution, Docker and every k3d server when no WSL session is open, and clears `/tmp`. A first attempt on 2026-10-23 was discarded before step 1 for that reason. The rehearsal host needs a session kept open for the whole run.

**Still unanswered after this run, because it stopped at step 1** (see the 2026-10-24 record for what was observed later): whether status becomes readable after the first restart round (and after which server), and what it shows then (rehearsal questions 1 and 3); questions 2 and 4 to 12, apart from the partial observations above on 9 (the no-configuration status text), 10 (the plaintext controls) and 11 (one CLI save on S1 created one file on S1 only).

### k3d rehearsal record (2026-10-24)

A fresh disposable three-server k3d cluster at `rancher/k3s:v1.36.4-k3s1` (k3d v5.9.0, Docker 29.1.3 under WSL2), driven from the pushed commit `ccfaf34`, which already contained the step 1 correction. The run **stopped after `k3s01`'s restart** on a failed acceptance check. The rehearsal has still **not** passed. The cluster was deleted afterwards. An earlier attempt the same day stopped at the same point on a defect in the rehearsal driver's restart-counter comparison. Docker events showed only the planned restart. That attempt was discarded and the driver fixed.

**Observed:**

- **Baseline, canary controls and p0:** as on 2026-10-23. p0 created exactly one file, on S1 only.
- **Step 1:** `enable` exited 0 with exactly `secrets-encryption enabled`. Status then failed on all three servers with the narrowly defined `unavailable` result.
- **The corrected transition:** the restart phase tolerated the unavailable status, with `k3s01` as the next server, a consistent ledger and the pre-enable checkpoint present. The snapshot, rotate-keys, validation and canary-verify gates refused it, as did drop-in removal and an S2 or S3 restart before S1.
- **`k3s01`'s restart with the drop-in:** ready in about 20 seconds, with no unplanned restart. The post-restart gate passed and the restart was verified.
- **After `k3s01` alone:** `k3s secrets-encrypt status` became readable on **all three** servers and reported `Disabled`, stage `start` and **matching hashes**, while `k3s02` and `k3s03` had not restarted and carried no drop-in. A replay of `k3s01` and an S3 restart before S2 were still refused. But the snapshot gate, which relied on the unavailable status to refuse, **passed**: checkpoint p1 was not blocked mid-round. That was the failed check. Rotation stayed blocked by its own prerequisites (every server verified, with the drop-in).

**Corrected in the encoded procedure** (statically tested only, not yet rehearsed): the [enable restart round](#between-enable-and-the-first-restart-round) is exclusive. The gate refuses every phase other than the next restart until all three servers have durable `restart-verified` records, and status readability never counts as completion. The validation playbook reports and enforces the same rule.

**Still unanswered:**

- what status shows after `k3s02` and `k3s03`, and whether hashes keep matching;
- every later step: rotation, re-encryption, the encrypted canary checks, the rollback, drop-in removal and snapshot restore;
- rehearsal questions 2 and 4 to 12, apart from the partial observations on 9, 10 and 11.

These were answered in part by the next record.

### k3d rehearsal records (2026-10-25 and 2026-10-26)

Fresh disposable clusters from the pushed commit `df316f8`. Docker lifecycle events and corrected container metadata were captured throughout, every negative check had to be refused for its expected reason, and a private volume on S1 held the canary comparison values. The k3d rehearsal has still **not** passed.

**Observed:**

- **Steps 0 to 4 passed end to end:**
  - the enable restart round was exclusive: after S1 and after S2, every other phase was refused by the exclusive-round gate, and only the next server was admitted;
  - the round completed only after S3's convergence check (`Disabled`, `start`, matching hashes);
  - one rotation in 35 to 53 seconds, `XSalsa20-POLY1305`, `reencrypt_finished`, with 9 Secrets stored before it;
  - the second ordered restart round.
- **Encrypted canary verification passed:** both API readbacks matched; the post-encryption Secret and the rewritten pre-encryption Secret are stored with the secretbox prefix and without their values; the ConfigMap control is still plaintext.
- **There were no unplanned restarts:** every server had only its planned restarts, kept its container, and kept a restart count of 0.
- **The rehearsal environment matters:**
  - a run that kept the canary values in k3d's tmpfs `/run` lost them across `docker restart`;
  - the earlier unexplained S3 restart (2026-10-24) did not recur in a diagnostic or in three later runs.
- **R1 and R2 behaved as documented:**
  - `disable` exited 0 with exactly `secrets-encryption disabled`;
  - status then read `Disabled`, `reencrypt_finished`, matching hashes, on every server, before and after the ordered restarts.
- **R3 is rejected:** `k3s secrets-encrypt reencrypt --force --skip` exited 1. The server log said `reencrypt does not support secretbox key type, use rotate-keys instead` (HTTP 400). Classification: an invalid state or transition, rejected by K3s by design, not a CLI parsing error, a timing condition or a defect. `--force` and `--skip` are both listed in `--help`, every server was ready, and etcd was 3/3 healthy before and after.

**Consequence:** the R1/R2/R3 rollback is removed from the automation. The only rollback after activation is the pre-enable snapshot restore (see [Rollback](#rollback)).

### k3d rehearsal record (2026-10-26, complete lifecycle)

A complete rehearsal of the unstaged correction (`df316f8` plus the candidate diff, in an isolated worktree). The rehearsal **did not pass**.

**Observed:**

- **Forward lifecycle, all passed:**
  - p0 taken immediately before `enable`, its record matching the file;
  - eleven bounded p0 negative checks refused for the expected reasons;
  - the exclusive enable restart round;
  - one rotation in 67 seconds;
  - the second restart round;
  - post-enable Secret and ConfigMap canaries;
  - Secrets encrypted, ConfigMaps plaintext, etcd 3/3 healthy;
  - checkpoint p2.
- **Restore stopped at the reset:** the reset was delivered as `cluster-reset`, `cluster-reset-restore-path` and `token-file` fields in a temporary `config.yaml.d` file, followed by an ordinary start of the S1 container. S1 did not exit within 600 seconds, and the run stopped there. The bounded log filter retained no INFO-level lines, so where it stopped was not determined.
- **Sequential stops:** stopping the servers one after another left S3 waiting after quorum was gone, and it needed SIGKILL after its 60-second stop timeout.

### k3d restore-mechanism diagnostics (2026-10-26)

Focused diagnostics of the restore mechanism alone, on fresh disposable clusters, after p0 and a minimal `enable` with its restart round (no rotation). They were not complete Stage 3 rehearsals.

- **First attempt:** stopped by its own precondition before any shutdown. It assumed k3d gives S1 a static address, but it is dynamic. The attempt also exposed two harness defects, both since corrected: the etcdctl wrapper passed an extra argument, and the event filters combined keys that Docker joins with AND.
- **Corrected run passed:**
  - the concurrent bounded stop took 20 seconds, every server exiting 143;
  - S1 was disconnected, and its recorded address proved free;
  - the explicit runner restored p0 and exited **0 after 8 seconds**. It logged the documented message at ERROR level and left the reset flag;
  - the runner was removed and the address proved free again; the original S1 was reconnected with its recorded address and started normally;
  - etcd was 1/1 healthy, then 2/2 and 3/3 as S2 and S3 rejoined one at a time with preserved database directories;
  - three Ready nodes and `Disabled, no configuration file found` on all three;
  - a marker created before p0 was present and one created after p0 was absent;
  - S1's container identity, volumes, address, hostname, gateway and aliases were unchanged. After the handoff, the address was an explicit assignment, and the MAC address and endpoint ID differed from the record. Both had also changed across an ordinary `docker restart` of S1 earlier in the same run, before any disconnect.
- **Encryption files:** retained unchanged on every server, as described in [Encryption files during a restore](#encryption-files-during-a-restore).

**Consequence:** the restore is delivered by explicit invocation, accepted by exit status, message and reset flag together, and rehearsed with the k3d mechanics above.

### k3d rehearsal record (2026-10-26, run 8: passed)

The complete disposable rehearsal of the unstaged correction (`df316f8` plus the candidate diff, in an isolated worktree whose diff matched the working tree byte for byte), with the corrected restore. **It passed.** Every phase exited 0, and so did teardown.

**Forward lifecycle, all passed:**

- clean preflight;
- canary controls created and verified before p0;
- p0 taken immediately before `enable`, its record matching the file, with token presence checked by `lstat` only;
- 45 negative checks refused for their expected reasons, among them all 11 p0 checks (absent, stale, malformed, mismatched, duplicated and superseded p0);
- `enable` with the exact result;
- the exclusive S1, S2, S3 restart round, converging to `Disabled`, `start`, matching hashes;
- exactly one rotation (58 seconds, `XSalsa20-POLY1305`, `reencrypt_finished`) and the second ordered restart round;
- post-enable canaries;
- encryption proven: four API readbacks matched, the Secrets were stored Secretbox-encrypted and both ConfigMaps in plaintext, and etcd was 3/3 healthy;
- checkpoint p2 taken.

**Restore of p0, all passed:**

- **Before the shutdown:** the restore acknowledgment was recorded; etcd member and health queries were proven; S1's network identity was recorded and found reconstructable.
- **Concurrent bounded stop:** one `docker stop` of all three servers finished in 16 seconds.
- **Drop-in:** moved aside on every server.
- **Network handoff:** S1 was disconnected, and its address proved free twice.
- **Explicit reset runner:** it exited **0 after 10 seconds** without OOM and logged the documented message at ERROR level, and the reset flag was present. All three acceptance criteria held.
- **Reconnect:** the runner was removed and the address proved free again. The original S1 was reconnected and started with the same container, hostname, network, address, prefix, gateway, aliases and volumes; the address became an explicit assignment, and the MAC address and endpoint ID differed.
- **S1 recovery:** a healthy single member (1/1), with its reset flag cleared on the normal start.
- **S2 and S3 rejoin:** each database directory was moved aside and preserved, and the servers rejoined one at a time, to 2/2 and then **3/3 healthy etcd**.

**Final acceptance, all passed:**

- three Ready nodes; three healthy etcd endpoints;
- `Disabled, no configuration file found` on all three servers; the drop-in absent on all three;
- the pre-enable Secret and ConfigMap controls restored **byte-for-byte**, in their API values and in the digests of their raw stored values;
- the restored Secret **plaintext in raw etcd**, with its canary value present in the record;
- the post-p0 Secret and ConfigMap canaries **absent**, in the API and in raw etcd.

The Flux and workload acceptance checks were **not applicable** in disposable k3d and are not claimed as passed.

**Lifecycle audit and teardown:**

- every Docker lifecycle event fell inside an audited planned window;
- no unplanned restart, recreation, OOM, or host or daemon restart;
- 7 labelled helper containers (including the reset runner) were each created and destroyed;
- teardown removed the cluster, containers, network and every volume (including the preserved databases), no kubeconfig was generated, the host kubeconfig and image set were unchanged, and the worktree was confirmed clean before it was removed.

**S1 shutdown observation:**

- During the planned concurrent stop, Docker sent SIGTERM to all three servers. S2 and S3 exited 143; **S1 exited 1**.
- S1 stopped within the 30-second bound, was not OOM-killed and was not restarted, and the subsequent restore succeeded.
- The cause of the exit status 1 was not determined. It is recorded as a k3d observation, not as expected behavior and not as evidence of failure. **It did not reproduce under systemd:** in the three-VM rehearsal, every server stopped with exit status 0 in both planned concurrent stops (see the [three-VM record](#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed)).

**Encryption files:** see [Encryption files during a restore](#encryption-files-during-a-restore). This run confirmed presence before and after the restore, but did not compare their metadata.

### Three-VM Ubuntu (after k3d)

Three disposable VMs built with this repository's Packer image and playbooks, with an inventory that uses none of the live host names. This rehearsal exercises the real playbooks end to end:

- `-e secrets_encryption_environment=rehearsal`;
- `install-etcdctl-rehearsal.yml`, then raw verification;
- the gate settings relaxed where the rehearsal lacks Flux, HelmReleases, monitoring or the platform canary (`secrets_encryption_expected_kustomizations=[]`, `secrets_encryption_min_helmreleases=0`, `secrets_encryption_monitoring_namespaces=[]`, `secrets_encryption_canary_deployment=""`). The guard refuses these relaxations in a live environment;
- systemd restart behavior, waits, gates, idempotent reruns and cleanup.

### Three-VM rehearsal record (2026-10-27, commit 825b09b: passed)

Three disposable Ubuntu VMs (`s3r01`, `s3r02`, `s3r03`, 4 GB and 2 vCPU each), full clones of this repository's Packer base image on an isolated NAT network. They ran K3s `v1.36.4+k3s1` under systemd, embedded etcd and kube-vip. They used a generated rehearsal inventory with none of the live host names, from a `git archive` code copy of the exact commit under test, with no live inventory present. Every command went through a wrapper that refused any other inventory, any live host name and any address outside the rehearsal network. **It passed** at `825b09b2b9bfffef1e227a843600a83665664d99`, after two repository defects found during the run were corrected:

| Defect | Found at | Corrected in |
| --- | --- | --- |
| The service probe's `argv` was a YAML flow list, so `--property=ActiveState,ActiveEnterTimestamp,NRestarts` was split at its commas: `systemctl` received two property names as unit names, and every server's start time and restart count were unreadable. The gate failed closed. | The first enforced `not-configured` validation, before any Stage 3 change | `0dea72001a3c757bc946e3f7259a9595ab242806`, which also added a structural check against unquoted commas in flow-style `argv` lists |
| Drop-in removal before activation could not pass its first server: a server whose drop-in was removed reports `Disabled, no configuration file found`, which the restart preconditions treated as unsettled, so `s3r02` was refused. Nothing restarted; the cluster stayed healthy in a mixed state. | Cycle B, removal round, second server | `825b09b2b9bfffef1e227a843600a83665664d99` (see [The removal round](#encoded-procedure)) |

**Cycle A, forward lifecycle, all passed:**

- **Before any change:** enforced `not-configured` validation, with every server's start time and restart count read. Eight guard refusals, each stopped inside the guard before facts with nothing changed: a limit pattern, another host's confirmation, a stale confirmation, the wrong phase, `live` declared against the rehearsal inventory, no environment, a non-first server, and an overridden pin.
- **Setup:** baseline snapshot, then the pinned etcdctl installation. A replayed confirmation was refused at the gate.
- **Controls and p0:** the canary controls passed readback and raw-plaintext checks. p0 was then taken, recorded and SHA-256 checked, with token presence checked by `lstat` only.
- **Step 1:** `enable` returned the exact result.
- **During the incomplete round, all refused:** a snapshot and drop-in removal at the health gate (status unreadable); an out-of-order `s3r02` restart at the order check; enforced validation (`enable_round_blocking: true`).
- **Step 2:** the enable restart round in order. A replayed `s3r01` and a skipped `s3r03` were refused. `configured-disabled` validation passed.
- **p1 and step 3:** p1, then one `rotate-keys`: `Enabled`, `reencrypt_finished`, `XSalsa20-POLY1305` on the first server.
- **Step 4:** the second ordered restart round. Enforced `enabled` validation passed on all three servers, with matching hashes.
- **Verification:** canary verify passed both readbacks. Raw etcd showed the rewritten pre-encryption Secret and the new Secret Secretbox-encrypted, and the ConfigMap control plaintext; every canary was then removed. p2 was taken.
- **Idempotence:**
  - a repeated restart of `s3r01` restarted nothing;
  - repeated canary cleanup and etcdctl installation changed only the ledger;
  - a second rotation was refused.

**p2 restore (post-rotation, drop-in kept), all passed:**

- **Precondition:** SHA-256 matched the record, and token presence was confirmed.
- **Stop:** all three servers stopped concurrently.
- **Reset:** the explicit foreground reset on S1 exited 0 after 4 seconds, logged the documented message at ERROR level, and left the reset flag. All three [acceptance criteria](#accepting-the-reset) held.
- **Rejoin:** S1 started normally (1/1), then S2 and S3 rejoined, each after its database directory was moved aside and preserved (2/2, 3/3).
- **Keys:** status `Enabled`, `reencrypt_finished`, matching hashes on all three. A Secret written before p2 matched its pre-p2 API and raw-record digests, and its raw record was still Secretbox-encrypted. The servers kept their encryption files on disk, so this shows decryption with the restored data and the retained files, not that a snapshot alone restores the key (see [Key material](#key-material-and-the-off-node-recovery-copy)).
- **Rollback of later writes:** a Secret created after p2 was absent from the API and from raw etcd.
- **Encryption files and drop-ins:** inode, size and modification time unchanged. Enforced `enabled` validation passed.

**p0 restore (the rollback; drop-in moved aside on every server), all passed:**

- **Reset and rejoin:** the same sequence. The reset exited 0 after 2 seconds with all three criteria, and etcd went 1/1, 2/2, then **3/3 healthy**.
- **Nodes and status:** three Ready nodes, and `Disabled, no configuration file found` on all three.
- **Controls:** the pre-enable Secret and ConfigMap matched their pre-p0 API and raw-record digests **byte for byte**, and both raw records were plaintext.
- **Later objects:** every post-p0 object was absent from the API and from raw etcd: the post-encryption canary, a post-enable ConfigMap, a post-rotation Secret and a post-p2 Secret.
- **Encryption files:** retained, with unchanged inode, size and modification time, which answers the metadata question that run 8 left open. Enforced `not-configured` validation passed.
- **Stale marker:** that validation passes even with the stale `rotate-keys` marker still in the state directory. [Step 9](#restore-procedure-manual-separately-approved) is what removes it.

**Cycle B (a fresh attempt after step 9), all passed:**

- **Step 9:** the state directory and the retained encryption files were preserved aside on every server.
- **Leftover controls:** the restored controls had no value files, so `create-control` refused them and removed them, as documented. Cleanup, fresh controls (readback and raw plaintext passed) and p0′ followed.
- **Enable round:** `enable` and the enable restart round in order. `configured-disabled` validation passed.
- **Removal round:** `s3r01` was removed, and the round then stopped at `s3r02` (defect 2). After the correction, an evaluation of the paused state with the corrected role passed `s3r02`'s preconditions with `flag_state=absent` and refused them with `flag_state=present`. It ran read-only, changing nothing.
- **Resume:** the round resumed from the recorded prefix: `s3r02`, then `s3r03`. `s3r01` was not repeated; its K3s process was unchanged.
- **Final state:** all three servers without the drop-in and `Disabled, no configuration file found`. Enforced `not-configured` validation passed with no health or preservation problem, and etcd was 3/3 healthy.
- **Data:** the controls matched their pre-removal digests byte for byte in the API and raw etcd and stayed plaintext. Cleanup then removed every canary from the API and raw etcd.

**Process, restart and boot observations (systemd):**

- **Boots:** no server rebooted after bootstrap; every boot ID was unchanged to the end.
- **Restarts:** K3s restarted only in planned restarts. `NRestarts` stayed 0 on every server throughout, including across every manual restart and both restores.
- **Status:** after `enable`, status was unreadable on every server until `s3r01` restarted. Each server then switched to `Disabled`, `start` only after its own restart; until then the other two reported `Disabled, no configuration file found`. Hashes matched only after all three had restarted, in both rounds. After rotation, the peers kept `Disabled`, `start` until their own restart.
- **Stop status:** in both planned concurrent stops, **every server stopped with exit status 0** (`Result=success`).
- **Reset flag:** the flag was still present when S1 first reported Ready after its normal start, and was gone about a minute later.

**Fail-closed results:** 15 named refusals and 3 more:
- **Named:** 8 guard refusals, the replayed etcdctl confirmation, 3 refusals during the incomplete enable round, the replayed `s3r01`, the skipped `s3r03`, and the second rotation.
- **Others:** blocked enforced validation during the round, the restored controls without value files, and the uncorrected removal round's `s3r02`.

Every refusal stopped before any restart, and none changed anything other than its ledger entry.

**Memory gate:** the host kept at least 24 GB free before cloning and met each per-VM start threshold. One early pre-clone check stopped at 22.64 GB, before any clone, until memory was freed. All 34 safety-gate runs during the rehearsal passed. Each run checked the free-memory floor, the exact running-VM set, unchanged live and base VM configuration and unchanged live inventories; the lowest free memory was 18.14 GB.

**Cleanup and live-asset preservation:**

- **Evidence first:** the sanitized evidence was saved before teardown.
- **VMs:** each rehearsal VM was verified by its exact recorded path, folder, display name and recorded network identity, and checked against the list of protected live and base VMs. Each was then stopped, with a soft stop that succeeded every time, and deleted by that exact path.
- **Leftovers:** each folder's only leftover was its own serial-console file. That exact file was deleted, then the empty folder; nothing was deleted recursively.
- **Controller:** the rehearsal work folder was removed, and no rehearsal host key remained.
- **Live assets, unchanged:** the live servers' and the other VMs' configuration files, the base image and its lock, and both live inventories, compared by SHA-256.
- **Afterwards:** only the three live servers were running.
- **Not contacted:** no live server, cloud service or other repository.

**Evidence:** `stage3-vm-rehearsal-evidence-20261027.tar.gz`, 208 files, 132,209 bytes, SHA-256 `078219c49d7572bab3f128cefd6496f3e94536349fb97490e8c83c549bf2ab80`. It holds metadata only and was scanned for secret material before it was saved. It is retained in private, unsynchronized local operator storage outside the repository.

The Flux and workload acceptance checks were **not applicable** in this rehearsal (the gate relaxations above) and are not claimed as passed. The rehearsal **is not approval**: the live rollout still needs its own approval. Drop-in removal before activation was approved for live separately, by the reviewed change that lists it in `secrets_encryption_rehearsal_approved_paths`.

### Rehearsal questions

1. Does `k3s secrets-encrypt enable` work on an existing `v1.36.4+k3s1` cluster without encryption configuration? What does `status` show after it, and after the first restart of each server? *Partly observed (k3d, historical; not the live expectation):* `enable` exits 0 with the exact documented output. `status` then fails on every server until `k3s01` restarts with the drop-in. After that single restart it is readable on every server as `Disabled`, `start`, with matching hashes. *Observed in the [three-VM record](#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed), under systemd:* status was unreadable on every server until the first server restarted. Each server then reported `Disabled`, `start` only after its own restart, and until then the others reported `Disabled, no configuration file found`. Hashes matched only after all three had restarted.
2. Does `secretbox` as the configured provider work with the existing-cluster path (does `rotate-keys` generate an `XSalsa20-POLY1305` key)? *Observed (three-VM):* yes. One `rotate-keys` ended `Enabled`, `reencrypt_finished`, with an `XSalsa20-POLY1305` key.
3. Does the order of the "restart all servers" steps matter, and does a peer report matching hashes only after its own restart? *Observed (three-VM):* in both rounds, hashes matched only after every server had restarted, and each peer's own status changed only with its own restart. The fixed order was enforced; out-of-order, skipped and replayed restarts were refused.
4. Does `rotate-keys` finish within the CLI's 90-second timeout for this cluster's Secret count? If not, does the server finish on its own, as the polling assumes? *Observed (three-VM, few Secrets):* the rotation run reached `reencrypt_finished` without hitting a timeout. The CLI's own duration was not measured, so behavior for a larger Secret count stays open.
5. Which stage does `status` report after `disable`, and is it settled? *Observed:* `Disabled`, `reencrypt_finished`, settled. `disable` is no longer part of the procedure (see [Rollback](#rollback)).
6. Is removing the drop-in safe at the one point where the automation allows it (step 2 complete, before step 3)? *Observed (three-VM):* the removal itself was safe: every server stayed healthy, and nothing restarted unplanned. The first implementation refused the second server and was corrected in `825b09b`. The round then resumed from its recorded prefix and completed, ending `Disabled, no configuration file found` on all three with the controls unchanged. It is listed in `secrets_encryption_rehearsal_approved_paths` for live use.
7. Does the pre-enable snapshot p0 restore with the matching token, through the official HA sequence, onto servers whose drop-in has been moved aside? Must the encryption configuration file be moved aside first? Do S2 and S3 rejoin after their database directories are moved aside? After the restore, are the plaintext controls back byte-for-byte, the post-enable canaries absent and the status not-configured? Does a post-rotation snapshot restore with its encryption keys? *Observed in disposable k3d (restore diagnostic and run 8, after a real rotation):* the explicit reset restores p0, S2 and S3 rejoin, the plaintext controls return byte-for-byte, the post-enable canaries are absent, and the status returns to not-configured with the encryption files retained, so they need not be moved aside for the restore itself. *Observed in the [three-VM record](#three-vm-rehearsal-record-2026-10-27-commit-825b09b-passed), under systemd:* the same sequence restored p0 with every acceptance criterion, and the retained encryption files kept their inode, size and modification time. A post-rotation snapshot (p2) restored: a Secret written before p2 read back and stayed encrypted, and a later Secret was rolled back, with the servers' encryption files retained. Whether a snapshot alone restores the key onto servers without those files remains open (see [Key material](#key-material-and-the-off-node-recovery-copy)).
8. Do pods keep running across `systemctl restart k3s`? Does `NRestarts` stay unchanged on a manual restart, as the post-restart gate assumes? *Observed (three-VM):* At every post-operation health check, the workload pods were Running. The K3s service NRestarts value remained 0 through all planned restarts and both restores. *Observed (live, 2026-10-28):* no. A planned restart reset a nonzero counter to 0, because systemd resets `NRestarts` on an explicit restart; it stays unchanged only when it is already 0. The post-restart gate now expects exactly that (see [Restart order and checkpoints](#restart-order-and-checkpoints)).
9. Does the status text match the parser exactly, including the key-name format? *Observed (three-VM):* yes. Every readable status parsed, including the `XSalsa20-POLY1305` key lines; only the documented unavailable result occurred during the enable round.
10. Do the raw positive controls behave as designed: plaintext ConfigMap, plaintext pre-encryption Secret, then encrypted post-encryption and rewritten Secrets? Does `etcdctl get --write-out=json` on v3.6.14 return exactly the fields the verifier expects? *Observed (three-VM):* yes, both. The plaintext controls, the encrypted post-encryption Secret and the rewritten pre-encryption Secret all verified as designed with the pinned etcdctl v3.6.14.
11. Does `k3s etcd-snapshot save --name <name>` from the CLI apply retention with the CLI's name, or with the server's configured snapshot name? Does it prune anything else, locally or (if configured) in S3? Snapshot S3 upload is assumed not configured before Stage 4. *Partly observed (three-VM):* every snapshot passed the preservation checks, so no recorded snapshot disappeared. Which name retention uses was not examined and stays open.
12. Which rollback paths behave as documented? *Answered for secretbox:* the documented in-place rollback (disable, restarts, `reencrypt --force --skip`) does not work. `reencrypt` is rejected, so it was removed. Drop-in removal before activation completed in the three-VM rehearsal (question 6), and the snapshot restore passed under systemd (question 7). Drop-in removal is listed there for live use.

## Tests

```bash
python3 ansible/tests/secrets_encryption_expressions.py
```

The test contacts no node, API, etcd or AWS, and downloads nothing. It runs in six parts.

**1. Structure checks:**

- every mutating playbook's targeting, serial and fail-fast settings;
- no automatic fact gathering, and the guard imported first without privilege escalation, before facts;
- guard-then-gate order;
- no handlers, and a single explicit K3s restart;
- the fixed restart order and the verified checkpoint;
- each `secrets-encrypt` subcommand only in its own phase, and no status read in `enable.yml`;
- the rollback model:
  - no phase runs `secrets-encrypt disable`, `reencrypt`, `prepare` or `rotate`, and no rollback phase or playbook exists, so R1 and R2 alone can never be reported as a rollback;
  - drop-in removal is allowed only before activation;
  - `enable` requires the recorded p0 as the newest Stage 3 snapshot, taken by the last accepted invocation, and the enabling rotation requires a recorded p0 and a consistent ledger;
  - the server token file is inspected by `lstat` only (no checksum, MIME type or content), and the checkpoint record has a fixed format with `token=present`;
  - `configured-disabled` validation requires the last change to be `enable`, while the parser still maps `Disabled`;
  - `rotate-keys` runs only after `enable` or a completed rotation and always ends `Enabled` with secretbox, so it is never a plaintext rollback;
  - the restore procedure for the real servers invokes `k3s server --cluster-reset --cluster-reset-restore-path` explicitly and never delivers the reset through configuration-file fields; the k3d runner is described only as rehearsal tooling;
  - the reset is accepted only with exit status 0, the documented message (logged at ERROR level) and the reset flag together;
  - the retained encryption files are not treated as proof of active encryption; status, readbacks and raw records decide;
  - the k3d restore records S1's network identity, refuses before shutdown when it cannot be rebuilt, checks that the address is free before the runner attaches and before S1 reconnects, keeps S1's container and volumes, stops the servers concurrently with a bound, uses two event collectors, and reports numeric exit statuses;
  - this document records the unsupported in-place conversion, that `disable` is not accepted or used, the full-state impact of a restore with its operator acknowledgment, the p0 definition, the official restore sequence including S2 and S3, the restore acceptance criteria and that static tests are not Stage 3 completion, and names no R1 or R3 playbook;
  - the live rollout record is sanitized and complete, with its commits, checkpoints, evidence manifests, the counter defect and the claims it does not make. The post-rotation Secret-decode window is part of the procedure and its stop conditions. No document still calls the rollout unperformed or Secrets unencrypted, and none claims a live restore or live raw checks;
- the exact `enable` result checked before the marker is written;
- the post-round status validation before the `k3s03` restart is recorded as verified;
- the `unavailable` status tolerated only inside the enable restart round, with no variable that enables it;
- the exact single-key, local-only, time-bounded etcdctl query piped only into the verifier;
- the installer's check-before-install order;
- no cluster reset, restore, rejoin, snapshot deletion or prune, `ignore_errors`, file removal outside the drop-in and canary values, or reads of Secrets, tokens, the encryption configuration, addresses or JSON/YAML object dumps;
- root-owned, link-replacing state files;
- `no_log` on every task that can carry a status, canary value, readback or raw etcd record;
- the pins;
- the safe defaults for `k3s-server` and `site.yml`.

**2. Verifier unit tests:** exact-key enforcement and range, prefix, multi-record, missing, malformed, oversize and wrong-provider rejection, with real exit codes.

**3. `ansible-playbook --syntax-check`** of every playbook and of every role task file.

**4. Guard runs.**

- **Refused invocations** run the real phase playbooks against throwaway inventories. They must fail inside the guard, before facts or any other task. The cases cover:
  - every unsafe limit form;
  - wrong, stale, future, malformed, other-phase and other-host confirmations;
  - environment and inventory mismatches, including a rehearsal declared for the live inventory;
  - overridden pins and approvals;
  - relaxed live gates;
  - missing protected artifacts;
  - not-yet-approved drop-in removal, and attempts to inject its approval or a removed rollback phase;
  - injected round, status or server-state facts.
- **Allowed invocations** run the real header and guard.

**5. Role scenarios on localhost, against mocked results and local stand-ins.** Every expected failure must fail at the named task.

- status parsing, including fail-closed cases and the narrow `unavailable` result;
- the health gate, with every failure class;
- the enable restart round: tolerated only in order, in the restart phase, with the marker, ledger and pre-enable checkpoint consistent; refused for a stale marker, a missing ledger entry or checkpoint, a skipped, out-of-order, partial or replayed restart, another phase, any other status failure, and after the round has completed;
- the exclusive enable restart round:
  - before S1 with an unavailable status, after S1 or S2 with a readable and settled status, after S3's restart before its verified record, and after an interrupted restart, only the next server's restart passes;
  - every other phase is refused: snapshots, canaries, rotation, drop-in removal, a repeated `enable`, the etcdctl installation, and enforced validation;
  - replayed, skipped and out-of-order restarts stay refused;
  - readable converged status without the durable verified records is not completion;
  - after completion the next phases pass the round gate, and rotation meets its prerequisites;
  - a stale marker, an inconsistent or malformed ledger, a missing pre-enable checkpoint or an interrupted rotation fail closed;
- `enable` with a stub k3s: the exact result is mandatory, a failed or unexpected result writes no marker, and no status is read afterwards;
- p0: `enable` is refused when the newest Stage 3 snapshot is not p0, is not recorded, has a different size from its record, when the records are malformed, or when another invocation followed the snapshot; the token check passes for a root-owned stand-in file and fails for a missing, empty or linked one; `configured-disabled` validation fails after activation;
- the post-round validation with a stub k3s: `Disabled`, `start` and matching hashes pass; an unavailable status, a mismatch, `Enabled` or no configuration fail, and the restart is not recorded as verified;
- preservation of protected artifacts and freshness;
- snapshot metadata comparison;
- every phase decision, including rotation refused before the post-round validation;
- the restart order;
- the post-restart restart counters: a restart by the run resets the target's nonzero counter to 0 and passes; a target counter above 0 after it, an unreadable one, or any change on another server fails; a run without a restart passes only with every counter unchanged;
- confirmation replay;
- state-directory and ledger link safety, with real `lstat`;
- the drop-in;
- `k3s-server` on fresh, existing and replacement servers;
- the etcdctl installer's extracted-binary checks and cleanup;
- the raw verification pipeline, with a stub etcdctl;
- the canary lifecycle, with a stub k3s: success, failure and interruption.

**6. Mutation tests.** Each mutant is a copy of the role's task files with one change that reintroduces a defect: the post-enable status assertion, a relaxed or removed enable-result check, the marker written before the check, the tolerance without the round, the round without its order, ledger or checkpoint conditions, the target check removed, the post-round validation removed, the exclusive round lock removed or weakened (readable status counted as completion, drop-in removal admitted, an inconsistent completed round trusted, the lock lifted early), validation without the round, the enabling rotation without the pre-enable snapshot, `enable` without the p0 requirement, the token inspected with a checksum, the round accepting an unrecorded snapshot, `configured-disabled` accepted after activation, `rotate-keys` accepted as a plaintext rollback after a disable, or drop-in removal after a rollback re-encryption. The structure checks also catch a reintroduced `reencrypt --force --skip` task, a reintroduced `disable` phase, a rollback playbook, and documentation that names one. They also catch documentation that delivers the reset through configuration-file fields, presents the Docker runner as a recovery method for the real servers, accepts a reset without exit status 0, the documented message and the reset flag together, or treats retained encryption files as active encryption. The same applies to a k3d restore that drops the free-address checks, lets S1's container or volumes be recreated, keeps S1 attached while the runner runs, reconnects S1 before the runner is removed, or stops the servers one after another. Each mutant is run against the same scenario as the regression test it targets, and must change the outcome; a surviving mutant fails the suite. The structure checks are also re-applied to mutated copies and must detect them.

Finally, the complete output is scanned for every canary value, raw etcd record, hash-mismatch node name and protected path.

Static tests do not show K3s behavior, and passing them is not Stage 3 completion. The rehearsal records hold what has been observed; the [rehearsal questions](#rehearsal-questions) record which answers they settled and which stay open.
