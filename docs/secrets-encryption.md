# Secrets Encryption at Rest (Phase 7, Stage 3)

## Status

The automation for enabling Kubernetes Secrets encryption at rest is **implemented and statically tested only**:

- It has **not** been rehearsed. Neither the required three-server k3d rehearsal nor the three-VM rehearsal has run.
- It has **not** been run against the live cluster.
- Nothing in this repository has changed the live cluster's encryption state, which remains disabled.
- [`site.yml`](../ansible/site.yml) does not run any of it.

Until the rehearsals pass, every statement below about K3s behavior is the documented or source-code behavior of K3s `v1.36.4+k3s1`, not observed behavior.

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
| **1. Configuration enablement** | `k3s secrets-encrypt enable` on S1 (on a cluster without encryption configuration), then the `secrets-encryption: true` drop-in on every server | Every server, S1 first | K3s writes an **identity-only** configuration. Nothing is encrypted, and no Secret is rewritten. Status: `Disabled`, stage `start`. |
| **2. Activation for new writes** | `k3s secrets-encrypt rotate-keys` on S1 | Every server afterwards, S1 first | Generates a secretbox key and puts it first. From then on, every Secret written is stored encrypted. |
| **3. Rewriting existing Secrets** | Part of the same `rotate-keys` call: K3s re-encrypts every Secret, about 5 per second, before reporting `reencrypt_finished` | — | Every existing Secret is written again, so its **current** etcd record becomes encrypted. Resource versions change and watches fire. |
| **4. Key rotation** | A later `rotate-keys` | Every server afterwards, S1 first | New key; every Secret rewritten; the retired key removed. **The approved procedure performs no rotation beyond step 2** (see [Exactly One Rotation](#exactly-one-rotation)). |
| **5. Decryption and disable (rollback)** | `k3s secrets-encrypt disable` on S1, restarts, then `k3s secrets-encrypt reencrypt --force --skip` on S1 | After `disable`, every server, S1 first | New writes are stored in plaintext. Existing Secrets stay encrypted, and readable, until the forced re-encryption rewrites them in plaintext. |

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
- requires, for every rotation, a new confirmation naming the current UTC time (`secrets_encryption_rotation_id=YYYYMMDDTHHMMSSZ`, at most 30 minutes old). Each confirmation is recorded in a ledger on the first server before the rotation starts and is never accepted again.

## Encoded Procedure

`S1` is the first server, `k3s01`. Every step is a separate invocation, with an exact one-host `--limit` and its own confirmation.

| Step | K3s procedure | Playbook | Expected status afterwards |
| --- | --- | --- | --- |
| 0 | Recovery point | `snapshot-etcd.yml --limit k3s01` | Unchanged |
| 1 | Verify encryption is disabled; `k3s secrets-encrypt enable` on S1 | `secrets-encryption-enable.yml --limit k3s01` | S1: `Disabled` |
| 2 | Restart all servers with `--secrets-encryption` | `secrets-encryption-restart.yml`, once per server: `k3s01`, `k3s02`, `k3s03` | All: `Disabled`, `start`, all hashes match |
| 3 | `k3s secrets-encrypt rotate-keys` on S1 | `secrets-encryption-rotate.yml --limit k3s01` | S1: `Enabled`, `reencrypt_finished`, active key `XSalsa20-POLY1305` |
| 4 | Restart all servers with the same arguments | `secrets-encryption-restart.yml`, once per server: `k3s01`, `k3s02`, `k3s03` | All: `Enabled`, `reencrypt_finished`, all hashes match |

Rollback (disable):

| Step | K3s procedure | Playbook |
| --- | --- | --- |
| R1 | `k3s secrets-encrypt disable` on S1 | `secrets-encryption-disable.yml --limit k3s01` |
| R2 | Restart S1, then S2 and S3, same arguments | `secrets-encryption-restart.yml`, once per server: `k3s01`, `k3s02`, `k3s03` |
| R3 | `k3s secrets-encrypt reencrypt --force --skip` on S1 | `secrets-encryption-reencrypt.yml --limit k3s01` |

**Rollback is not yet rehearsal-approved.** Several of its details are open [rehearsal questions](#rehearsal-questions): the stage after `disable`, the restarts it needs, and whether removing the drop-in is safe. In a live environment, the guard therefore refuses each of these, with "not yet rehearsal-approved", rather than run a guessed procedure:

- `secrets-encryption-disable.yml` (R1);
- `secrets-encryption-reencrypt.yml` (R3);
- drop-in removal (`-e secrets_encryption_flag_state=absent` on the restart playbook).

A rehearsal environment may run them, to produce the rehearsal record. Each becomes available live only through a reviewed change that adds it to `secrets_encryption_rehearsal_approved_paths` in the role's vars, citing that record. An extra-vars override of that list is refused, like every other committed value.

The documented disable procedure keeps the server arguments. Drop-in removal is not part of the K3s procedure. The automation permits it only when every server reports `Disabled`, after step 1 or after R3.

The disable (R1) and the plaintext re-encryption (R3) are separate phases, each with its own confirmation.

**Restart order.** The documentation's HA tabs say "restart all servers" for steps 2 and 4 without an order, and "S1 first, then S2 and S3" for key rotation and disable. The automation uses one fixed order for every restart round, `k3s01`, `k3s02`, `k3s03`, which is the inventory order the live guard requires. Each server is refused until every server before it has restarted after the last change and passed its post-restart gate.

## Implementation

### Files

| Path | Purpose |
| --- | --- |
| [`roles/secrets-encryption/`](../ansible/roles/secrets-encryption) | The phases as separate task files; no default entry point |
| [`snapshot-etcd.yml`](../ansible/snapshot-etcd.yml) | On-demand checkpoint snapshot on the first server |
| [`secrets-encryption-enable.yml`](../ansible/secrets-encryption-enable.yml) | Step 1 |
| [`secrets-encryption-restart.yml`](../ansible/secrets-encryption-restart.yml) | Steps 2, 4 and R2: one server per run |
| [`secrets-encryption-rotate.yml`](../ansible/secrets-encryption-rotate.yml) | Step 3 |
| [`secrets-encryption-canary.yml`](../ansible/secrets-encryption-canary.yml) | Canary controls, verification and cleanup |
| [`secrets-encryption-disable.yml`](../ansible/secrets-encryption-disable.yml) | R1 |
| [`secrets-encryption-reencrypt.yml`](../ansible/secrets-encryption-reencrypt.yml) | R3 |
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
   - **Limit:** `--limit` is exactly one inventory host name: no pattern, group, list, regex or exclusion, even one that resolves to a single host. Phases on the first server require that host to be `groups['servers'][0]`.
   - **Confirmation:** `secrets_encryption_confirm` is `<phase>:<target host>:<UTC time YYYYMMDDTHHMMSSZ>`, at most 30 minutes old and not in the future. A value for another phase or another host is refused. The phases are `snapshot`, `enable`, `restart`, `rotate-keys`, `canary-create-control`, `canary-verify`, `canary-cleanup`, `disable`, `reencrypt-after-disable` and `install-etcdctl`.
   - **Environment:** `secrets_encryption_environment` is declared. `live` is accepted only with the exact inventory `k3s01`, `k3s02`, `k3s03`, in that order. `rehearsal` is accepted only with three servers and no live host name anywhere in the inventory.
   - **Rehearsal-only work:** etcdctl installation and raw etcd verification are refused for any inventory or target containing `k3s01`, `k3s02` or `k3s03`, whatever environment is declared.
   - **Committed values:** every role var (pins, paths, live host list, approvals) equals the committed `vars/main.yml`; extra vars cannot override them. In a live environment, the gate defaults (Flux, HelmRelease, monitoring, canary, Chrony, freshness and free-space settings, raw verification off) must also equal the committed `defaults/main.yml`.
   - **Protected artifacts:** in a live environment, `secrets_encryption_protected_paths` names the preserved Stage 2 artifacts as absolute paths on known servers. Set it in local, uncommitted inventory.
   - **Rehearsal approval:** paths not yet rehearsal-approved are refused live (see [Encoded Procedure](#encoded-procedure)).
2. **Facts:** minimal fact gathering, only after the guard.
3. **Gate.** Read-only until every check has passed:
   - **Each server, through its own local API:** `k3s.service` is active at exactly `v1.36.4+k3s1`; local `/readyz` and `/readyz/etcd` are `ok`; `secrets-encrypt status` parses and is in a settled stage (`start` or `reencrypt_finished`), never during re-encryption or in a legacy stage; Chrony is synchronized with an offset below 100 ms; swap is unchanged since the baseline; free space is sufficient; the state directory and its files are root-owned regular paths, not symbolic links.
   - **Cluster:** exactly the three servers are nodes, each once, Ready and without memory, disk or PID pressure, and exactly those three carry the etcd role. The six Flux Kustomizations are present once and Ready, and every Kustomization present is Ready. At least two HelmReleases exist, all Ready. Every Deployment, StatefulSet and DaemonSet is fully ready; the monitoring namespaces hold their StatefulSets and DaemonSets; `platform-demo/platform-canary` is fully available.
   - **Fail closed:** empty, missing, null, duplicated or unparsable results are failures.
   - **Preservation:** every protected Stage 2 artifact exists and is unchanged, and no recorded on-demand snapshot or database directory has disappeared (see [Snapshots and preservation](#snapshots-and-preservation)).
   - **Snapshot:** a Stage 3 snapshot on the first server is at most 120 minutes old. For rotate, disable and the rollback re-encryption, it must also be newer than the last recorded change.
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

The role records each procedure change (`enable`, `rotate-keys`, `disable`, `reencrypt-after-disable`) with its time in `last-change` on the first server. It records each drop-in change on the server concerned, in `dropin-change`. After each restart's post-restart gate passes, the server records `restart-verified`.

A server reaches the checkpoint of the last change when both hold:

- `k3s.service` became active after the later of the last procedure change and its own last drop-in change;
- `restart-verified` was recorded after that.

[`secrets-encryption-restart.yml`](../ansible/secrets-encryption-restart.yml):

- refuses while any server is re-encrypting or in an unsettled stage;
- enforces the fixed order `k3s01`, `k3s02`, `k3s03`. A server is refused until every server before it has reached the checkpoint with the requested drop-in state;
- restarts nothing if the target already runs with the current configuration (a no-op that only repeats the post-restart gate and its record);
- contains the role's only K3s restart, an explicit `systemd_service` task. No handler restarts K3s.

After the restart it waits for:

- the service;
- the local API and etcd readiness;
- the node to be Ready.

It then re-runs the full gate and fails if any server's automatic restart counter (`NRestarts`) changed. Only then does it record `restart-verified`.

### Status parsing without exposure

`k3s secrets-encrypt status` output is read with `no_log` and reduced to allowlisted fields:

- `encryption`
- `stage`
- `hashes_match` (a boolean)
- `key_count`
- `active_key_type`
- `active_key_name`

Every line must be recognized, and every field must appear exactly once where required, or the result is "not parsed" and every gate fails closed. The hash line names nodes when hashes differ; only the boolean is kept. No encryption hash, raw status, node annotation (which carries the encryption hash), Secret, token or encryption configuration is read into or printed by Ansible.

### Snapshots and preservation

[`snapshot-etcd.yml`](../ansible/snapshot-etcd.yml) runs `k3s etcd-snapshot save --name stage3-<checkpoint>-<UTC time>` on the first server.

**Retention.** In K3s v1.36 (`pkg/etcd/snapshot.go`), a successful save is followed by local retention pruning. It removes the oldest of the files whose names *start with* the snapshot name, beyond `--etcd-snapshot-retention`. The automation refuses a name that any existing file already starts with. That pruning can therefore only ever see the new file.

Whether a CLI save prunes with the CLI's `--name` or with the server's configured snapshot name is a [rehearsal question](#rehearsal-questions). Preservation is therefore checked, not assumed:

- **Before and after the save:** the size and time of every non-scheduled snapshot file are compared. Any missing or changed file stops the run. Changes among scheduled snapshots (`etcd-snapshot-*`), which K3s prunes by its own retention, are reported separately as scheduled retention and are not Stage 3 deletions.
- **After the save:** the full preservation gate runs again, including the protected Stage 2 artifacts.
- **Record:** the name, size, time and SHA-256 of the new snapshot file are recorded (decision D4). The file is never read into Ansible.

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

## Live Rollout (Not Yet Approved)

Prerequisites:

1. Both rehearsals have passed and are recorded, with their answers to the [rehearsal questions](#rehearsal-questions).
2. This branch is merged.
3. The live run is separately approved.

Run from `ansible/`. `secrets_encryption_protected_paths` must be set in local, uncommitted inventory: the absolute paths of the preserved Stage 2 database directories and snapshot files on each server.

Every command needs a new confirmation naming its phase, its host and the current UTC time; `c` below builds one. After every restart:

- wait at least 10 minutes;
- run `validate-secrets-encryption.yml` and `validate-time-sync.yml -e time_sync_enforce_acceptance=true`;
- keep the LAN canary monitor running throughout.

```bash
E="-e secrets_encryption_environment=live"
c() { echo "secrets_encryption_confirm=$1:$2:$(date -u +%Y%m%dT%H%M%SZ)"; }

# 0. Baseline and recovery point
ansible-playbook validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=not-configured
ansible-playbook snapshot-etcd.yml --limit k3s01 $E -e "$(c snapshot k3s01)" -e secrets_encryption_snapshot_checkpoint=p0-pre-enable
ansible-playbook secrets-encryption-canary.yml --limit k3s01 $E -e secrets_encryption_canary_action=create-control \
  -e "$(c canary-create-control k3s01)"

# 1. Configuration enablement
ansible-playbook secrets-encryption-enable.yml --limit k3s01 $E -e "$(c enable k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s01 $E -e "$(c restart k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s02 $E -e "$(c restart k3s02)"
ansible-playbook secrets-encryption-restart.yml --limit k3s03 $E -e "$(c restart k3s03)"
ansible-playbook validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=configured-disabled

# 2-3. Activation and rewrite (the one rotation)
ansible-playbook snapshot-etcd.yml --limit k3s01 $E -e "$(c snapshot k3s01)" -e secrets_encryption_snapshot_checkpoint=p1-pre-rotate
ansible-playbook secrets-encryption-rotate.yml --limit k3s01 $E -e "$(c rotate-keys k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s01 $E -e "$(c restart k3s01)"
ansible-playbook secrets-encryption-restart.yml --limit k3s02 $E -e "$(c restart k3s02)"
ansible-playbook secrets-encryption-restart.yml --limit k3s03 $E -e "$(c restart k3s03)"

# Verification and the post-change recovery point
ansible-playbook validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=enabled
ansible-playbook secrets-encryption-canary.yml --limit k3s01 $E -e secrets_encryption_canary_action=verify -e "$(c canary-verify k3s01)"
ansible-playbook snapshot-etcd.yml --limit k3s01 $E -e "$(c snapshot k3s01)" -e secrets_encryption_snapshot_checkpoint=p2-post-encryption
```

Also confirm that existing Secrets still decrypt, without printing any of them:

- `helm list -A` succeeds;
- Flux reconciles;
- the Grafana login works.

The restart order is fixed: `k3s01`, `k3s02`, `k3s03`.

### Stop conditions

Stop immediately, and do not run another step, if:

- any playbook fails;
- quorum is lost, or etcd readiness fails on any server;
- a node is not Ready, or a local API is not ready;
- a K3s service fails to start or restarts unexpectedly;
- a status is not parsed, a stage is unexpected, or hashes do not match where the table above expects them to;
- re-encryption does not finish within its timeout;
- any API error reads a Secret;
- a Flux Kustomization or HelmRelease is not Ready;
- the LAN canary monitor records failures;
- a canary check fails;
- any result differs from the rehearsal record;
- any unplanned host change happens during the window (the Stage 2 incident followed a host swap-state change).

## Rollback Decision Table

| Point reached | Rollback | Snapshot restore |
| --- | --- | --- |
| Before step 1 | Nothing to undo | No |
| Step 1 done, no restarts | Stop. The automation offers no live path here until the rehearsal approves one (`disable`, or drop-in removal). Data is unchanged. | No |
| Some servers restarted with the drop-in | Stop. If a server fails to start, keep the other two (quorum holds) and investigate manually; the automation does not change it further. **No rejoin while flags differ.** | No |
| Step 2 complete (`Disabled`, `start`) | Drop-in removal in the fixed order (`flag_state=absent`): refused live until rehearsal-approved | No |
| Step 3 running (`reencrypt_active`) | **Wait** for `reencrypt_finished`. Never restart during re-encryption. If it is stuck, stop and follow the K3s documentation; do not improvise. | Only if Secrets become unreadable and the documented path fails |
| Step 3 done, restarts incomplete | Go forward: finish the restarts in order | No |
| Step 4 complete | Disable procedure R1–R3: refused live until rehearsal-approved | No |
| Quorum lost and not recoverable by restarting members; Secrets unreadable after the documented disable fails; or etcd corruption | Cluster reset from the latest checkpoint snapshot whose server configuration matches, with `--token-file`. Peers' databases are moved aside and **preserved**, then rejoin with matching flags. Cluster reset is never part of this automation; it is the separately documented recovery procedure. | **Yes, last resort.** Writes after the checkpoint are lost. Flux re-applies Git; out-of-band objects do not return. Restoring a pre-enable snapshot onto servers with the drop-in has not been tested and must be rehearsed first. |

A snapshot restore is never the response to a single failed server (it rejoins) or to an unexpected stage alone. This automation contains no snapshot restore, cluster reset, database move or removal, or rejoin logic; those remain separately approved manual procedures.

**Key material:**

- **Where it lives:** the encryption configuration travels in K3s bootstrap data, which is encrypted with the server token. A snapshot restored with the matching token is therefore expected to bring its encryption keys with it. The rehearsal must confirm this before Stage 3 decides whether the configuration needs its own `age`-encrypted recovery copy.
- **If every copy is lost:** every Secret encrypted under the lost key is lost.

## Fresh Builds and Replacement Joins

[`roles/k3s-server`](../ansible/roles/k3s-server) has `k3s_secrets_encryption_enabled: false` by default.

**When true:**

- The role writes the same drop-in **only on a server where neither the K3s binary nor K3s data exists**, before K3s first starts.
- A new cluster then starts with secretbox encryption, the documented path for new servers.
- A replacement server joins with the critical arguments the cluster requires.

**On a server with K3s installed**, the role never writes or removes the drop-in, and never restarts K3s.

**Timing of the flip:**

- **Leave it false until the live procedure has completed.** Today's servers run without the flag, so a server built with it could not join them.
- **Set it to true in the follow-up template-flip PR afterwards.** Otherwise a rebuilt or replacement server could not join the encrypted cluster.

`site.yml` is unchanged by Stage 3.

## Rehearsals

### k3d (required before merge)

A disposable three-server k3d cluster at `rancher/k3s:v1.36.4-k3s1`. k3d nodes are containers, so the phase playbooks cannot drive them. The rehearsal executes the [encoded procedure](#encoded-procedure) step by step with `docker exec <server> k3s ...`:

- restarts are `docker restart <server>` in the fixed order, with each server confirmed ready before the next;
- etcdctl is the same pinned v3.6.14 binary, checksum-verified on the host, copied into the S1 container and used only on the canary keys through the same verifier;
- it records every server's parsed status and the restarts needed at each step;
- it covers the rollback (R1–R3);
- it restores pre- and post-rotation snapshots with the matching token.

### Three-VM Ubuntu (after k3d)

Three disposable VMs built with this repository's Packer image and playbooks, with an inventory that uses none of the live host names. This rehearsal exercises the real playbooks end to end:

- `-e secrets_encryption_environment=rehearsal`;
- `install-etcdctl-rehearsal.yml`, then raw verification;
- the gate settings relaxed where the rehearsal lacks Flux, HelmReleases, monitoring or the platform canary (`secrets_encryption_expected_kustomizations=[]`, `secrets_encryption_min_helmreleases=0`, `secrets_encryption_monitoring_namespaces=[]`, `secrets_encryption_canary_deployment=""`). The guard refuses these relaxations in a live environment;
- systemd restart behavior, waits, gates, idempotent reruns and cleanup.

### Rehearsal questions

1. Does `k3s secrets-encrypt enable` work on an existing `v1.36.4+k3s1` cluster without encryption configuration? What does `status` show after it, and after the first restart of each server?
2. Does `secretbox` as the configured provider work with the existing-cluster path (does `rotate-keys` generate an `XSalsa20-POLY1305` key)?
3. Does the order of the "restart all servers" steps matter, and does a peer report matching hashes only after its own restart?
4. Does `rotate-keys` finish within the CLI's 90-second timeout for this cluster's Secret count? If not, does the server finish on its own, as the polling assumes?
5. Which stage does `status` report after `disable`, and is it settled?
6. Is removing the drop-in safe at the two points where the automation allows it?
7. Does restoring a snapshot with the matching token alone recover the encryption keys? Does a pre-enable snapshot restore onto servers that carry the drop-in? Do pre- and post-rotation snapshots both restore?
8. Do pods keep running across `systemctl restart k3s`? Does `NRestarts` stay unchanged on a manual restart, as the post-restart gate assumes?
9. Does the status text match the parser exactly, including the key-name format?
10. Do the raw positive controls behave as designed: plaintext ConfigMap, plaintext pre-encryption Secret, then encrypted post-encryption and rewritten Secrets? Does `etcdctl get --write-out=json` on v3.6.14 return exactly the fields the verifier expects?
11. Does `k3s etcd-snapshot save --name <name>` from the CLI apply retention with the CLI's name, or with the server's configured snapshot name? Does it prune anything else, locally or (if configured) in S3? Snapshot S3 upload is assumed not configured before Stage 4.
12. Which of the rollback paths (disable, rollback re-encryption, drop-in removal) behave as documented, and may therefore be listed in `secrets_encryption_rehearsal_approved_paths`?

## Tests

```bash
python3 ansible/tests/secrets_encryption_expressions.py
```

The test contacts no node, API, etcd or AWS, and downloads nothing. It runs in five parts.

**1. Structure checks:**

- every mutating playbook's targeting, serial and fail-fast settings;
- no automatic fact gathering, and the guard imported first without privilege escalation, before facts;
- guard-then-gate order;
- no handlers, and a single explicit K3s restart;
- the fixed restart order and the verified checkpoint;
- each `secrets-encrypt` subcommand only in its own phase;
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
  - not-yet-approved rollback paths.
- **Allowed invocations** run the real header and guard.

**5. Role scenarios on localhost, against mocked results and local stand-ins.** Every expected failure must fail at the named task.

- status parsing, including fail-closed cases;
- the health gate, with every failure class;
- preservation of protected artifacts and freshness;
- snapshot metadata comparison;
- every phase decision;
- the restart order;
- confirmation replay;
- state-directory and ledger link safety, with real `lstat`;
- the drop-in;
- `k3s-server` on fresh, existing and replacement servers;
- the etcdctl installer's extracted-binary checks and cleanup;
- the raw verification pipeline, with a stub etcdctl;
- the canary lifecycle, with a stub k3s: success, failure and interruption.

Finally, the complete output is scanned for every canary value, raw etcd record, hash-mismatch node name and protected path.

Static tests do not show K3s behavior. Everything in [Rehearsal questions](#rehearsal-questions) remains to be shown.
