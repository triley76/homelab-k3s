# etcd Snapshot Uploads to S3 (Stage 4)

## Status

**Status: S4-1, static tests only.** The `etcd-s3` role, its five playbooks and their tests exist. Nothing has run against a node, a VM, a rehearsal endpoint or AWS. No access key exists, and the Stage 1 stack still has the condition that K3s cannot use. Nothing here is rehearsed, and no server uploads anything.

The design is Stage 4 of the home-cluster backup and disaster recovery design (`docs/design/backup-disaster-recovery.md` in home-cluster, decisions D1 to D7 and the S4-1 decisions). The AWS side of each step is in its runbook, `docs/runbooks/etcd-s3-uploads.md` in home-cluster. The next gate is S4-2, the k3d rehearsal against MinIO; every gate needs its own approval.

## What it configures

K3s's built-in S3 support uploads each snapshot right after it is written locally. Each server gets one drop-in, `/etc/rancher/k3s/config.yaml.d/30-etcd-s3.yaml`:

| Setting | Value | Source |
| --- | --- | --- |
| `etcd-snapshot-name` | `etcd-snapshot-s4-<host>` | D1 |
| `etcd-snapshot-retention` | `5` (local) | D1 |
| `etcd-s3-folder` | `etcd`, shared by all servers | D1 |
| `etcd-s3-retention` | `5` (in S3, per server) | D1 |
| `etcd-snapshot-schedule-cron` | `0 */12 * * *` | D4 |
| `etcd-snapshot-compress` | `false` | D4 |
| `etcd-s3`, `etcd-s3-region`, `etcd-s3-endpoint` | `true`, `us-east-1`, `s3.amazonaws.com` | D4 |
| `etcd-s3-bucket-lookup-type`, `etcd-s3-timeout` | `auto`, `5m0s` | D4 |
| `etcd-s3-proxy` | Unset, or `none` if the preflight finds proxy variables | D4 |
| `etcd-s3-bucket`, `etcd-s3-access-key`, `etcd-s3-secret-key` | From the operator's files | D3 |

The fixed values are role vars in [`roles/etcd-s3/vars/main.yml`](../ansible/roles/etcd-s3/vars/main.yml). The guard compares every one of them with the committed file, so neither inventory nor extra vars can change them.

**Object keys.** `etcd/etcd-snapshot-s4-<host>-<host>-<unix time>`, with K3s's own node suffix after the base, and `etcd/on-demand-s4-<host>-<host>-<unix time>` for on-demand uploads.

### The K3s behavior it relies on (v1.36.4+k3s1 source)

| Behavior | How the role handles it |
| --- | --- |
| **Retention is a plain string prefix with no node filter**, locally and in S3 | Each server's bases are built from its inventory host name, which must be its node name. The guard refuses an inventory in which any server's scheduled or on-demand base is a string prefix of another's (for example `node1` and `node10`). On a first configuration, no local file may already start with a new base. |
| **Reconciliation lists the whole folder and deletes records it cannot see** | The folder is fixed to `etcd` for every server; any other value, including a per-node folder, is refused. |
| **Every new S3 client sends `HEAD` on the bucket, with no prefix** | Needs D2's `StringLikeIfExists` condition, deployed at gate 9. Until then, any upload attempt fails. |
| **Server-side S3 settings are read only at startup** | [`configure-etcd-s3.yml`](../ansible/configure-etcd-s3.yml) writes the drop-in and proves it with an on-demand upload, but does not restart. Scheduled uploads begin only after [`restart-etcd-s3.yml`](../ansible/restart-etcd-s3.yml), one server at a time. CLI saves read the drop-in on every run, which is how a rotated key is proved before the restarts. |
| **K3s stores a short token hash** as a snapshot annotation and as S3 object metadata | Nothing reads either. The probe returns only counts, booleans and times from `ETCDSnapshotFile` records; no record, annotation or object metadata is ever displayed. |
| **CLI saves without `--name` use the shared default `on-demand`** | Every save the role runs passes `--name on-demand-s4-<host>`, so retention applies per server. No other name can be passed; `etcd_s3_ondemand_name` is a reserved variable. |
| **The bucket name appears in K3s's output and journal** | The save and the restart run with `no_log`. The bucket is never printed by the role. |

## Credentials

The access key and the bucket name enter Ansible **only from the operator's files, never from extra vars**:

- `HOMELAB_ETCD_S3_KEY_FILE` names the AWS CLI's `create-access-key` JSON output. It must be a regular `0600` file, not a link, owned by the operator, in a `0700` directory owned by the operator, on tmpfs. The key must belong to `home-cluster-etcd-backup` and be `Active`.
- `HOMELAB_ETCD_S3_BUCKET_FILE` names the operator's existing `0600` bucket file; its first line is the bucket name.
- A credential, the bucket, or any name the role sets, passed as an extra var or in inventory, is refused before anything is read. So is any other `etcd_s3_*` or `es_*` variable that is not a documented input.

Every task that reads, validates, holds or writes a credential has **`no_log: true`, `diff: false` and no backup**: the reads and checks on the controller, the probe runs, the drop-in write and the save. A refusal is identified by its task name alone. The guard also refuses, before anything is read:
- `-v`, `--check` and `--diff`;
- `ANSIBLE_DEBUG`, `ANSIBLE_KEEP_REMOTE_FILES` and a log path;
- displayed task arguments, any stdout callback but `default`, and extra callbacks.

**The drop-in holds the access key persistently.** It stays on each server's disk, in a root-owned `0600` file readable only by root (and so by K3s), until a rotation replaces it. Anyone with root on a server, or its disk, has the key. That is the one place the key is kept; the workstation copy is removed after the rollout, as the home-cluster runbook describes. The key is not recovery material. `etcd-s3-config-secret`, `AWS_*` variables and `/root/.aws` are not used, and the preflight requires `/root/.aws` to be absent, because K3s would silently fall back to it.

**Leak checks (counts only).** After every configuration, save and restart, the probe counts the drop-in's key ID, its secret and any key-shaped string in:
- the K3s journal;
- the K3s process's command line and environment;
- the `ETCDSnapshotFile` records and the `k3s-etcd-snapshots` ConfigMap.

Any count above zero stops the run. The operator still scans Ansible output and evidence before keeping them.

## Playbooks

Each mutating playbook acts on exactly one server (`--limit <host>`, no pattern), needs `-e etcd_s3_environment=live|rehearsal` and a fresh confirmation `-e etcd_s3_confirm=<phase>:<host>:<UTC time>`, and records the confirmation in `/var/lib/homelab-etcd-s3/confirmations` on that server before it acts, so it is never accepted again.

| Playbook | Phase | Does |
| --- | --- | --- |
| [`preflight-etcd-s3.yml`](../ansible/preflight-etcd-s3.yml) | read-only | The gate S4-5 checks, with `-e etcd_s3_enforce=true` to fail on a problem |
| [`configure-etcd-s3.yml`](../ansible/configure-etcd-s3.yml) | `configure` | D5 gate, credentials, preconditions, drop-in, on-demand upload, leak checks |
| [`restart-etcd-s3.yml`](../ansible/restart-etcd-s3.yml) | `restart` | D5 gate, the approved drop-in, restart, every server Ready, leak checks |
| [`snapshot-etcd-s3.yml`](../ansible/snapshot-etcd-s3.yml) | `snapshot` | D5 gate, the approved drop-in, on-demand upload, leak checks |
| [`validate-etcd-s3.yml`](../ansible/validate-etcd-s3.yml) | read-only | Configuration, leaks, local and S3 counts and ages; `-e etcd_s3_expect=uploading` adds a scheduled upload within 14 hours |

**D5: no pre-encryption snapshot under `etcd/`.** Before writing the drop-in, before each restart and before each on-demand save, the enforced Stage 3 validation must pass on all three servers. It is `validate-secrets-encryption.yml -e secrets_encryption_enforce=true -e secrets_encryption_expect=enabled`, run as a separate `ansible-playbook` process against the same inventory, so that the single-host limit cannot skip it. Its exit status alone decides.

**The approved drop-in, before anything acts.** The restart and the save first require:
- the drop-in to be a root-owned `0600` regular file with only allowlisted keys and the expected values;
- `etcd-snapshot-name` to be defined exactly once, in the drop-in, as the server's `etcd-snapshot-s4-` base;
- no other configuration source, and no unit flag, to set an `etcd-s3` or `etcd-snapshot` key.

A missing, default or differently prefixed name is refused before any restart and before any snapshot is created.

**Rehearsal endpoints.** `etcd_s3_rehearsal_endpoint` and `etcd_s3_rehearsal_endpoint_ca` point the drop-in at an S3-compatible rehearsal endpoint. They are refused for any inventory that contains a live host name, whatever environment is declared.

## Integrity

**An ETag is never an integrity check.** For a multipart upload it is not a digest of the object. Integrity is accepted only from a method listed in `etcd_s3_integrity_approved_methods`, which is empty: `-e etcd_s3_expect_integrity=true` therefore fails closed, and so does any unknown or unsupported remote-checksum behavior. [`validate-etcd-s3.yml`](../ansible/validate-etcd-s3.yml) reports integrity as not verified.

The candidate method for the S4-2 rehearsal is to download an object and compare it with the node's local snapshot by exit status, using [`snapshot_compare.py`](../ansible/roles/etcd-s3/files/snapshot_compare.py). It prints only `MATCH` or `MISMATCH`, never a size or digest, and no playbook runs it. A reviewed change may list it as approved only after the rehearsal record shows it works.

## Residual plaintext (D6)

[`byte_count.py`](../ansible/roles/etcd-s3/files/byte_count.py) is the rehearsal tool for the D6 marker search. It counts exact occurrences of a marker file's raw bytes in a snapshot file, including across read chunks, and prints only the count. A base64 or hex rendering is a different byte sequence and is not counted. No playbook runs it.

## Stage 3 interaction

The Stage 3 preservation baseline tracks every snapshot except those that K3s prunes by its own retention. That pattern is now **`^(etcd-snapshot-|on-demand-s4-)`**: the scheduled names, including the Stage 4 base, and the Stage 4 on-demand base. Without it, the first time K3s pruned an `on-demand-s4-<host>` file, every later Stage 3 gate would report it missing. Older baselines that recorded such a name are filtered the same way. Default-named `on-demand-*` files, `stage3-*` checkpoints and every other name stay tracked.

Once a server has the drop-in, the Stage 3 `snapshot-etcd.yml` save is uploaded too. Its unique `stage3-<checkpoint>-<UTC time>` name keeps S3 retention from ever pruning it.

## Fresh builds

`site.yml`, the build playbooks and the fresh-build setting are unchanged: no build writes the S3 drop-in. A rebuilt or restored cluster, including one restored from the pre-encryption checkpoint, uploads nothing until a separately approved Stage 4 run, which first passes the D5 gate.

## Rollout outline (gate S4-6, not yet approved)

For each server in turn:
1. Run `configure-etcd-s3.yml`, which proves the key with an on-demand upload.
2. Run `restart-etcd-s3.yml`.
3. Check the server with `validate-etcd-s3.yml`.

Then wait for the first scheduled cycle on all three servers. A rotation repeats the same three steps with a new key file; the old key is deactivated only after all three servers have restarted.

## S4-2 questions

These are open until the k3d rehearsal against MinIO answers them:

1. Do the S3 calls match the source reading: the bucket `HEAD` with no prefix, reconciliation with prefix `etcd`, retention with `etcd/<base>`? Is `GetBucketLocation` never called with the region set? Does MinIO reproduce both the Stage 1 condition's failure and D2's success?
2. Does a CLI save read the drop-in and upload with its key before any restart? Does it prune locally and in S3 by its `--name` only?
3. Does a server with a failing S3 configuration (S3 unavailable, a wrong key, or the Stage 1 condition) still start, and keep taking local snapshots?
4. Is `etcd-s3-proxy: none` accepted, and does it disable proxy variables? Is `etcd-s3-endpoint-ca` enough for a rehearsal endpoint with a private CA?
5. Is the `ETCDSnapshotFile` record of an uploaded snapshot ready, under the node's name, with a creation time after the save starts, as `record_wait.yml` assumes?
6. Does download-and-compare work as the integrity method, and does the uploader add or need any remote checksum?
7. D6: does compaction alone remove the marker, or is defragmentation needed?
8. Is PyYAML present on the servers for the probe? Does the etcd metrics endpoint answer on `127.0.0.1:2381`?

## Tests

```bash
python3 ansible/tests/etcd_s3_expressions.py
```

The test contacts no node, VM, Kubernetes API, etcd, AWS or home-cluster, and downloads nothing. Its credentials are sentinels, built at runtime, that match the committed formats.

- **Structure:**
  - the committed values;
  - each playbook's name, phase, targeting, fail-fast settings and step order;
  - the guard first, without privilege escalation, and the D5 gate;
  - credentials only from the two named files, with `no_log`, diff off and no backup;
  - the single, explicitly named save;
  - no ETag, object metadata, annotation or object dump;
  - every role-set name refused if injected;
  - the fresh-build files unchanged;
  - the Stage 3 pattern and its baseline filter;
  - fail-closed integrity, the overlap check and these documentation statements.

  Structural mutants must fail them.
- **Unit:**
  - the probe's configuration, leak and snapshot logic, and its booleans-and-integers output filter;
  - the D6 byte counter;
  - the comparator.
- **Behavior:** the real playbooks run against local stand-in servers, with fake `k3s`, `systemctl` and `journalctl`.
  - **Success paths:** configure, snapshot, restart, validate and preflight.
  - **Refusals and failures:** every refusal and failure listed above, including the output modes, the credential sources, the limits and confirmations, the environments, overrides and injected names, overlapping bases, the D5 gate, a failed save, a missing record and leaks.

  Every case checks that no credential or bucket sentinel appears in the output, on success and on failure, and that a refused case wrote nothing.

The Stage 3 test (`secrets_encryption_expressions.py`) covers the pattern change: pruned Stage 4 names are not preservation problems, while default-named on-demand files and `stage3-*` checkpoints that disappear still are.
