# Time Synchronization

## Status

The `time-sync` Ansible role, the per-node remediation playbook and the read-only acceptance playbook are implemented in this repository.

**They have not yet been applied to the running cluster.** Only static checks and local expression tests have been run (see [Evidence Boundaries](#evidence-boundaries)). Live convergence is demonstrated only by the per-node rollout and acceptance procedure below.

## Why Accurate Time Matters

| Consumer | Effect of clock error |
| --- | --- |
| Embedded etcd | etcd peers compare clocks and log `prober found high clock drift` when two members differ by more than one second. Raft safety does not depend on synchronized clocks, but drift makes etcd logs and lease timing harder to reason about and is treated as a defect in this platform. |
| Kubernetes control plane | Leader-election leases record wall-clock renew times that other nodes evaluate. Skew between servers distorts lease expiry. |
| TLS | Certificates carry validity windows. A clock that is behind can reject newly issued certificates as not yet valid. |
| Logs and evidence | Correlating events across three nodes, and with external monitors, requires a common timebase. |
| AWS Signature Version 4 | Signed requests carry a timestamp. AWS rejects requests whose time differs too much from AWS's own clock, so off-cluster backups depend on correct time. |

## Previous Condition

A backup and disaster-recovery preflight found the same pattern on all three Ubuntu 24.04 VMware servers:

- `systemd-timesyncd` was active, enabled and reporting synchronized;
- VMware Tools periodic time synchronization was also enabled, so **two independent mechanisms were adjusting the same clock**;
- `systemd-timesyncd` reported offsets of about +757 ms, +875 ms and +830 ms, with a 32-second poll interval;
- every node was pinned at `systemd-timesyncd`'s maximum frequency correction, +500 ppm;
- etcd repeatedly logged high clock drift, sometimes around 1–2 seconds;
- the nodes were otherwise healthy.

A frequency correction held at its limit means the client could not remove the error by slewing. The likely causes are the competing VMware Tools correction, an intrinsic virtual-clock drift larger than the client can correct, or both. Which one dominated has not been established; the remediation addresses both.

The clocks were not stepped manually. Secret encryption and the AWS backup rollout are paused until time synchronization is corrected.

## Why Chrony

- **Larger correction range.** On Linux, Chrony adjusts the kernel tick as well as the frequency, so it can compensate drift beyond the ±500 ppm frequency limit that pinned `systemd-timesyncd`.
- **Multiple sources with selection.** Chrony combines several servers and rejects falsetickers, rather than following one server.
- **Slewing by default.** Normal corrections are applied by speeding up or slowing down the clock, not by stepping it.
- **Machine-readable status.** `chronyc -c` produces CSV, so validation does not depend on parsing localized prose.
- **Packaged drop-in support.** Ubuntu 24.04's Chrony package reads extra sources from `/etc/chrony/sources.d`, so the distro-owned `chrony.conf` is not replaced.

## Stepping: Two Modes

Ubuntu's packaged `chrony.conf` contains `makestep 1 3`: chronyd may step the clock **during any of the first three clock updates after it starts**, whenever the error at that update exceeds one second. That can mean more than one step per start. It is acceptable before K3s exists, but not on a running embedded-etcd member. The role therefore has two modes:

| Mode | When | Startup step |
| --- | --- | --- |
| Fresh-build | `time_sync_allow_startup_step: true` (set by the first play of `site.yml`, `init-first-server.yml` and `join-servers.yml`) **and** no K3s on the node | Ubuntu's bounded `makestep 1 3` stays effective, only until the build's final play |
| No-startup-step | Every other case: the role default, `configure-time-sync.yml`, the final play of each build playbook, and any node where `/usr/local/bin/k3s` or `/var/lib/rancher/k3s` exists | The running chronyd carries `-R`, and so does every later start |

The presence of K3s overrides the variable, so an accidental fresh-build run against an existing node still uses no-startup-step mode.

### How No-Startup-Step Mode Works

- **`chronyd -R`.** With `-R`, chronyd ignores `initstepslew`, and sets the limit of any `makestep` with a positive limit to zero. This was confirmed in the Chrony 4.5 source that Ubuntu 24.04 packages (`conf.c`), not assumed from the order of directives.

  For the record, the same source shows that:
  - the last `makestep` parsed wins;
  - `confdir` files are parsed at the point of the `confdir` directive, which comes before the packaged `makestep 1 3`, so a `conf.d` file **cannot** override it;
  - with no `makestep` at all, chronyd never steps.
- **Delivered as a systemd drop-in, not an edit to `chrony.conf`.** `/etc/systemd/system/chrony.service.d/10-homelab-no-startup-step.conf` reproduces the packaged `ExecStart` with `-R` appended. Ubuntu's starter script passes extra arguments through to chronyd. The distro-owned, ucf-managed `chrony.conf` is not modified, so package upgrades raise no configuration-file conflict.
- **No autostart during installation.** Two independent guards prevent the package from starting chronyd before the configuration is verified:
  1. the `apt` task uses `policy_rc_d: 101`, so the postinst's `deb-systemd-invoke` does not start the service;
  2. on a first install, `chrony.service` is masked beforehand. The postinst's `deb-systemd-helper unmask` removes only masks that the helper itself recorded, so an administrator's mask survives.

  The drop-in is also installed before the package, so even an unexpected start would carry `-R`.
- **systemd-timesyncd is stopped and masked before Chrony is installed.** The `policy-rc.d` guard would also block the timesyncd package's own stop during its removal.
- **Fail-closed checks before Chrony starts.** The role fails, leaving chronyd stopped, if:
  - package installation started chronyd anyway;
  - `chronyd -p` (which prints the effective configuration, including `conf.d`, and exits before touching the clock) shows a `makestep` with a negative limit, which `-R` does not suppress;
  - the packaged unit's `ExecStart` differs from the one the drop-in reproduces;
  - the effective `ExecStart` is not the single drop-in command with `-R`;
  - `DAEMON_OPTS` contains `-s`, `-q` or `-Q`, which can set the clock at startup.
- **Bring the running daemon into compliance.** After the pre-start checks pass and Chrony is started, the role reads the running chronyd's arguments.
  - It restarts chronyd only when the process lacks the distinct `-R` argument, or when a daemon that was already running predates a drop-in change.
  - Because the drop-in and the effective `ExecStart` were verified first, the restarted daemon carries `-R` and cannot perform a configured startup step.
  - The role then requires the running process to contain `-R`.
  - A chronyd that already runs with `-R`, with no drop-in change, is not restarted.
  - If the restart or the verification fails, the role stops Chrony and fails.

The fail-closed state is: Chrony installed but stopped (and masked if it failed before its first start), with `systemd-timesyncd` masked. No time daemon is running, so the clock free-runs until the cause is fixed or the node is rolled back.

### What "Does Not Step" Means

- **The role never invokes a step.** It never runs `chronyc makestep`, `date`, `hwclock` or anything else that sets the time.
- **The role restarts chronyd only to bring it into no-startup-step mode,** and only after the `-R` configuration has been verified.
- **When the role finishes in no-startup-step mode, the running chronyd carries `-R` and cannot step the clock from its configuration.** The same holds for every later start, including reboots and package-upgrade restarts, because the drop-in persists.
- **The clock can still be stepped by:**
  - an administrator running `chronyc makestep` or changing the configuration;
  - VMware's one-off corrections (see [VMware Tools](#vmware-tools));
  - the kernel inserting a leap second.
- **In fresh-build mode, before K3s exists, chronyd may step during any of its first three clock updates after each start.** Once K3s is installed or joined, the build playbooks' final play converts the node to no-startup-step mode. A successfully built node therefore does not permit startup steps on later reboots.
- **If a build fails after K3s is installed but before that final play,** the node may still permit startup steps. Re-running the build playbook, or `configure-time-sync.yml`, converts it: the presence of K3s forces no-startup-step mode.

Package-upgrade implication: the drop-in pins the packaged `ExecStart` with `-R` added. If a future Chrony package changes its `ExecStart`, the override would hide that change. The next role run detects the mismatch and fails closed instead of starting Chrony with an unverified command.

## What the Role Does

The role is [`ansible/roles/time-sync`](../ansible/roles/time-sync). In order, it:

1. Refuses to run on anything other than Ubuntu 24.04, and validates that every configured source is a `server` or `pool` directive.
2. Resolves the mode (above), and records whether Chrony was already installed and running.
3. On a first install, masks `chrony.service`.
4. Installs the no-startup-step drop-in, or removes it on a fresh build; reloads systemd only if the drop-in changed.
5. Stops and disables `systemd-timesyncd` if its unit is installed, then masks it.
6. If `vmware-toolbox-cmd` exists, disables VMware Tools **periodic** time synchronization, only when it reports `Enabled`.
7. Installs the Ubuntu `chrony` package with `policy_rc_d: 101`. Chrony conflicts with `time-daemon`, which `systemd-timesyncd` provides, so apt removes the `systemd-timesyncd` package in the same transaction.
8. Verifies that installation did not start chronyd, and that the packaged `chrony.conf` still includes `sourcedir /etc/chrony/sources.d`.
9. Writes the explicit public sources to `/etc/chrony/sources.d/homelab.sources`. A change triggers `chronyc reload sources`, never a restart.
10. Runs the fail-closed pre-start checks.
11. Unmasks, enables and starts `chrony.service`.
12. In no-startup-step mode, restarts chronyd if the running process lacks `-R` (or predates a drop-in change), and requires `-R` afterwards. On failure it stops Chrony and fails.
13. Runs post-configuration validation (below).

The role never stops or restarts K3s.

### Sources

The default is the NTP Pool Project's public pool:

```text
pool pool.ntp.org iburst maxsources 4
```

Ubuntu's packaged `chrony.conf` also contains its own default public pools (`ntp.ubuntu.com` and the Ubuntu pool zones). The role does not remove them, because that would require editing the distro-owned file. Chrony therefore selects among the explicit sources and Ubuntu's defaults. All of them are public NTP services. Leap-smearing services (such as Google Public NTP) are deliberately not added, because the packaged configuration uses `leapsectz` and mixing smeared and unsmeared time is unsafe around a leap second.

Private time servers can be supplied through the `time_sync_sources` variable in local inventory. They are not committed.

### VMware Tools

`vmware-toolbox-cmd timesync disable` turns off VMware Tools' **periodic** synchronization only. One-off corrections that the hypervisor makes after events such as resume, snapshot restore or VMware Tools startup are separate hypervisor settings, and the role does not change them. Such a correction can step the guest clock; Chrony then slews it back to its sources.

The status text is localized by open-vm-tools, so the role reads it in the C locale and accepts only `Enabled` or `Disabled`.

### Post-Configuration Validation

At the end of every run, the role confirms that:

- `chrony.service` is active and enabled;
- `systemd-timesyncd.service` is inactive and masked (a masked unit cannot be enabled);
- in no-startup-step mode, the running chronyd carries `-R`, re-read independently at the end of the run;
- VMware Tools periodic synchronization reports `Disabled`, when the command exists;
- `chronyc -c tracking` succeeds and returns the expected fields;
- `chronyc -c sources` reports at least one usable source (state `*` or `+`), waiting up to about a minute;
- the node remains reachable.

It deliberately does **not** require the final offset target. A freshly started Chrony may still be slewing, so convergence is assessed separately by the acceptance check.

## Fresh Builds

[`ansible/site.yml`](../ansible/site.yml) and the step-by-step [`init-first-server.yml`](../ansible/init-first-server.yml) and [`join-servers.yml`](../ansible/join-servers.yml) apply the `time-sync` role twice:

1. **Before K3s,** in the first play, with `time_sync_allow_startup_step: true`. The role honors that only while K3s is absent, so a large initial error on a new VM can be corrected by a bounded startup step.
2. **After K3s is installed or joined,** in a final play, with `time_sync_allow_startup_step: false`. The role installs and verifies the `-R` drop-in, restarts chronyd only if the running process lacks `-R`, and requires the running process to carry `-R`. K3s is not stopped or restarted.

A successfully built node therefore ends with chronyd running with `-R`, and keeps `-R` across later reboots.

Every play that applies the role is `serial: 1`, and every one that can target more than one server is also `any_errors_fatal: true`. A run therefore never changes time synchronization on two embedded-etcd members at once, and it stops at the first failure.

## Existing Cluster: Per-Node Rollout

Use [`ansible/configure-time-sync.yml`](../ansible/configure-time-sync.yml). It:

- targets the `servers` group with `become: true`, gathers facts and uses `serial: 1`;
- stops on the first failure (`any_errors_fatal`, `max_fail_percentage: 0`);
- sets `time_sync_allow_startup_step: false`, so Chrony always starts with `-R`;
- applies only the `time-sync` role;
- **refuses to run unless `--limit` selects exactly one server.**

Process `k3s01`, `k3s02` and `k3s03` separately, in that order. Run all commands from the `ansible/` directory.

### Before Each Node

```bash
ansible-playbook validate-time-sync.yml --limit k3s01
```

Proceed only if:

- all three Kubernetes nodes are `Ready`;
- etcd readiness is `ok`;
- the six expected Flux Kustomizations are present and `Ready`;
- the monitoring workloads and `platform-canary` are healthy;
- the LAN canary monitor is clean.

The node's current offset no longer gates the change, because Chrony cannot step at startup in this mode. The report is still kept as the baseline.

### Apply

```bash
ansible-playbook configure-time-sync.yml --limit k3s01
```

### After Each Node

Wait at least 15 minutes, then:

```bash
ansible-playbook validate-time-sync.yml --limit k3s01
ansible-playbook validate-time-sync.yml
```

Continue to the next node only when:

- the changed node reports Chrony synchronized, with a usable source;
- its chronyd runs with `-R`;
- the cluster report is still healthy.

While some nodes still use the old configuration, etcd may continue to report drift involving those peers. That is expected until all three nodes are migrated. New drift warnings between two **migrated** nodes are a stop condition.

### Acceptance After All Three Nodes

Run the acceptance check with enforcement repeatedly through an observation window, for example every 10 minutes for one hour:

```bash
for i in 1 2 3 4 5 6 7; do
  ansible-playbook validate-time-sync.yml \
    -e time_sync_enforce_acceptance=true \
    -e time_sync_report_window=15m || break
  sleep 600
done
```

Acceptance criteria. The playbook enforces every one of these except the procedural first item.

- Each node was processed separately with `--limit`, with cluster and etcd health verified between nodes.
- Chrony remains synchronized on every node, with at least one usable source, and chronyd runs with `-R`.
- The absolute system-time offset stays below 100 ms, and preferably below 10 ms, throughout the observation window.
- The frequency is no longer pinned at ±500 ppm. Chrony may settle at a large but stable value; a value persistently far beyond 500 ppm points to the virtual clock itself and is recorded, with the reported clocksource, for investigation.
- No new etcd high-clock-drift warnings occur during the observation window.
- All three Kubernetes nodes stay `Ready`.
- Each of these six Flux Kustomizations is present exactly once and `Ready`. A missing, duplicated or not-`Ready` one fails acceptance:
  - `flux-system/flux-system`
  - `flux-system/infrastructure-controllers`
  - `flux-system/infrastructure-configs`
  - `flux-system/monitoring`
  - `flux-system/monitoring-configs`
  - `flux-system/apps`

  Additional Kustomizations are reported, with their readiness, but do not fail acceptance. A later platform layer should not invalidate time-synchronization acceptance; it is validated by its own procedure.
- In the `monitoring` and `monitoring-node-exporter` namespaces:
  - each namespace has Pods, every Pod is `Running`, and every declared container is `Ready`. A completed Job Pod (`Succeeded`) also fails this check, as specified;
  - at least two StatefulSets exist (Prometheus and Alertmanager), and each has `readyReplicas` equal to `spec.replicas`, with at least one replica;
  - at least one DaemonSet exists (node-exporter), and each has `numberReady` equal to `desiredNumberScheduled`, with at least one Pod scheduled.
- `platform-demo/platform-canary` exists, and its `availableReplicas` equals `spec.replicas`, with at least one replica.
- Every Deployment is fully available.

Absent or null status counters (`readyReplicas`, `numberReady`, `desiredNumberScheduled`, `availableReplicas`) are read as zero, because Kubernetes omits zero-valued counters. An absent or null `spec.replicas` is reported as a problem. Empty results are never treated as healthy.

### Stop Conditions

Stop the rollout, and do not continue to the next node, if:

- the configure playbook fails on any task. It stops on its own; if it failed a fail-closed check, Chrony is left stopped;
- etcd readiness is not `ok`, a Kubernetes node is not `Ready`, or an expected Flux Kustomization is missing or not `Ready`;
- a monitoring workload or `platform-canary` becomes unhealthy;
- Chrony has no usable source, is not synchronized, or is running without `-R`, 15 minutes after the change;
- the offset grows instead of converging;
- the K3s service restarts unexpectedly (the role never touches it);
- the LAN canary monitor records failures;
- new etcd drift warnings appear between two migrated nodes.

### Rollback

Rollback restores the previous condition, which is the known-bad dual time source, so it is a last resort. Prefer stopping and investigating. For one node:

```bash
ansible k3s01 -b -m ansible.builtin.systemd_service -a 'name=systemd-timesyncd.service masked=false'
# Installing systemd-timesyncd removes chrony, because the packages conflict.
ansible k3s01 -b -m ansible.builtin.apt -a 'name=systemd-timesyncd state=present'
ansible k3s01 -b -m ansible.builtin.systemd_service -a 'name=systemd-timesyncd.service enabled=true state=started'
ansible k3s01 -b -m ansible.builtin.file -a 'path=/etc/chrony/sources.d/homelab.sources state=absent'
ansible k3s01 -b -m ansible.builtin.file -a 'path=/etc/systemd/system/chrony.service.d/10-homelab-no-startup-step.conf state=absent'
ansible k3s01 -b -m ansible.builtin.systemd_service -a 'name=chrony.service masked=false daemon_reload=true'
# Only if the previous VMware Tools behavior must be restored exactly:
ansible k3s01 -b -m ansible.builtin.command -a 'vmware-toolbox-cmd timesync enable'
```

Rollback does not stop or restart K3s. The `apt` step starts `systemd-timesyncd`, which may step the clock as it did before the change.

## Verification Commands

```bash
chronyc tracking
chronyc sources -v
chronyc -c tracking
chronyc -c sources
systemctl is-active chrony.service
systemctl cat chrony.service
ps -o args= -p "$(systemctl show chrony.service --property=MainPID --value)"
systemctl is-enabled systemd-timesyncd.service
LC_ALL=C vmware-toolbox-cmd timesync status
cat /sys/devices/system/clocksource/clocksource0/current_clocksource
journalctl -u k3s.service --since -1h --grep 'found high clock drift'
k3s kubectl get nodes
k3s kubectl get --raw /readyz/etcd
k3s kubectl get kustomizations.kustomize.toolkit.fluxcd.io -A
k3s kubectl get pods,statefulsets,daemonsets -n monitoring
k3s kubectl get pods,daemonsets -n monitoring-node-exporter
k3s kubectl get deployment platform-canary -n platform-demo
```

[`ansible/validate-time-sync.yml`](../ansible/validate-time-sync.yml) collects the same information without changing anything:

- node name and UTC timestamp;
- Chrony tracking and sources, from CSV output;
- whether chronyd runs with `-R`;
- `systemd-timesyncd` state;
- VMware Tools periodic-synchronization state;
- the kernel clocksource;
- the K3s service state;
- the number of recent etcd clock-drift warnings;
- node and etcd readiness;
- the expected Flux set and any extras;
- Deployment availability;
- monitoring Pods, StatefulSets and DaemonSets;
- the canary.

It reports only counts of drift warnings, not the log lines, which contain peer identifiers. `time_sync_require_no_startup_step=false` relaxes the `-R` check for a fresh-built cluster.

Its parsing is limited to:

| Source | Format |
| --- | --- |
| Chrony | `chronyc -c` CSV columns, as defined by Chrony |
| systemd | `systemctl` state keywords and properties |
| Kubernetes | `kubectl` JSONPath and JSON output |
| chronyd arguments | `ps -o args=`, matched for the `-R` token |
| VMware Tools | Read in the C locale and compared with two fixed tokens |
| etcd | Matched by its fixed warning text |

## Expression Tests

[`ansible/tests/time_sync_expressions.py`](../ansible/tests/time_sync_expressions.py) does two things, and contacts no node:

1. **Structure checks.** It checks the playbook and role structure:
   - both time-sync plays in each build playbook, their modes, and their order around K3s;
   - `serial: 1` and fail-fast settings;
   - the remediation playbook's mode and single-host guard;
   - the role's safe task order and `policy_rc_d: 101`;
   - the conditional restart and its stop-and-fail rescue;
   - that the role never manages the K3s service.
2. **Expression scenarios.** It extracts the real evaluation and assertion tasks from the role and from the acceptance playbook, and runs them on localhost against mocked command output.

| Area | Scenarios |
| --- | --- |
| Mode resolution | Both modes, K3s overriding a fresh-build request, and the safe default |
| Pre-start gate | Pass, plus the fail-closed cases: no `-R`, `-Rx`, two `ExecStart` entries, a changed packaged `ExecStart`, and `-s`, `-sR` or `-q` in `DAEMON_OPTS` |
| Effective configuration | A negative-limit `makestep` |
| Restart decision | Restart for a pre-existing chronyd without `-R`, for `-Rx`, for unreadable arguments, and for a pre-existing daemon with a changed drop-in; no restart for a compliant daemon, or for one the role just started with `-R` |
| Post-transition and final `-R` checks | Pass; and fail closed when the running process still lacks `-R`, or its arguments cannot be read |
| Fresh build to persistent no-startup-step | After K3s install: the node transitions to a running `-R`; the run fails closed if `-R` is still missing; a re-run on a compliant node does not restart chronyd |
| Flux | Six of six; an extra Kustomization; five of six; a duplicate; NotReady; a missing condition; a read failure |
| Workloads | Positive cases, and negative cases for every Pod, StatefulSet, DaemonSet and canary condition above, including absent and null fields and empty results |

```bash
python3 ansible/tests/time_sync_expressions.py
```

## Evidence Boundaries

Static checks and the expression tests show that the playbooks parse, that the decision logic behaves as specified on the mocked inputs, and that the tasks are written to be idempotent. They do **not** show that:

- `policy_rc_d`, the pre-install mask and the drop-in behave as described on these nodes. They follow from the Ubuntu 24.04 maintainer scripts, `deb-systemd-helper`, `deb-systemd-invoke`, the Ansible 2.16 `apt` module and the Chrony 4.5 source, all inspected for this change; none has been observed on a node;
- Chrony converges on these VMware guests, or reaches the 100 ms or 10 ms targets;
- the etcd drift warnings stop;
- disabling VMware Tools periodic synchronization persists across VM restarts on this hypervisor;
- the role is idempotent on a live node (a second run reporting no changes has not been observed);
- the CSV columns, `ExecStart` property format and Kubernetes JSON match live output, rather than the documented and mocked formats.

Those claims require the live per-node rollout and the acceptance check above, recorded in [validation.md](validation.md).
