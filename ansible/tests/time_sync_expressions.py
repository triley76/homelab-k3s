"""Expression and structure tests for the time-sync role and its playbooks.

First checks the structure of the build, remediation and role files (play
order, modes, serial and fail-fast settings, the guarded restart and its
fail-closed rescue). Then extracts the real assertion and evaluation tasks from
the role and the acceptance playbook, runs them on localhost against mocked
command results, and checks the expected outcome of each scenario (pass, fail
closed, or specific report values). Nothing here contacts a cluster node.

Usage (requires ansible-core and PyYAML):
    python3 ansible/tests/time_sync_expressions.py
"""
import base64
import copy
import json
import os
import pathlib
import subprocess
import sys
import tempfile

import yaml

repo = pathlib.Path(__file__).resolve().parents[2]
val = yaml.safe_load((repo / "ansible/validate-time-sync.yml").read_text())[0]
role_main = yaml.safe_load((repo / "ansible/roles/time-sync/tasks/main.yml").read_text())
role_val = yaml.safe_load((repo / "ansible/roles/time-sync/tasks/validate.yml").read_text())
defaults = yaml.safe_load((repo / "ansible/roles/time-sync/defaults/main.yml").read_text())


def walk(tasks):
    """Yield every task, descending into block/rescue/always sections."""
    for t in tasks:
        yield t
        for section in ("block", "rescue", "always"):
            yield from walk(t.get(section, []))


def pick(tasks, name):
    t = next(t for t in walk(tasks) if t.get("name") == name)
    t = copy.deepcopy(t)
    t.pop("run_once", None)
    return t


def b64(s):
    return base64.b64encode(s.encode()).decode()


def play(name, mocks, tasks, expect_fail, checks=(), extra_vars=None):
    pre = [{"name": f"mock {k}", "ansible.builtin.set_fact": {k: v}} for k, v in mocks.items()]
    body = [{"name": "reset outcome", "ansible.builtin.set_fact": {"harness_failed": False}},
            {"block": tasks, "rescue": [{"name": "record failure", "ansible.builtin.set_fact": {"harness_failed": True}}]}]
    post = [{"name": f"EXPECT {'FAIL' if expect_fail else 'PASS'}: {name}",
             "ansible.builtin.assert": {"that": [f"harness_failed | bool == {expect_fail}"] + list(checks), "quiet": True}}]
    vars_ = dict(val["vars"]); vars_.update(defaults); vars_.update(extra_vars or {})
    return {"name": name, "hosts": "localhost", "connection": "local", "gather_facts": True,
            "gather_subset": ["min"], "vars": vars_, "tasks": pre + body + post}


plays = []

# ---------------------------------------------------------------- node report
csv = "A9FEA97B,ntp.example,3,1700000000.123,-0.000012345,0.000006747,0.000035822,612.225,-0.000,0.129,0.013639022,0.001100737,64.2,Normal"
units = lambda r: {"results": [{"item": {"key": k}, "stdout": v} for k, v in r.items()]}
node_mocks = {
    "time_sync_tracking": {"rc": 0, "stdout": csv},
    "time_sync_sources_csv": {"rc": 0, "stdout_lines": ["^,*,a.example,2,6,377,12,0,0,0", "^,-,b.example,2,6,377,12,0,0,0", "^,?,c.example,0,6,0,-,0,0,0"]},
    "time_sync_unit_states": units({"timesyncd_active": "inactive", "timesyncd_enabled": "masked", "chrony_active": "active", "k3s_active": "active"}),
    "time_sync_vmware_toolbox": {"stat": {"exists": True}},
    "time_sync_vmware_status": {"stdout": "Disabled\n"},
    "time_sync_clocksource": {"content": b64("tsc\n")},
    "time_sync_drift": {"rc": 1, "stdout_lines": []},
    "time_sync_chronyd_args": {"rc": 0, "stdout": "/usr/sbin/chronyd -F 1 -R"},
}
node_tasks = [pick(val["tasks"], n) for n in ("Build the per-node report", "Evaluate per-node acceptance criteria")]
plays.append(play("node report: healthy, -R present", node_mocks, node_tasks, False, [
    "time_sync_report.sources_usable | int == 1", "time_sync_report.frequency_ppm | float == 612.225",
    "time_sync_report.chronyd_started_with_R | bool",
    "time_sync_checks.values() | map('bool') | select('equalto', false) | list | length == 0"]))
m = dict(node_mocks, time_sync_chronyd_args={"rc": 0, "stdout": "/usr/sbin/chronyd -F 1"})
plays.append(play("node report: chronyd without -R fails the no-startup-step check", m, node_tasks, False, [
    "not (time_sync_report.chronyd_started_with_R | bool)", "not (time_sync_checks.chrony_no_startup_step | bool)"]))
plays.append(play("node report: without -R allowed when not required", m, node_tasks, False, [
    "time_sync_checks.chrony_no_startup_step | bool"], {"time_sync_require_no_startup_step": False}))
m = dict(node_mocks, time_sync_chronyd_args={"rc": 0, "stdout": "/usr/sbin/chronyd -F 1 -Rx"})
plays.append(play("node report: -Rx is not mistaken for -R", m, node_tasks, False, ["not (time_sync_report.chronyd_started_with_R | bool)"]))

# ---------------------------------------------------------------- cluster
expected = val["vars"]["time_sync_expected_kustomizations"]
flux_ok = [f"{n}=True" for n in expected]


def pod(ns, name, phase="Running", containers=("main",), ready=None, statuses=True):
    ready = {c: True for c in containers} if ready is None else ready
    p = {"metadata": {"namespace": ns, "name": name}, "spec": {"containers": [{"name": c} for c in containers]}, "status": {"phase": phase}}
    if statuses:
        p["status"]["containerStatuses"] = [{"name": c, "ready": ready.get(c, False)} for c in containers]
    return p


pods_ok = [pod("monitoring", "prometheus-0", containers=("prometheus", "config-reloader")),
           pod("monitoring", "alertmanager-0", containers=("alertmanager", "config-reloader")),
           pod("monitoring", "grafana-x", containers=("grafana", "sc-dashboard", "sc-datasources")),
           pod("monitoring-node-exporter", "node-exporter-a"), pod("apps", "unrelated", phase="Pending")]
sts = lambda name, replicas=1, ready=1: {"kind": "StatefulSet", "metadata": {"namespace": "monitoring", "name": name},
                                         "spec": ({} if replicas == "absent" else {"replicas": replicas}),
                                         "status": ({} if ready == "absent" else {"readyReplicas": ready})}
ds = lambda desired=3, ready=3: {"kind": "DaemonSet", "metadata": {"namespace": "monitoring-node-exporter", "name": "node-exporter"},
                                 "status": {k: v for k, v in (("desiredNumberScheduled", desired), ("numberReady", ready)) if v != "absent"}}
work_ok = [sts("prometheus"), sts("alertmanager"), ds()]
canary_ok = {"spec": {"replicas": 2}, "status": {"availableReplicas": 2}}


def cluster_mocks(flux=flux_ok, flux_rc=0, pods=pods_ok, work=work_ok, canary=canary_ok, canary_rc=0, pods_rc=0):
    return {
        "time_sync_nodes": {"rc": 0, "stdout_lines": ["k3s01=True", "k3s02=True", "k3s03=True"]},
        "time_sync_etcd_ready": {"rc": 0, "stdout": "ok"},
        "time_sync_flux": {"rc": flux_rc, "stdout_lines": flux},
        "time_sync_deployments": {"rc": 0, "stdout_lines": ["monitoring/a=1/1", "platform-demo/platform-canary=2/2", "x/scaled=/0", "z/ten=10/10"]},
        "time_sync_pods": {"rc": pods_rc, "stdout": json.dumps({"items": pods})},
        "time_sync_workloads": {"rc": 0, "stdout": json.dumps({"items": work})},
        "time_sync_canary": {"rc": canary_rc, "stdout": json.dumps(canary) if canary_rc == 0 else ""},
    }


cluster_tasks = [pick(val["tasks"], n) for n in ("Evaluate Flux Kustomizations", "Evaluate monitoring and canary workloads", "Build the cluster report")]
ok = lambda: ["time_sync_cluster.expected_flux_kustomizations_ready | bool", "time_sync_cluster.monitoring_and_canary_healthy | bool"]
plays.append(play("cluster: all healthy", cluster_mocks(), cluster_tasks, False, ok() + [
    "time_sync_cluster.all_deployments_available | bool", "time_sync_cluster.workload_counts.monitoring_pods | int == 4"]))
plays.append(play("flux: six of six plus an extra NotReady (reported, not failed)",
                  cluster_mocks(flux=flux_ok + ["flux-system/backup=False"]), cluster_tasks, False, ok() + [
    "time_sync_cluster.flux_extra == ['flux-system/backup']", "time_sync_cluster.flux_extra_not_ready == ['flux-system/backup']"]))
plays.append(play("flux: five of six fails", cluster_mocks(flux=flux_ok[:-1]), cluster_tasks, False, [
    "not (time_sync_cluster.expected_flux_kustomizations_ready | bool)", "time_sync_cluster.flux_missing == ['flux-system/apps']"]))
plays.append(play("flux: duplicate fails", cluster_mocks(flux=flux_ok + ["flux-system/monitoring=True"]), cluster_tasks, False, [
    "not (time_sync_cluster.expected_flux_kustomizations_ready | bool)", "time_sync_cluster.flux_duplicates == ['flux-system/monitoring']"]))
plays.append(play("flux: NotReady fails", cluster_mocks(flux=flux_ok[:3] + ["flux-system/monitoring=False"] + flux_ok[4:]), cluster_tasks, False, [
    "not (time_sync_cluster.expected_flux_kustomizations_ready | bool)", "time_sync_cluster.flux_not_ready == ['flux-system/monitoring']"]))
plays.append(play("flux: missing Ready condition fails", cluster_mocks(flux=flux_ok[:5] + ["flux-system/apps="]), cluster_tasks, False, [
    "not (time_sync_cluster.expected_flux_kustomizations_ready | bool)", "time_sync_cluster.flux_not_ready == ['flux-system/apps']"]))
plays.append(play("flux: read failure fails", cluster_mocks(flux=[], flux_rc=1), cluster_tasks, False, [
    "not (time_sync_cluster.expected_flux_kustomizations_ready | bool)", "time_sync_cluster.flux_missing | length == 6"]))


def work_case(label, problem_substring, **kw):
    plays.append(play(f"workloads: {label}", cluster_mocks(**kw), cluster_tasks, False, [
        "not (time_sync_cluster.monitoring_and_canary_healthy | bool)",
        f"time_sync_cluster.workload_problems | select('search', {problem_substring!r}) | list | length > 0"]))


work_case("Pending monitoring pod", "prometheus-0: phase Pending",
          pods=[pod("monitoring", "prometheus-0", phase="Pending", containers=("prometheus",))] + pods_ok[1:])
work_case("Succeeded monitoring pod", "job-x: phase Succeeded", pods=pods_ok + [pod("monitoring", "job-x", phase="Succeeded")])
work_case("container not ready", "grafana-x: container sc-dashboard not ready",
          pods=pods_ok[:2] + [pod("monitoring", "grafana-x", containers=("grafana", "sc-dashboard"), ready={"grafana": True, "sc-dashboard": False})] + pods_ok[3:])
work_case("containerStatuses absent", "alertmanager-0: container alertmanager not ready",
          pods=[pods_ok[0], pod("monitoring", "alertmanager-0", containers=("alertmanager",), statuses=False)] + pods_ok[2:])
work_case("empty monitoring namespace", "monitoring-node-exporter: no pods", pods=pods_ok[:3])
work_case("no pods at all", "monitoring: no pods", pods=[])
work_case("pods read failure", "pods: read failed", pods=[], pods_rc=1)
work_case("StatefulSet readyReplicas absent", "statefulset monitoring/prometheus: ready 0 of 1", work=[sts("prometheus", ready="absent"), sts("alertmanager"), ds()])
work_case("StatefulSet spec.replicas absent", "statefulset monitoring/prometheus: spec.replicas absent", work=[sts("prometheus", replicas="absent"), sts("alertmanager"), ds()])
work_case("StatefulSet spec.replicas null", "statefulset monitoring/prometheus: spec.replicas absent", work=[sts("prometheus", replicas=None), sts("alertmanager"), ds()])
work_case("StatefulSet scaled to zero", "statefulset monitoring/alertmanager: ready 0 of 0", work=[sts("prometheus"), sts("alertmanager", 0, 0), ds()])
work_case("too few StatefulSets", "statefulsets: 1 found, 2 required", work=[sts("prometheus"), ds()])
work_case("DaemonSet numberReady absent", "daemonset monitoring-node-exporter/node-exporter: ready 0 of 3", work=work_ok[:2] + [ds(3, "absent")])
work_case("DaemonSet desired absent", "daemonset monitoring-node-exporter/node-exporter: ready 0 of 0", work=work_ok[:2] + [ds("absent", "absent")])
work_case("no DaemonSet", "daemonsets: 0 found, 1 required", work=work_ok[:2])
work_case("canary availableReplicas null", "platform-canary: available 0 of 2", canary={"spec": {"replicas": 2}, "status": {"availableReplicas": None}})
work_case("canary partially available", "platform-canary: available 1 of 2", canary={"spec": {"replicas": 2}, "status": {"availableReplicas": 1}})
work_case("canary spec.replicas absent", "platform-canary: spec.replicas absent", canary={"spec": {}, "status": {}})
work_case("canary missing", "platform-canary: not found", canary={}, canary_rc=1)

# ---------------------------------------------------------------- role: mode
mode_task = [pick(role_main, "Resolve the startup-step mode")]
k3s = lambda *exists: {"results": [{"stat": {"exists": e}} for e in exists]}
plays.append(play("mode: fresh build, no K3s -> startup step allowed", {"time_sync_k3s_paths": k3s(False, False)}, mode_task, False,
                  ["time_sync_startup_step_effective | bool", "not (time_sync_k3s_present | bool)"], {"time_sync_allow_startup_step": True}))
plays.append(play("mode: fresh-build request with K3s present -> no-startup-step", {"time_sync_k3s_paths": k3s(True, False)}, mode_task, False,
                  ["not (time_sync_startup_step_effective | bool)", "time_sync_k3s_present | bool"], {"time_sync_allow_startup_step": True}))
plays.append(play("mode: K3s data directory alone counts as present", {"time_sync_k3s_paths": k3s(False, True)}, mode_task, False,
                  ["not (time_sync_startup_step_effective | bool)"], {"time_sync_allow_startup_step": True}))
plays.append(play("mode: live remediation (allow=false) -> no-startup-step", {"time_sync_k3s_paths": k3s(False, False)}, mode_task, False,
                  ["not (time_sync_startup_step_effective | bool)"], {"time_sync_allow_startup_step": False}))
plays.append(play("mode: role default is no-startup-step", {"time_sync_k3s_paths": k3s(False, False)}, mode_task, False,
                  ["not (time_sync_startup_step_effective | bool)"]))

# ---------------------------------------------------------------- role: pre-start gate
packaged_unit = "[Service]\nType=forking\nExecStart=!/usr/lib/systemd/scripts/chronyd-starter.sh $DAEMON_OPTS\n"
good_exec = "{ path=/usr/lib/systemd/scripts/chronyd-starter.sh ; argv[]=/usr/lib/systemd/scripts/chronyd-starter.sh $DAEMON_OPTS -R ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
gate = [pick(role_main, "Require the no-startup-step configuration before starting Chrony")]


def gate_mocks(unit=packaged_unit, execstart=good_exec, opts='DAEMON_OPTS="-F 1"'):
    return {"time_sync_startup_step_effective": False, "time_sync_packaged_unit": {"content": b64(unit)},
            "time_sync_execstart": {"stdout": execstart}, "time_sync_default_chrony": {"content": b64(f"# comment\n{opts}\nSYNC_IN_CONTAINER=\"no\"\n")}}


plays.append(play("gate: verified no-startup-step configuration passes", gate_mocks(), gate, False))
plays.append(play("gate: ExecStart without -R fails closed", gate_mocks(execstart=good_exec.replace(" -R ;", " ;")), gate, True))
plays.append(play("gate: -Rx is not accepted as -R", gate_mocks(execstart=good_exec.replace(" -R ;", " -Rx ;")), gate, True))
plays.append(play("gate: two ExecStart entries fail closed", gate_mocks(execstart=good_exec + " ; " + good_exec), gate, True))
plays.append(play("gate: changed packaged ExecStart fails closed", gate_mocks(unit=packaged_unit.replace("$DAEMON_OPTS", "$DAEMON_OPTS -n")), gate, True))
plays.append(play("gate: DAEMON_OPTS with -s fails closed", gate_mocks(opts='DAEMON_OPTS="-F 1 -s"'), gate, True))
plays.append(play("gate: DAEMON_OPTS with combined -sR fails closed", gate_mocks(opts='DAEMON_OPTS="-F 1 -sR"'), gate, True))
plays.append(play("gate: DAEMON_OPTS with -q fails closed", gate_mocks(opts='DAEMON_OPTS="-q"'), gate, True))
plays.append(play("gate: skipped in fresh-build mode", dict(gate_mocks(execstart="none"), time_sync_startup_step_effective=True), gate, False))

steps = [pick(role_main, "Reject unconditional clock steps")]
cfg = lambda *lines: {"time_sync_effective_config": {"stdout_lines": list(lines)}}
plays.append(play("chronyd -p: packaged makestep 1 3 accepted", cfg("confdir /etc/chrony/conf.d", "makestep 1 3"), steps, False))
plays.append(play("chronyd -p: makestep with negative limit rejected", cfg("makestep 1 3", "makestep 0.1 -1"), steps, True))

# ---------------------------------------------------------------- role: restart decision
WITH_R, WITHOUT_R = "/usr/sbin/chronyd -F 1 -R", "/usr/sbin/chronyd -F 1"
decide = [pick(role_main, "Decide whether chronyd must be restarted")]


def dm(args, was_active, dropin_changed, rc=0):
    return {"time_sync_args_before": {"rc": rc, "stdout": args}, "time_sync_chrony_was_active": was_active,
            "time_sync_dropin_present": {"changed": dropin_changed}}


plays.append(play("restart: pre-existing chronyd without -R is restarted", dm(WITHOUT_R, True, True), decide, False,
                  ["time_sync_restart_required | bool"]))
plays.append(play("restart: pre-existing chronyd without -R and unchanged drop-in is restarted", dm(WITHOUT_R, True, False), decide, False,
                  ["time_sync_restart_required | bool"]))
plays.append(play("restart: pre-existing chronyd with -R and unchanged drop-in is NOT restarted", dm(WITH_R, True, False), decide, False,
                  ["not (time_sync_restart_required | bool)"]))
plays.append(play("restart: chronyd just started by the role with -R is NOT restarted", dm(WITH_R, False, True), decide, False,
                  ["not (time_sync_restart_required | bool)"]))
plays.append(play("restart: pre-existing chronyd with -R but a changed drop-in is restarted", dm(WITH_R, True, True), decide, False,
                  ["time_sync_restart_required | bool"]))
plays.append(play("restart: -Rx is not -R, so a restart is required", dm("/usr/sbin/chronyd -F 1 -Rx", True, False), decide, False,
                  ["time_sync_restart_required | bool"]))
plays.append(play("restart: unreadable process arguments require a restart", dm("", True, False, rc=1), decide, False,
                  ["time_sync_restart_required | bool"]))

# ---------------------------------------------------------------- role: post-transition and final -R checks
transition_check = [pick(role_main, "Require the running chronyd to carry -R")]
tm = lambda args, rc=0: {"time_sync_chronyd_args": {"rc": rc, "stdout": args}}
plays.append(play("post-transition: running chronyd with -R passes", tm(WITH_R), transition_check, False))
plays.append(play("post-transition: running chronyd still lacking -R fails closed", tm(WITHOUT_R), transition_check, True))
plays.append(play("post-transition: unreadable process arguments fail closed", tm("", rc=1), transition_check, True))

final_check = [pick(role_val, "Require the running chronyd to carry -R")]
fm = lambda args, effective=False, rc=0: {"time_sync_startup_step_effective": effective, "time_sync_final_args": {"rc": rc, "stdout": args}}
plays.append(play("final check: -R present passes", fm(WITH_R), final_check, False))
plays.append(play("final check: pre-existing chronyd without -R can no longer pass", fm(WITHOUT_R), final_check, True))
plays.append(play("final check: not applied in fresh-build mode before K3s", fm(WITHOUT_R, effective=True), final_check, False))

# ---------------------------------------------------------------- fresh build -> persistent no-startup-step
# The post-install play runs the role with allow=false on a node where K3s now
# exists and chronyd still runs from the fresh-build phase (without -R).
sequence = mode_task + decide + transition_check + final_check
plays.append(play("fresh build after K3s install: transitions to running -R", {
    "time_sync_k3s_paths": k3s(True, True),
    "time_sync_args_before": {"rc": 0, "stdout": WITHOUT_R}, "time_sync_chrony_was_active": True,
    "time_sync_dropin_present": {"changed": True},
    "time_sync_chronyd_args": {"rc": 0, "stdout": WITH_R}, "time_sync_final_args": {"rc": 0, "stdout": WITH_R},
}, sequence, False, ["not (time_sync_startup_step_effective | bool)", "time_sync_restart_required | bool"],
    {"time_sync_allow_startup_step": False}))
plays.append(play("fresh build after K3s install: fails closed if chronyd still lacks -R", {
    "time_sync_k3s_paths": k3s(True, True),
    "time_sync_args_before": {"rc": 0, "stdout": WITHOUT_R}, "time_sync_chrony_was_active": True,
    "time_sync_dropin_present": {"changed": True},
    "time_sync_chronyd_args": {"rc": 0, "stdout": WITHOUT_R}, "time_sync_final_args": {"rc": 0, "stdout": WITHOUT_R},
}, sequence, True, [], {"time_sync_allow_startup_step": False}))
plays.append(play("re-run on a compliant node: no restart, -R verified", {
    "time_sync_k3s_paths": k3s(True, True),
    "time_sync_args_before": {"rc": 0, "stdout": WITH_R}, "time_sync_chrony_was_active": True,
    "time_sync_dropin_present": {"changed": False},
    "time_sync_chronyd_args": {"rc": 0, "stdout": WITH_R}, "time_sync_final_args": {"rc": 0, "stdout": WITH_R},
}, sequence, False, ["not (time_sync_restart_required | bool)"], {"time_sync_allow_startup_step": False}))

# ---------------------------------------------------------------- role: other expressions
plays.append(play("role: sources and unit-state assertions", {
    "time_sync_sources": ["pool pool.ntp.org iburst maxsources 4", "server time.example.org iburst"],
    "time_sync_chrony_conf": {"content": b64("confdir /etc/chrony/conf.d\nsourcedir /etc/chrony/sources.d\nmakestep 1 3\n")},
    "time_sync_unit_states": units({"chrony_active": "active", "chrony_enabled": "enabled", "timesyncd_active": "inactive", "timesyncd_enabled": "masked"}),
}, [pick(role_main, "Validate the configured NTP sources"), pick(role_main, "Require the packaged sources.d include"),
    pick(role_val, "Require Chrony running and systemd-timesyncd masked")], False))
plays.append(play("role: invalid source directive rejected", {"time_sync_sources": ["allow 0/0"]},
                  [pick(role_main, "Validate the configured NTP sources")], True))
plays.append(play("role: commented sourcedir rejected", {"time_sync_chrony_conf": {"content": b64("# sourcedir /etc/chrony/sources.d\n")}},
                  [pick(role_main, "Require the packaged sources.d include")], True))
plays.append(play("role: timesyncd merely disabled (not masked) rejected", {
    "time_sync_unit_states": units({"chrony_active": "active", "chrony_enabled": "enabled", "timesyncd_active": "inactive", "timesyncd_enabled": "disabled"})},
    [pick(role_val, "Require Chrony running and systemd-timesyncd masked")], True))

# ---------------------------------------------------------------- static structure checks
structure_failures = []


def require(label, condition):
    print(f"{'PASS' if condition else 'FAIL'}  structure: {label}", flush=True)
    if not condition:
        structure_failures.append(label)


def roles_of(p):
    return [r if isinstance(r, str) else r.get("role") for r in p.get("roles", [])]


def time_sync_play_ok(p, allow, hosts):
    return (roles_of(p) == ["time-sync"] or roles_of(p)[:1] == ["time-sync"]) and p.get("hosts") == hosts \
        and p.get("vars", {}).get("time_sync_allow_startup_step") is allow


for path, first_hosts, final_hosts, multi in (("ansible/site.yml", "servers", "servers", True),
                                              ("ansible/init-first-server.yml", "servers[0]", "servers[0]", False),
                                              ("ansible/join-servers.yml", "servers[1:]", "servers[1:]", True)):
    pb = yaml.safe_load((repo / path).read_text())
    k3s_idx = [i for i, p in enumerate(pb) if "k3s-server" in roles_of(p)]
    first, last = pb[0], pb[-1]
    require(f"{path}: first play applies time-sync in fresh-build mode before K3s",
            time_sync_play_ok(first, True, first_hosts) and k3s_idx and 0 < min(k3s_idx))
    if multi:
        require(f"{path}: first time-sync play is serial and fail-fast", first.get("serial") == 1 and first.get("any_errors_fatal") is True)
    require(f"{path}: final play re-applies time-sync in no-startup-step mode after K3s",
            roles_of(last) == ["time-sync"] and time_sync_play_ok(last, False, final_hosts) and len(pb) - 1 > max(k3s_idx))
    require(f"{path}: final time-sync play is serial and fail-fast", last.get("serial") == 1 and last.get("any_errors_fatal") is True)

live = yaml.safe_load((repo / "ansible/configure-time-sync.yml").read_text())[0]
require("configure-time-sync.yml: no-startup-step, serial, fail-fast, single-host guard",
        live["vars"]["time_sync_allow_startup_step"] is False and live["serial"] == 1 and live["any_errors_fatal"] is True
        and any("ansible_limit is defined" in str(t) for t in live["pre_tasks"]))

names = [t.get("name") for t in role_main]
order = ["Mask chrony.service until its configuration is verified", "Install the no-startup-step drop-in",
         "Mask systemd-timesyncd", "Install Chrony without starting it", "Fail closed if package installation started Chrony",
         "Require the no-startup-step configuration before starting Chrony", "Enable and start Chrony",
         "Bring the running chronyd into no-startup-step mode", "Validate the time-synchronization configuration"]
require("role: guards, gate, start and transition run in the safe order", all(n in names for n in order)
        and [names.index(n) for n in order] == sorted(names.index(n) for n in order))
apt = next(t for t in role_main if t.get("name") == "Install Chrony without starting it")
require("role: apt installs Chrony with policy_rc_d 101", apt["ansible.builtin.apt"].get("policy_rc_d") == 101)
transition = next(t for t in role_main if t.get("name") == "Bring the running chronyd into no-startup-step mode")
restart = next(t for t in transition["block"] if t.get("name") == "Restart chronyd with the verified -R drop-in")
rescue = transition.get("rescue", [])
require("role: transition applies only in no-startup-step mode", transition.get("when") == "not time_sync_startup_step_effective | bool")
require("role: restart is conditional on the restart decision", restart.get("when") == "time_sync_restart_required | bool"
        and restart["ansible.builtin.systemd_service"] == {"name": "chrony.service", "state": "restarted"})
require("role: transition failure stops Chrony and fails", len(rescue) == 2
        and rescue[0].get("ansible.builtin.systemd_service") == {"name": "chrony.service", "state": "stopped"}
        and "ansible.builtin.fail" in rescue[1])
touches_k3s = [t.get("name") for t in walk(role_main + role_val)
               if "k3s" in str(t.get("ansible.builtin.systemd_service", {}).get("name", ""))]
require("role: never manages the K3s service", not touches_k3s)

if structure_failures:
    print(f"structure checks failed: {structure_failures}", flush=True)
    sys.exit(1)

with tempfile.TemporaryDirectory() as tmp:
    playbook = pathlib.Path(tmp) / "time-sync-expressions.yml"
    playbook.write_text(yaml.safe_dump(plays, sort_keys=False, width=200))
    cfg = pathlib.Path(tmp) / "ansible.cfg"
    cfg.write_text("[defaults]\nretry_files_enabled = False\n")
    env = dict(os.environ, ANSIBLE_CONFIG=str(cfg))
    print(f"scenarios: {len(plays)}", flush=True)
    result = subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)], env=env)
    sys.exit(result.returncode)
