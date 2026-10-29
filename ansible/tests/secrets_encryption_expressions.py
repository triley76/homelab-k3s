"""Structure, expression and safety tests for the Stage 3 secrets-encryption role.

Contacts no cluster node, Kubernetes API, etcd or AWS, and downloads nothing.

1. Structure checks on the role, the phase playbooks, the validation playbook,
   k3s-server and site.yml: targeting, serial and fail-fast settings, the guard
   before facts and privilege escalation, no handlers, a single explicit K3s
   restart, the K3s subcommand each phase may use, the exact etcdctl query,
   the installer's check-before-install order, forbidden commands and paths,
   no_log on every task that can carry a canary value, raw etcd record or
   status output, the pins, the safe default for fresh builds, and no
   unquoted comma inside an item of any flow-style argv under ansible/.
2. The local verifier, imported and run against crafted etcdctl JSON.
3. ansible-playbook --syntax-check of every playbook and of every role task file.
4. The real guard: refused invocations run the real phase playbooks and must
   stop inside the guard, before facts or any other task; allowed invocations
   run the real playbook header and guard with the phase tasks replaced.
5. Real role tasks on localhost, against mocked probe results and local
   stand-ins: status parsing; the health, preservation and snapshot gates;
   every phase decision; the restart order; confirmation replay; state
   directory safety; the drop-in; k3s-server fresh, existing and replacement
   servers; the etcdctl installer's extracted-binary checks and cleanup; the
   raw verification pipeline with a stub etcdctl; and the canary lifecycle with
   a stub k3s, including cleanup after success, failure and interruption.
   Also the corrected step 1 and the enable restart round (k3d rehearsal,
   2026-10-23): the exact enable result before the marker and no status read
   afterwards, the round's order, ledger and checkpoint conditions, and the
   post-round Disabled/start/matching-hashes validation, with a stub k3s.
   Also the service-state probe's exact argv and its parsed start time and
   restart count, with a stub systemctl (three-VM rehearsal, 2026-10-27).
   Also the post-restart counter rule (live, 2026-10-28): a restart by the
   run resets the target's NRestarts to exactly 0, every other counter and
   the target's on a run without a restart stay unchanged.
   Every expected failure names the task that must fail.
6. Mutation tests: structure predicates re-applied to mutated copies, and
   role scenarios re-run against mutated copies of the task files with the
   expected outcome inverted. A surviving mutant fails the suite.
7. A scan of the complete ansible-playbook output for every sentinel: canary
   values, raw etcd values, node names from a hash-mismatch status, and
   protected artifact paths.

Usage (requires ansible-core and PyYAML):
    python3 ansible/tests/secrets_encryption_expressions.py
"""
import base64
import copy
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import yaml

repo = pathlib.Path(__file__).resolve().parents[2]
ans = repo / "ansible"
role = ans / "roles/secrets-encryption"


def load(p):
    return yaml.safe_load(pathlib.Path(p).read_text())


role_vars = load(role / "vars/main.yml")
role_defaults = load(role / "defaults/main.yml")
task_files = {p.stem: load(p) for p in sorted((role / "tasks").glob("*.yml"))}
task_text = {p.stem: p.read_text() for p in sorted((role / "tasks").glob("*.yml"))}

MUTATING = {
    "snapshot-etcd": ("snapshot", "first", "gate.yml", "snapshot.yml"),
    "secrets-encryption-enable": ("enable", "first", "gate.yml", "enable.yml"),
    "secrets-encryption-restart": ("restart", "single", "gate.yml", "restart.yml"),
    "secrets-encryption-rotate": ("rotate-keys", "first", "gate.yml", "rotate.yml"),
    "secrets-encryption-canary": ("canary-{{ secrets_encryption_canary_action | default('unset') }}", "first", "gate.yml", "canary.yml"),
    "install-etcdctl-rehearsal": ("install-etcdctl", "first", "gate.yml", "etcdctl.yml"),
}
playbooks = {name: load(ans / f"{name}.yml") for name in MUTATING}
validate_pb = load(ans / "validate-secrets-encryption.yml")
site_text = (ans / "site.yml").read_text()
k3s_server_tasks = load(ans / "roles/k3s-server/tasks/main.yml")
k3s_server_defaults = load(ans / "roles/k3s-server/defaults/main.yml")
k3s_server_vars = load(ans / "roles/k3s-server/vars/main.yml")


def walk(tasks):
    """Yield every task, descending into block/rescue/always sections."""
    for t in tasks or []:
        yield t
        for section in ("block", "rescue", "always"):
            yield from walk(t.get(section, []))


def module_of(t):
    keys = [k for k in t if k.startswith("ansible.builtin.")]
    return keys[0] if keys else ("block" if "block" in t else None)


def absolutize(tasks, base=None):
    """Point include_tasks at the role's own files (or a mutant copy), wherever the test play lives."""
    for t in walk(tasks):
        inc = t.get("ansible.builtin.include_tasks")
        if inc and not inc.startswith("/"):
            t["ansible.builtin.include_tasks"] = str((base or role / "tasks") / inc)
    return tasks


def unroot(tasks):
    """The tests run unprivileged: drop owner and group (root in the role; checked below)."""
    for t in walk(tasks):
        for m in ("ansible.builtin.file", "ansible.builtin.copy", "ansible.builtin.template", "ansible.builtin.lineinfile"):
            if m in t:
                t[m].pop("owner", None)
                t[m].pop("group", None)
    return tasks


def pick(file, name, tasks=None, base=None):
    source = tasks if tasks is not None else (task_files[file] if base is None else load(base / f"{file}.yml"))
    t = next(t for t in walk(source) if t.get("name") == name)
    t = copy.deepcopy(t)
    t.pop("run_once", None)
    return absolutize([t], base)[0]


def picks(file, *names, base=None):
    return [pick(file, n, base=base) for n in names]


# ====================================================================== structure
structure_failures = []


def require(label, condition):
    print(f"{'PASS' if condition else 'FAIL'}  structure: {label}", flush=True)
    if not condition:
        structure_failures.append(label)


all_role_tasks = [(f, t) for f, ts in task_files.items() for t in walk(ts)]

# Pins and defaults.
require("vars: provider is secretbox with the K8s secretbox prefix and K3s key type",
        role_vars["secrets_encryption_provider"] == "secretbox"
        and role_vars["secrets_encryption_expected_prefix"] == "k8s:enc:secretbox:v1:"
        and role_vars["secrets_encryption_expected_key_type"] == "XSalsa20-POLY1305")
require("vars: supported K3s release is v1.36.4+k3s1", role_vars["secrets_encryption_supported_k3s_version"] == "v1.36.4+k3s1")
require("vars: etcdctl pinned to v3.6.14 with the official SHA-256, as role vars (not defaults)",
        role_vars["secrets_encryption_etcdctl_version"] == "3.6.14"
        and role_vars["secrets_encryption_etcdctl_sha256"] == "ffe840ff9295808e88cce2794a18a5ac87f12a5203c8314d0bf6aa119b41bac5"
        and role_vars["secrets_encryption_etcdctl_url"] == "https://github.com/etcd-io/etcd/releases/download/v3.6.14/etcd-v3.6.14-linux-amd64.tar.gz"
        and not {k for k in role_defaults if "etcdctl" in k})
require("vars: live hosts are k3s01, k3s02, k3s03", role_vars["secrets_encryption_live_hosts"] == ["k3s01", "k3s02", "k3s03"])
require("vars: settled stages are start and reencrypt_finished only",
        role_vars["secrets_encryption_settled_stages"] == ["start", "reencrypt_finished"])
require("vars: drop-in removal before activation is the only rehearsal-approved path (three-VM rehearsal, 2026-10-27)",
        role_vars["secrets_encryption_rehearsal_approved_paths"] == ["flag-removal"])
require("vars: install-etcdctl is the rehearsal-only phase", role_vars["secrets_encryption_rehearsal_only_phases"] == ["install-etcdctl"])
require("vars: state files are root-owned (uid 0)", role_vars["secrets_encryption_state_owner_uid"] == 0)
require("vars: canary values live in a root-only tmpfs directory under /run", role_vars["secrets_encryption_canary_dir"].startswith("/run/"))
require("vars: every gate default named as live-fixed exists in defaults",
        all(k in role_defaults for k in role_vars["secrets_encryption_live_fixed_defaults"]))
require("defaults: no environment default, raw verification off, no protected paths, no additional rotation reason",
        "secrets_encryption_environment" not in role_defaults and role_defaults["secrets_encryption_raw_verification"] is False
        and role_defaults["secrets_encryption_protected_paths"] == {} and role_defaults["secrets_encryption_additional_rotation_reason"] == "")
require("defaults: fixed values are not defined as defaults", not set(role_defaults) & set(role_vars))
require("template: exactly the two critical arguments",
        (role / "templates/secrets-encryption.yaml.j2").read_text().splitlines()[2:]
        == ["secrets-encryption: true", "secrets-encryption-provider: {{ secrets_encryption_provider }}"])
require("role: main.yml refuses to run without a phase",
        len(task_files["main"]) == 1 and "ansible.builtin.fail" in task_files["main"][0])
require("role: no handlers directory and no notify anywhere",
        not (role / "handlers").exists() and not any("notify" in t for _, t in all_role_tasks))

# Playbooks: the guard runs first, on the controller, before facts and privilege escalation.
GUARD_IMPORT = {"name": "Guard the phase", "ansible.builtin.import_role": {"name": "secrets-encryption", "tasks_from": "guard.yml"},
                "become": False}
SETUP = {"name": "Gather minimal facts after the guard", "ansible.builtin.setup": {"gather_subset": ["min"]}}
for name, (phase, target, gate, action) in MUTATING.items():
    pb = playbooks[name]
    p = pb[0] if isinstance(pb, list) and len(pb) == 1 else {}
    tasks = p.get("tasks", [])
    require(f"{name}: one play on servers, serial 1, any_errors_fatal, max_fail_percentage 0, no automatic fact gathering",
            p.get("hosts") == "servers" and p.get("become") is True and p.get("serial") == 1 and p.get("gather_facts") is False
            and p.get("any_errors_fatal") is True and p.get("max_fail_percentage") == 0 and "gather_subset" not in p)
    require(f"{name}: phase {phase} and target {target} set in play vars",
            p.get("vars", {}).get("secrets_encryption_phase") == phase and p.get("vars", {}).get("secrets_encryption_target") == target)
    require(f"{name}: the guard is imported first without privilege escalation, then facts", p.get("pre_tasks") == [GUARD_IMPORT, SETUP])
    require(f"{name}: the gate runs first, then {action}, and nothing else",
            [t.get("ansible.builtin.include_role", {}).get("tasks_from") for t in tasks] == [gate, action]
            and all(t["ansible.builtin.include_role"]["name"] == "secrets-encryption" for t in tasks))
    require(f"{name}: no handlers, roles or post_tasks", not {"handlers", "roles", "post_tasks"} & set(p))
gate_vars = {n: playbooks[n][0]["tasks"][0].get("vars", {}) for n in MUTATING}
require("snapshot-etcd: the only phase without the snapshot freshness gate",
        [n for n, v in gate_vars.items() if v.get("secrets_encryption_require_snapshot") is False] == ["snapshot-etcd"])
require("rotate: snapshot must be newer than the last change",
        sorted(n for n, v in gate_vars.items() if v.get("secrets_encryption_snapshot_after_change") is True)
        == ["secrets-encryption-rotate"])
require("guard.yml: only controller-side assert and set_fact tasks",
        {module_of(t) for t in task_files["guard"]} == {"ansible.builtin.assert", "ansible.builtin.set_fact"}
        and not any("delegate_to" in t or "become" in t for t in task_files["guard"]))
guard_text = task_text["guard"]
require("guard.yml: exact single-host limit, fresh phase/host confirmation, environment, rehearsal boundary, committed values, approvals",
        all(s in guard_text for s in (
            "ansible_limit in groups['servers']", "ansible_play_hosts_all | length == 1", "ansible_play_hosts_all[0] == ansible_limit",
            "ansible_limit == groups['servers'][0]", "se_parts[0] == secrets_encryption_phase", "se_parts[1] == ansible_limit",
            "secrets_encryption_confirm_max_age_minutes", "groups['servers'] == secrets_encryption_live_hosts",
            "groups['all'] | intersect(secrets_encryption_live_hosts) | length == 0",
            "inventory_hostname not in secrets_encryption_live_hosts", "role_path ~ '/vars/main.yml'",
            "role_path ~ '/defaults/main.yml'", "secrets_encryption_rehearsal_approved_paths", "secrets_encryption_protected_paths")))

vp = validate_pb[0]
require("validate: one read-only play on the first server, using gather and checks only",
        len(validate_pb) == 1 and vp["hosts"] == "servers[0]" and vp.get("gather_facts") is False
        and [t["ansible.builtin.include_role"]["tasks_from"] for t in vp["tasks"] if "ansible.builtin.include_role" in t] == ["gather.yml", "checks.yml"]
        and {module_of(t) for t in vp["tasks"]} <= {"ansible.builtin.include_role", "ansible.builtin.set_fact",
                                                   "ansible.builtin.debug", "ansible.builtin.assert"})

# Read-only task files.
READ_ONLY_FILES = ("gather", "summarize", "evaluate", "checks", "parse_status")
READ_ONLY_MODULES = {"ansible.builtin.command", "ansible.builtin.stat", "ansible.builtin.slurp", "ansible.builtin.find",
                     "ansible.builtin.set_fact", "ansible.builtin.include_tasks", "ansible.builtin.debug", "ansible.builtin.assert"}
for f in READ_ONLY_FILES:
    mods = {module_of(t) for t in walk(task_files[f])}
    require(f"{f}.yml: read-only modules only", mods <= READ_ONLY_MODULES)
    require(f"{f}.yml: every command is marked unchanged",
            all(t.get("changed_when") is False for t in walk(task_files[f]) if "ansible.builtin.command" in t))
gather_argv = [t["ansible.builtin.command"]["argv"] for t in walk(task_files["gather"]) if "ansible.builtin.command" in t]
k3s = "{{ secrets_encryption_k3s_bin }}"
allowed_reads = [
    lambda a: a[:3] == ["systemctl", "show", "k3s.service"],
    lambda a: a == [k3s, "--version"],
    lambda a: a[:4] == [k3s, "kubectl", "get", "--raw"] and a[4] in ("/readyz", "/readyz/etcd"),
    lambda a: a[:4] == [k3s, "kubectl", "get", "nodes"] and a[-2] == "-o" and (a[-1].startswith("jsonpath=") or a[-1] == "name"),
    lambda a: a[:3] == [k3s, "kubectl", "get"] and a[3] in ("kustomizations.kustomize.toolkit.fluxcd.io", "helmreleases.helm.toolkit.fluxcd.io",
                                                           "deployments", "statefulsets", "daemonsets") and a[-1].startswith("jsonpath="),
    lambda a: a == [k3s, "secrets-encrypt", "status"],
    lambda a: a == ["date", "+%s"],
    lambda a: a[:2] == ["df", "--output=avail"],
    lambda a: a == ["chronyc", "-c", "tracking"],
    lambda a: a == ["swapon", "--show=SIZE", "--bytes", "--noheadings", "--raw"],
]
require("gather.yml: every command is one of the allowlisted reads", all(any(r(a) for r in allowed_reads) for a in gather_argv))
require("gather.yml: never reads Secrets, node annotations, addresses or JSON/YAML object dumps",
        not any(x in ("secret", "secrets", "json", "yaml", "-ojson", "-oyaml", "wide") for a in gather_argv for x in a)
        and not re.search(r"annotations|addresses|InternalIP|podIP|hostIP",
                          "\n".join(l for l in task_text["gather"].splitlines() if not l.lstrip().startswith("#"))))
require("gather.yml: every stat is lstat-style (follow: false) and computes no checksum",
        all(t["ansible.builtin.stat"].get("follow") is False and t["ansible.builtin.stat"].get("get_checksum") is False
            for t in walk(task_files["gather"]) if "ansible.builtin.stat" in t))
slurps = [t["ansible.builtin.slurp"]["src"] for _, t in all_role_tasks if "ansible.builtin.slurp" in t]
require("role: slurp reads only the Stage 3 state directory", slurps and all(p.startswith("{{ secrets_encryption_state_dir }}/") for p in slurps))
require("role: find lists only the snapshot and database directories",
        {t["ansible.builtin.find"]["paths"] for _, t in all_role_tasks if "ansible.builtin.find" in t}
        == {"{{ secrets_encryption_snapshot_dir }}", "{{ secrets_encryption_db_dir }}"})
require("role: stat computes a checksum only of the new Stage 3 snapshot",
        [f for f, t in all_role_tasks if t.get("ansible.builtin.stat", {}).get("get_checksum") is True] == ["snapshot"])
require("role: no fetch, raw, script, apt, package, pip, reboot or service module",
        not {module_of(t) for _, t in all_role_tasks} & {"ansible.builtin.fetch", "ansible.builtin.raw", "ansible.builtin.script",
                                                        "ansible.builtin.apt", "ansible.builtin.package", "ansible.builtin.pip",
                                                        "ansible.builtin.reboot", "ansible.builtin.service", "ansible.builtin.systemd"})
shells = [(f, t.get("name")) for f, t in all_role_tasks if "ansible.builtin.shell" in t]
require("role: shell only for the canary value generation, the readback comparison and the raw etcd query",
        sorted(shells) == sorted([("canary", "Generate the pre-encryption canary value"), ("canary", "Generate the post-encryption canary value"),
                                  ("canary_readback", "Compare a canary readback without output"),
                                  ("raw_verify", "Verify the stored form of one canary record")]))

# The single restart, the fixed order and the post-restart record.
restarts = [(f, t) for f, t in all_role_tasks if "ansible.builtin.systemd_service" in t]
require("role: exactly one systemd task, in restart.yml: restart k3s.service",
        len(restarts) == 1 and restarts[0][0] == "restart"
        and restarts[0][1]["ansible.builtin.systemd_service"] == {"name": "k3s.service", "state": "restarted"})
restart_block = next(t for t in task_files["restart"] if t.get("name") == "Restart and wait for the server")
require("restart.yml: the restart runs only when decided, after the order and precondition checks",
        restart_block.get("when") == "secrets_encryption_restart_required | bool")
require("restart.yml: the order covers every earlier server in inventory order and requires its verified checkpoint",
        "groups['servers'][:se_index | int]" in task_text["restart"] and "s.checkpoint_reached" in task_text["restart"])
require("summarize.yml: the checkpoint needs a restart after the change and a later restart-verified record",
        "se_server.verified_epoch | int >= se_server.start_epoch | int" in task_text["summarize"]
        and "se_server.verified_epoch | int > se_change_epoch | int" in task_text["summarize"])

# K3s subcommands per file.
argvs = [(f, t["ansible.builtin.command"]["argv"]) for f, t in all_role_tasks if "ansible.builtin.command" in t]
se_sub = {}
for f, a in argvs:
    if a[:2] == [k3s, "secrets-encrypt"]:
        se_sub.setdefault(" ".join(a[2:]), set()).add(f)
require("role: secrets-encrypt subcommands only where documented",
        se_sub == {"status": {"gather", "restart", "rotate"}, "enable": {"enable"}, "rotate-keys": {"rotate"}})
require("role: etcd-snapshot only as 'save --name', only in snapshot.yml",
        [(f, a[2:4]) for f, a in argvs if a[:2] == [k3s, "etcd-snapshot"]] == [("snapshot", ["save", "--name"])])
kubectl_writes = sorted({(f, a[2], a[3]) for f, a in argvs if a[:2] == [k3s, "kubectl"] and a[2] in ("create", "delete", "label", "apply", "replace", "patch", "edit")})
require("role: kubectl writes only create/label/delete canary objects in the canary files",
        kubectl_writes == [("canary", "create", "configmap"), ("canary", "create", "secret"), ("canary", "delete", "secret"),
                           ("canary", "label", "--overwrite"), ("canary_cleanup", "delete", "configmap"), ("canary_cleanup", "delete", "secret")])
canary_names = {"{{ secrets_encryption_canary_pre_secret }}", "{{ secrets_encryption_canary_post_secret }}",
                "{{ secrets_encryption_canary_control_configmap }}", "{{ item }}"}
require("role: every kubectl delete names a fixed canary object, never a selector or --all",
        all(a[4] in canary_names and not any(x.startswith(("-l", "--selector", "--all")) for x in a)
            for f, a in argvs if a[:3] == [k3s, "kubectl", "delete"]))
require("canary_cleanup.yml: deletes exactly the two canary Secrets",
        next(t for t in task_files["canary_cleanup"] if t["name"] == "Delete the canary Secrets")["loop"]
        == ["{{ secrets_encryption_canary_pre_secret }}", "{{ secrets_encryption_canary_post_secret }}"])

# The exact etcd query.
raw_cmd = next(t for t in task_files["raw_verify"] if "ansible.builtin.shell" in t)["ansible.builtin.shell"]["cmd"]
require("raw_verify.yml: one exact key, JSON output, local endpoint only, documented certificates, bounded time",
        "get --write-out=json -- {{ se_raw_key | quote }}" in raw_cmd
        and re.findall(r"--endpoints=\S+", raw_cmd) == ["--endpoints=https://127.0.0.1:2379"]
        and "server-ca.crt" in raw_cmd and "/client.crt" in raw_cmd and "/client.key" in raw_cmd
        and "--dial-timeout=5s" in raw_cmd and "--command-timeout=15s" in raw_cmd and "timeout 30" in raw_cmd
        and "set -o pipefail" in raw_cmd and not re.search(r"--prefix|--from-key|--range|--keys-only|--limit|--rev|watch|\bput\b|\bdel\b", raw_cmd))
require("raw_verify.yml: the etcdctl output goes only into the verifier, with the exact key, never into a file",
        re.search(r"\|\s*python3 -I \{\{ secrets_encryption_verifier_path \| quote \}\}", raw_cmd) is not None
        and re.sub(r"\{\{.*?\}\}", "", raw_cmd).count("|") == 1 and ">" not in re.sub(r"\{\{.*?\}\}", "", raw_cmd)
        and "tee" not in raw_cmd
        and raw_cmd.rstrip().endswith("{{ se_raw_key | quote }}"))
key_guard = next(t for t in task_files["raw_verify"] if t.get("name") == "Require one of the fixed canary keys")
require("raw_verify.yml: only the three fixed canary keys, checked before the query",
        task_files["raw_verify"].index(key_guard) == 0 and len(key_guard["vars"]["se_keys"]) == 3)

# The etcdctl installer.
etc_block = next(t for t in task_files["etcdctl"] if t.get("name") == "Install the pinned etcdctl")
etc_names = [t["name"] for t in etc_block["block"]]
first_dest = etc_names.index("Ensure the tools directory exists")
require("etcdctl.yml: private directory, checksummed download, single-member extraction, then checks, then the destination",
        etc_names[:2] == ["Create a private working directory", "Restrict the working directory to root"]
        and etc_names.index("Download the pinned etcd release and verify its SHA-256") < etc_names.index("Extract etcdctl only")
        < etc_names.index("Inspect the extracted etcdctl") < etc_names.index("Require the extracted etcdctl to be a regular file")
        < etc_names.index("Run the extracted etcdctl from the working directory")
        < etc_names.index("Require the extracted etcdctl to report the pinned version") < first_dest)
require("etcdctl.yml: no destination path is touched before the checks",
        all("{{ secrets_encryption_tools_dir" not in json.dumps(t) and "{{ secrets_encryption_etcdctl_path" not in json.dumps(t)
            and "{{ secrets_encryption_verifier_path" not in json.dumps(t) for t in etc_block["block"][:first_dest]))
dl = next(t for t in etc_block["block"] if "ansible.builtin.get_url" in t)["ansible.builtin.get_url"]
ux = next(t for t in etc_block["block"] if "ansible.builtin.unarchive" in t)["ansible.builtin.unarchive"]
xs = next(t for t in etc_block["block"] if t["name"] == "Inspect the extracted etcdctl")["ansible.builtin.stat"]
require("etcdctl.yml: get_url verifies the pinned SHA-256 into the private directory; one member extracted there; lstat",
        dl["url"] == "{{ secrets_encryption_etcdctl_url }}" and dl["checksum"] == "sha256:{{ secrets_encryption_etcdctl_sha256 }}"
        and dl["dest"].startswith("{{ secrets_encryption_etcdctl_tmp.path }}/") and ux["remote_src"] is True
        and ux["dest"].startswith("{{ secrets_encryption_etcdctl_tmp.path }}/") and len(ux["include"]) == 1 and xs["follow"] is False)
require("etcdctl.yml: the working directory is removed in always, and the verifier is installed only after the block",
        [t["name"] for t in etc_block["always"]] == ["Remove the working directory"]
        and [t.get("name") for t in task_files["etcdctl"]].index("Install the local verifier")
        > [t.get("name") for t in task_files["etcdctl"]].index("Install the pinned etcdctl"))

# Forbidden text anywhere in the role and the Stage 3 playbooks.
stage3_text = "\n".join(list(task_text.values()) + [(ans / f"{n}.yml").read_text() for n in MUTATING]
                        + [(ans / "validate-secrets-encryption.yml").read_text()])
code_text = "\n".join(line for line in stage3_text.splitlines() if not line.lstrip().startswith("#"))
forbidden = {"cluster-reset": "cluster-reset", "snapshot restore": r"restore-path|etcd-snapshot,?\s*restore|snapshot restore",
             "rejoin or server URL changes": r"\brejoin\b|\bserver:\s|--server\b",
             "etcd-snapshot delete": "etcd-snapshot, delete|etcd-snapshot delete",
             "etcd-snapshot prune": "etcd-snapshot, prune|etcd-snapshot prune", "legacy prepare": r"secrets-encrypt, prepare|secrets-encrypt prepare",
             "legacy rotate": r"secrets-encrypt, rotate\]|secrets-encrypt rotate\b(?!-)", "rm": r"(^|[\s;&|])rm\s", "mv": r"(^|[\s;&|])mv\s",
             "server token": r"node-token|server/token|token-file", "encryption config": r"server/cred|encryption-config",
             "JSON/YAML object dumps": r"-o,\s*(json|yaml)\b|-o\s+(json|yaml)\b|--output[= ](json|yaml)",
             "all Secrets": r"get,\s*secrets\b|get secrets\b", "kubectl replace": r"kubectl.{0,40}replace",
             "etcd defrag or compact": r"defrag|compact", "ignore_errors": r"ignore_errors"}
for label, pattern in forbidden.items():
    require(f"forbidden: {label}", not re.search(pattern, code_text, re.MULTILINE))
absent_paths = [t["ansible.builtin.file"]["path"] for _, t in all_role_tasks if t.get("ansible.builtin.file", {}).get("state") == "absent"]
require("role: files removed only: the drop-in, canary values, the etcdctl working directory",
        sorted(absent_paths) == sorted(["{{ secrets_encryption_dropin_path }}", "{{ secrets_encryption_canary_dir }}",
                                        "{{ secrets_encryption_canary_dir }}/post.value", "{{ secrets_encryption_etcdctl_tmp.path }}"]))
write_dests = [(f, t[m]["dest"] if m != "ansible.builtin.lineinfile" else t[m]["path"], t[m]) for f, t in all_role_tasks
               for m in ("ansible.builtin.copy", "ansible.builtin.template", "ansible.builtin.lineinfile") if m in t]
require("role: files written only to the state directory, the drop-in or the rehearsal tools directory",
        all(d.startswith("{{ secrets_encryption_state_dir }}/") or d in ("{{ secrets_encryption_dropin_path }}",
            "{{ secrets_encryption_etcdctl_path }}", "{{ secrets_encryption_verifier_path }}") for _, d, _ in write_dests))
require("role: every state-file copy replaces rather than follows a link, and is root 0600",
        all(a.get("follow") is False and a.get("owner") == "root" and a.get("mode") == "0600"
            for _, d, a in write_dests if d.startswith("{{ secrets_encryption_state_dir }}/") and "dest" in a))
ledger = [(f, a) for f, d, a in write_dests if d == "{{ secrets_encryption_state_dir }}/confirmations"]
require("gate.yml: the ledger is appended only in gate.yml, after the safety and replay checks",
        [f for f, _ in ledger] == ["gate"]
        and [t["name"] for t in task_files["gate"]].index("Record the confirmation as used")
        > [t["name"] for t in task_files["gate"]].index("Require a root-only state directory on every server")
        > [t["name"] for t in task_files["gate"]].index("Refuse a confirmation that was already used"))
statedir = next(t for t in task_files["gate"] if t["name"] == "Ensure the Stage 3 state directory exists on every server")["ansible.builtin.file"]
require("gate.yml: the state directory is root:root 0700 and not followed",
        statedir == {"path": "{{ secrets_encryption_state_dir }}", "state": "directory", "owner": "root", "group": "root",
                     "mode": "0700", "follow": False})
canary_dir_task = next(t for t in task_files["canary"] if t.get("name") == "Ensure the canary value directory exists")
require("canary.yml: the value directory is root:root 0700",
        canary_dir_task["ansible.builtin.file"] == {"path": "{{ secrets_encryption_canary_dir }}", "state": "directory",
                                                    "owner": "root", "group": "root", "mode": "0700"})

# no_log on every task that can carry sensitive content.
SENSITIVE = [r"secrets-encrypt,\s*status|'secrets-encrypt', 'status'", r"\.value", r"urandom", r"--write-out=json", r"jsonpath=\{\.data"]


def needs_no_log(t):
    if module_of(t) not in ("ansible.builtin.command", "ansible.builtin.shell"):
        return False
    text = json.dumps(t)
    return any(re.search(p, text) for p in SENSITIVE) or t.get("ansible.builtin.command", {}).get("argv", [None])[1:3] == ["secrets-encrypt", "status"]


require("no_log: every status read, canary value, readback and raw etcd query hides its output",
        len([1 for _, t in all_role_tasks if needs_no_log(t)]) == 9 and all(t.get("no_log") is True for _, t in all_role_tasks if needs_no_log(t)))
RAW_REGISTERS = ["secrets_encryption_status_probe", "secrets_encryption_round_status", "secrets_encryption_rotate_wait",
                 "secrets_encryption_reencrypt_wait", "secrets_encryption_raw_probe", "secrets_encryption_readback_probe",
                 "secrets_encryption_status_input", "secrets_encryption_protected_probe"]
shown = [(f, t.get("name")) for f, t in all_role_tasks
         if module_of(t) in ("ansible.builtin.debug", "ansible.builtin.assert", "ansible.builtin.fail")
         and any(r in json.dumps({k: v for k, v in t.items() if k != "name"}) for r in RAW_REGISTERS)]
require("no raw status, raw record, readback result or protected path is ever shown in a message", shown == [])
require("parse_status.yml: the parsed fact keeps no raw line, error text, hash text or node name",
        not re.search(r"se_hash_value\s*}}|se_lines\s*}}|se_err_lines\s*}}|stdout|stderr", json.dumps(next(
            t for t in task_files["parse_status"] if t["name"] == "Parse the secrets-encryption status")["ansible.builtin.set_fact"])))
require("evaluate.yml: the report keeps allowlisted status fields, snapshot basenames and protected-artifact counts only",
        "['parsed', 'problems', 'unavailable', 'encryption', 'stage', 'hashes_match', 'key_count', 'active_key_type', 'active_key_name']"
        in task_text["evaluate"]
        and "map(attribute='protected') | map('length')" in task_text["evaluate"] and "map('basename')" in task_text["evaluate"])
require("checks.yml: protected artifacts are reported by number, never by path",
        "protected artifact #' ~ loop.index" in task_text["checks"] and "~ p ~" not in task_text["checks"].replace(" ", " "))


def order_ok(file, names):
    seq = [t.get("name") for t in walk(task_files[file])]
    return all(n in seq for n in names) and [seq.index(n) for n in names] == sorted(seq.index(n) for n in names)


require("enable.yml: decide, enforce, run, check, record the change",
        order_ok("enable", ["Decide whether enable is required", "Enforce the enable preconditions",
                            "Run secrets-encrypt enable on the first server", "Require the documented enable result", "Record the enable change"]))
require("rotate.yml: purpose, preconditions, rotate, wait, verify, record the change",
        order_ok("rotate", ["Decide the rotation purpose", "Enforce the rotation preconditions", "Run secrets-encrypt rotate-keys on the first server",
                            "Wait for re-encryption to finish", "Require encryption with the approved provider", "Record the rotation change"]))
require("rotate.yml: an additional rotation needs a reason and an approval naming this confirmation",
        "secrets_encryption_additional_rotation_reason" in task_text["rotate"]
        and "'additional-rotation:' ~ secrets_encryption_confirm_id" in task_text["rotate"])
require("restart.yml: preconditions, order, enable round, drop-in, decision, restart, waits, post-gate, round validation, then the verified record",
        order_ok("restart", ["Enforce the restart preconditions", "Enforce the restart order", "Enforce the enable restart round",
                             "Apply the requested drop-in state", "Record the drop-in change", "Decide the restart",
                             "Restart K3s on the target server", "Require the restarted server to be ready",
                             "Gather the cluster state after the restart", "Require a healthy cluster and no unplanned restarts",
                             "Wait for a readable status on every server after the enable restart round",
                             "Require Disabled, start and matching hashes on every server after the enable restart round",
                             "Record the passed post-restart gate"]))
# Rollback model: secretbox has no in-place way back to plaintext on K3s v1.36.4+k3s1
# (reencrypt rejected for secretbox; rotate-keys always encrypts). After
# activation the only rollback is restoring the pre-enable snapshot (p0).
ROLLBACK_DOC = (repo / "docs/secrets-encryption.md").read_text()
README_TEXT = (repo / "README.md").read_text()
VALIDATION_DOC = (repo / "docs/validation.md").read_text()
ARCH_DOC = (repo / "docs/architecture.md").read_text()
PLAYBOOK_NAMES = sorted(x.stem for x in ans.glob("*.yml"))
P0_RULE = ("secrets_encryption_rotation_purpose != 'enabling' or (secrets_encryption_enable_round.checkpoint_ok | bool "
           "and secrets_encryption_enable_round.ledger_ok | bool)")


def secrets_encrypt_subcommands(task_map):
    out = set()
    for ts in task_map.values():
        for t in walk(ts):
            a = t.get("ansible.builtin.command", {}).get("argv", [])
            if a[1:2] == ["secrets-encrypt"] and len(a) > 2:
                out.add(a[2])
    return out


def no_inplace_rollback(task_map, texts, playbook_names, vars_):
    banned = set(vars_.get("secrets_encryption_unsupported_rollback_commands", []))
    code = "\n".join(line for text in texts.values() for line in text.splitlines() if not line.lstrip().startswith("#"))
    return (banned == {"disable", "reencrypt", "prepare", "rotate"}
            and not secrets_encrypt_subcommands(task_map) & banned
            and not re.search(r"secrets-encrypt,?\s+(disable|reencrypt|prepare|rotate)\b(?!-)", code)
            and not {"disable", "reencrypt-after-disable"} & set(vars_["secrets_encryption_mutating_phases"])
            and not {"disable", "reencrypt-after-disable"} & set(vars_["secrets_encryption_change_phases"])
            and not any("disable" in n or "reencrypt" in n for n in playbook_names)
            and "disable" not in task_map and "reencrypt" not in task_map)


def flag_removal_preactivation_only(restart_text, guard_text):
    return ("or (se_encryptions == ['disabled'] and secrets_encryption_marker.phase == 'enable')" in restart_text
            and "reencrypt-after-disable" not in restart_text
            and ("se_path: \"{{ 'flag-removal' if (secrets_encryption_phase == 'restart' and secrets_encryption_flag_state != 'present') "
                 "else '' }}\"") in guard_text)


def rotation_requires_p0(rotate_tasks):
    t = next((t for t in rotate_tasks if t.get("name") == "Enforce the rotation preconditions"), {})
    return P0_RULE in [" ".join(x.split()) for x in t.get("ansible.builtin.assert", {}).get("that", [])]


def rotate_never_plaintext(rotate_tasks):
    req = next((t for t in walk(rotate_tasks) if t.get("name") == "Require encryption with the approved provider"), {})
    that = req.get("ansible.builtin.assert", {}).get("that", [])
    dec = json.dumps(next((t for t in rotate_tasks if t.get("name") == "Decide the rotation purpose"), {}))
    return ("secrets_encryption_parsed.encryption == 'enabled'" in that
            and "secrets_encryption_parsed.active_key_type == secrets_encryption_expected_key_type" in that
            and "'disable'" not in dec and "reencrypt-after-disable" not in dec and "'disabled-no-config'" not in dec
            and "secrets_encryption_marker.phase == 'enable'" in dec and "secrets_encryption_marker.phase == 'rotate-keys'" in dec)


def docs_rollback_consistent(doc, readme, validation):
    return (all(x in doc for x in ("reencrypt does not support secretbox key type, use rotate-keys instead", "## Rollback",
                                   "pre-enable snapshot", "--cluster-reset-restore-path", "is not supported",
                                   "rotate-keys` cannot convert", "Disabled-but-not-rewritten"))
            and not re.search(r"\(\.\./ansible/secrets-encryption-(disable|reencrypt)\.yml\)", doc)
            and not re.search(r"(ansible-playbook\s+)?secrets-encryption-(disable|reencrypt)\.yml", doc + readme + validation)
            and "snapshot restore" in validation.lower() and "snapshot restore" in readme.lower())


P0_OK_TERMS = ("not se_malformed | bool and not secrets_encryption_ledger_malformed | bool",
               "se_newest_name is match('^stage3-' ~ (secrets_encryption_p0_checkpoint | regex_escape) ~ '-')",
               "se_newest_records | length == 1 and se_last_snapshot | bool")
P0_RECORD_LINE = ("{{ secrets_encryption_snapshot_stat.stat.mtime | int }} {{ secrets_encryption_snapshot_checkpoint }} "
                  "{{ secrets_encryption_snapshot_new[0] }} {{ secrets_encryption_snapshot_stat.stat.size }} "
                  "{{ secrets_encryption_snapshot_stat.stat.checksum }} token=present")


def token_stat_only(task_map):
    """The server token file is only ever lstat'ed: no checksum, MIME type, attributes, content or other use."""
    uses = [(f, x) for f, ts in task_map.items() for x in walk(ts) if "secrets_encryption_token_file" in json.dumps(x)]
    if len(uses) != 1 or uses[0][0] != "snapshot":
        return False
    st = uses[0][1].get("ansible.builtin.stat", {})
    reg_uses = [x for _, ts in task_map.items() for x in walk(ts) if "secrets_encryption_token_stat" in json.dumps(x)]
    return (set(uses[0][1]) == {"name", "ansible.builtin.stat", "register"} and st.get("path") == "{{ secrets_encryption_token_file }}"
            and st.get("get_checksum") is False and st.get("get_mime") is False and st.get("get_attributes") is False
            and st.get("follow") is False and "checksum_algorithm" not in st
            and [x.get("name") for x in reg_uses] == ["Inspect the server token file without reading it",
                                                      "Require the server token file for a restorable checkpoint"]
            and "ansible.builtin.assert" in reg_uses[1])


def checkpoint_record_fixed(snapshot_tasks, summarize_text):
    names = [x.get("name") for x in snapshot_tasks]
    rec = next((x for x in snapshot_tasks if x.get("name") == "Record the checkpoint metadata"), {}).get("ansible.builtin.lineinfile", {})
    return (" ".join(str(rec.get("line", "")).split()) == P0_RECORD_LINE
            and rec.get("path") == "{{ secrets_encryption_state_dir }}/checkpoints" and rec.get("mode") == "0600"
            and names.index("Inspect the server token file without reading it") < names.index("Take the on-demand etcd snapshot")
            < names.index("Require a non-empty regular snapshot file") < names.index("Record the checkpoint metadata")
            and "[0-9a-f]{64} token=present$" in summarize_text)


def enable_requires_p0(enable_tasks, summarize_text):
    names = [x.get("name") for x in enable_tasks]
    req = next((x for x in enable_tasks if x.get("name") == "Require the recorded pre-enable checkpoint"), {})
    run = next((i for i, x in enumerate(enable_tasks) if "secrets-encrypt enable" in json.dumps(x) or "block" in x), len(enable_tasks))
    flat = " ".join(summarize_text.split())
    return ("Require the recorded pre-enable checkpoint" in names and names.index("Require the recorded pre-enable checkpoint") < run
            and req.get("ansible.builtin.assert", {}).get("that") == ["secrets_encryption_enable_decision == 'done' or secrets_encryption_p0.ok | bool"]
            and all(x in flat for x in P0_OK_TERMS)
            and "se_last_snapshot: \"{{ secrets_encryption_ledger_events[-1:] == ['snapshot ' ~ groups['servers'][0]] }}\"" in summarize_text)


def round_requires_recorded_p0(summarize_tasks):
    rt = next((x for x in summarize_tasks if x.get("name") == "Summarize the enable restart round"), {})
    ck = " ".join(str(rt.get("vars", {}).get("se_checkpoint_ok", "")).split())
    return ("secrets_encryption_p0.p0_records | select('search', key | regex_escape) | list | length > 0" in ck
            and "f.mtime | int < secrets_encryption_marker.epoch | int" in ck and "not secrets_encryption_p0.records_malformed | bool" in ck)


def configured_disabled_preactivation(validate_text, parse_text):
    flat = " ".join(validate_text.split())
    return ("(secrets_encryption_expect == 'configured-disabled' and se_encryptions == ['disabled'] "
            "and secrets_encryption_marker.phase == 'enable')" in flat and "      Disabled: disabled\n" in parse_text)


RESTORE_DOC_PHRASES = (
    "rolls back all Kubernetes and etcd state created or changed after p0, not only the encryption configuration",
    "**Operator impact acknowledgment.**", "No future live restore starts without a written acknowledgment",
    "**`disable` is not accepted or used.**", "**`Disabled` is still parsed and reported.**", "no supported mutating phase creates it",
    "### The pre-enable checkpoint (p0)", "**Created immediately before `enable`.**", "**Verified and fresh.**",
    "**Stored on the designated first server.**", "**Name and checksum recorded as metadata.**",
    "**Matching server token availability confirmed, never read.**", "never read, displayed, copied or hashed",
    "### Restore procedure (manual, separately approved)", "This automation does not run it.", "https://docs.k3s.io/cli/etcd-snapshot",
    "**Stop K3s on every server:**", "`k3s server --cluster-reset --cluster-reset-restore-path=<p0 path>`", "**Start K3s on `k3s01` normally:**",
    "**Rejoin `k3s02`, then `k3s03`:**", "**Rebuild a peer that does not rejoin.**",
    "**All three servers return Ready.**", "**All three etcd endpoints are healthy.**", "**The pre-enable plaintext controls return byte-for-byte:**",
    "**The post-enable Secret and ConfigMap canaries are absent.**", "**Encryption status returns to the original not-configured state:**",
    "**The encryption drop-in is absent**", "**The container lifecycle contains only planned events:**",
    "removes the cluster, its volumes, the kubeconfigs, the temporary worktree and every rehearsal process",
    "A passing static test run is not completion.")


def docs_restore_defined(doc, readme, validation):
    """The restore impact, p0 definition, official sequence, acceptance criteria, and no claim that disable restores plaintext."""
    live = doc[doc.find("## Live Rollout"):doc.find("### Stop conditions")]
    order = [live.find(x) for x in ("secrets_encryption_canary_action=create-control", "secrets_encryption_snapshot_checkpoint=p0-pre-enable",
                                    "secrets-encryption-enable.yml")]
    return (all(x in doc for x in RESTORE_DOC_PHRASES) and -1 not in order and order == sorted(order)
            and not re.search(r"leaves plaintext|successfully rewrites|disable[^.\n]{0,60}rewrites? [^.\n]{0,40}plaintext", doc + readme + validation)
            and "is not Stage 3 completion" in validation and "is not completion" in readme)


require("role: no phase runs secrets-encrypt disable, reencrypt, prepare or rotate, and no rollback phase or playbook exists",
        no_inplace_rollback(task_files, task_text, PLAYBOOK_NAMES, role_vars))
require("restart.yml and guard.yml: drop-in removal only before activation (marker enable); the only path that needs rehearsal approval",
        flag_removal_preactivation_only(task_text["restart"], task_text["guard"]))
require("rotate.yml: the enabling rotation requires the pre-enable snapshot (the rollback boundary) and a consistent ledger",
        rotation_requires_p0(task_files["rotate"]))
require("rotate.yml: rotate-keys only after enable or a completed rotation, and always ends Enabled with secretbox (never a plaintext rollback)",
        rotate_never_plaintext(task_files["rotate"]))
require("docs: in-place conversion to plaintext documented as unsupported; rollback after activation is the pre-enable snapshot restore; no R1/R3 playbook named",
        docs_rollback_consistent(ROLLBACK_DOC, README_TEXT, VALIDATION_DOC))
require("snapshot.yml: the server token file is only inspected by lstat (no checksum, MIME type, attributes or content)",
        token_stat_only(task_files))
require("snapshot.yml: token check before the save; the checkpoint record has the fixed metadata format and is parsed strictly",
        checkpoint_record_fixed(task_files["snapshot"], task_text["summarize"]))
require("enable.yml: enable requires the recorded p0 as the newest Stage 3 snapshot, taken by the last accepted invocation",
        enable_requires_p0(task_files["enable"], task_text["summarize"]))
require("summarize.yml: the enable round requires a recorded p0 (name and size match its record) older than the marker",
        round_requires_recorded_p0(task_files["summarize"]))
require("validate: configured-disabled requires the last change enable; the parser still maps Disabled for diagnosis",
        configured_disabled_preactivation((ans / "validate-secrets-encryption.yml").read_text(), task_text["parse_status"]))
def doc_section(doc, start, end):
    a = doc.find(start)
    b = doc.find(end, a + 1) if a >= 0 else -1
    return doc[a:b] if a >= 0 and b > a else ""


def in_order(text, phrases):
    pos = [text.find(x) for x in phrases]
    return -1 not in pos and pos == sorted(pos)


REAL_RESTORE = ("### Restore procedure (manual, separately approved)", "#### Accepting the reset")
K3D_RESTORE = ("### Restore in the k3d rehearsal (rehearsal tooling only)", "## Fresh Builds and Replacement Joins")
RESET_ACCEPT = ("#### Accepting the reset", "#### Encryption files during a restore")
ENC_FILES = ("#### Encryption files during a restore", "### Restore in the k3d rehearsal")


def docs_restore_mechanism(doc):
    """Real servers: explicit reset invocation, never config-file fields, never the k3d runner. The reset is accepted only
    with exit 0, the ERROR-level documented message and the reset flag. Retained encryption files prove nothing. The k3d
    rehearsal restore keeps S1's identity, refuses unsafe address handoffs and is documented as rehearsal tooling only."""
    real, k3d = doc_section(doc, *REAL_RESTORE), doc_section(doc, *K3D_RESTORE)
    acc, enc = doc_section(doc, *RESET_ACCEPT), doc_section(doc, *ENC_FILES)
    real_ok = (
        "**This is the procedure for the real servers**" in real
        and "**Reset and restore on `k3s01`, by explicit invocation:**" in real
        and "`k3s server --cluster-reset --cluster-reset-restore-path=<p0 path>` in the foreground" in real
        and "Never deliver the reset by writing `cluster-reset` fields into a configuration file" in real
        and "are **never** a recovery method for the real servers" in real
        and in_order(real, ("**Stop K3s on every server:**", "**Return every server to the pre-enable configuration:**",
                            "by explicit invocation:**", "**Start K3s on `k3s01` normally:**", "**Rejoin `k3s02`, then `k3s03`:**"))
        and not re.search(r"docker|--volumes-from|runner|network (dis)?connect", real.split("are **never** a recovery method")[1], re.I)
        and not re.search(r"^\s*cluster-reset(-restore-path)?:\s", doc, re.M))
    accept_ok = (
        all(x in acc for x in ("**exit status 0**", "**ERROR level**", 'level=error msg="Shutdown request received:',
                               "The reset is accepted **only** when all three hold", "the process exited with status 0",
                               "restart without --cluster-reset flag now", "/var/lib/rancher/k3s/server/db/reset-flag",
                               "The ERROR level of that line is not a failure, and exit status 0 alone is not success",
                               "do not start `k3s01`")))
    enc_ok = all(x in enc for x in (
        "the encryption drop-in is moved aside before the reset", "**remain on disk**",
        "**Their presence alone must not be interpreted as active encryption**",
        "The effective state after a restore is established only by the post-restore status",
        "API readbacks and raw etcd checks"))
    k3d_ok = (
        all(x in k3d for x in (
            "None of them is a recovery method for the real servers",
            "Refuse before any shutdown if a disconnect and reconnect could not rebuild the network attachment exactly",
            "Its container and volumes are never deleted or recreated",
            "held by no endpoint and reserved by no other container; otherwise stop",
            "An address-allocation failure is a rehearsal-harness failure, not a restore result",
            "`/bin/k3s server <S1's own server arguments> --cluster-reset --cluster-reset-restore-path=<p0> --token-file=<server token file>`",
            "No token or join URL is passed in the environment or on the command line", "S1 stays stopped",
            "the container identity, hostname, network, address, prefix, gateway, aliases and volumes must be unchanged",
            "two collectors", "reports every runner exit status as a number", "INFO and ERROR lines"))
        and in_order(k3d, ("**Record S1's identity before the stop:**", "**Stop all three server containers concurrently**",
                           "**Move the drop-in aside**", "**Disconnect only S1**", "**Run the explicit reset**", "**Accept the reset**",
                           "**Remove the runner, prove the address is free again, and reconnect the original S1**", "**Rejoin S2, then S3**")))
    return real_ok and accept_ok and enc_ok and k3d_ok


require("docs: restore by explicit invocation on the real servers; reset accepted by exit 0, ERROR-level message and reset flag; retained encryption files are no proof; k3d runner with a safe network handoff is rehearsal tooling only",
        docs_restore_mechanism(ROLLBACK_DOC))
STALE_STATUS = re.compile(
    r"k3d rehearsal has \*\*not\*\* passed|required k3d rehearsal has \*\*not passed\*\*|has \*\*not\*\* passed a rehearsal|"
    r"not yet passed a rehearsal|has not yet passed a rehearsal|implemented and statically tested only|It is statically tested only|"
    r"complete rehearsal with the corrected restore has \*\*not\*\* run|complete rehearsal has not been run with the corrected restore|"
    r"three-VM rehearsal is still pending|three-VM rehearsal pending|recorded as an open observation for the three-VM rehearsal")
# The live rollout (2026-10-28 to 2026-10-29) is recorded as performed. A claim that it was not is stale; a claim the
# live record does not support (a live restore, raw etcd checks run live, plaintext proven absent) is an overclaim.
LIVE_STALE = re.compile(
    r"live rollout is not approved|not approved and not performed|not approved for or applied to the live cluster|"
    r"has \*\*not\*\* been run against the live cluster|not been approved for or applied to the live cluster|"
    r"encryption state, which remains disabled|Stage 3 is not complete\*\* and has not been applied|"
    r"stored in etcd without encryption at rest|Live Rollout \(Not Yet Approved\)", re.I)
OVERCLAIM = re.compile(
    r"(?<!no )live restore (was|has been) (performed|rehearsed|passed)|restored? (was|has been) rehearsed on the live|"
    r"raw (etcd )?(checks?|verification) (was|were|has been|have been) (run|performed|passed) (live|on the live)|"
    r"plaintext (is|was) (proven )?absent from etcd|no plaintext remains", re.I)
LIVE_RECORD = ("### Live rollout record (2026-10-28 to 2026-10-29: complete)", "## Rollback")
LIVE_FACTS = ("`09ce4af`", "`6cfa7fd`", "`7fd364f`", "`9f46215`", "`stage3-p0-pre-enable-20261028t213918z-k3s01-1793223582`",
              "`stage3-p1-pre-rotate-20261029t135952z-k3s01-1793282417`", "`stage3-p2-post-encryption-20261029t144551z-k3s01-1793285175`",
              "`6f7a54c20814228a0640029f9bb9e21f6f2db06c6770f7a8d7c11b44b532dab6`",
              "`c9f0e9c3ee4c967fd7de8b71234ab70d716835cab85c885da61f9a69ce0baffc`",
              "Raw etcd checks were **not run**", "no live restore was performed", "systemd reset its `NRestarts` from 59 to 0")
DECODE_WINDOW = ("### After rotate-keys: the Secret-decode window", "### Stop conditions")
THREE_VM_RECORD = ("### Three-VM rehearsal record (2026-10-27, commit 825b09b: passed)", "### Rehearsal questions")
THREE_VM_FACTS = ("825b09b2b9bfffef1e227a843600a83665664d99", "0dea72001a3c757bc946e3f7259a9595ab242806",
                  "`stage3-vm-rehearsal-evidence-20261027.tar.gz`, 208 files, 132,209 bytes, SHA-256 "
                  "`078219c49d7572bab3f128cefd6496f3e94536349fb97490e8c83c549bf2ab80`",
                  "The rehearsal **is not approval**", "**not applicable** in this rehearsal", "**every server stopped with exit status 0**")
SENSITIVE_IN_RECORD = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b|[A-Za-z]:\\|/home/|/mnt/")


def docs_status_current(doc, readme, validation, arch):
    """Both rehearsals recorded as passed: k3d (run 8) and three-VM (825b09b, with both corrections, the evidence and no host
    addresses, MAC addresses or workstation paths). The live rollout (2026-10-28 to 2026-10-29) recorded as complete, in a
    sanitized record with its commits, checkpoints, evidence manifests, the counter defect and the claims it does not make; the
    post-rotation Secret-decode window in the procedure and its stop conditions; every summary current. No stale "not passed",
    "pending" or "not performed" claim and no overclaim; S1's k3d exit 1 recorded with the systemd result."""
    texts = (doc, readme, validation, arch)
    s1_obs = doc_section(doc, "**S1 shutdown observation:**", "**Encryption files:** see")
    record = doc_section(doc, *THREE_VM_RECORD)
    live = doc_section(doc, *LIVE_RECORD)
    window = doc_section(doc, *DECODE_WINDOW)
    return (
        not any(STALE_STATUS.search(x) for x in texts) and not any(OVERCLAIM.search(x) for x in texts)
        and not any(LIVE_STALE.search(x) for x in texts)
        and "**The required disposable k3d rehearsal passed on 2026-10-26**" in doc
        and "### k3d rehearsal record (2026-10-26, run 8: passed)" in doc
        and "**The three-VM rehearsal passed on 2026-10-27**" in doc
        and "**The live rollout ran from 2026-10-28 to 2026-10-29 and reached every completion condition**" in doc
        and live != "" and all(x in live for x in LIVE_FACTS) and not SENSITIVE_IN_RECORD.search(live)
        and window != "" and "`Internal error occurred: no matching prefix found`" in window and "without the 10-minute waits" in window
        and "returns to Ready by itself, with no `flux reconcile`" in window
        and "except the [decode window](#after-rotate-keys-the-secret-decode-window)" in doc
        and "### Stage 3 live rollout" in validation and "Active on the live cluster since 2026-10-29" in readme
        and "encrypted at rest with secretbox since 2026-10-29" in arch
        and record != "" and all(x in record for x in THREE_VM_FACTS) and not SENSITIVE_IN_RECORD.search(record)
        and "rehearsal **passed on 2026-10-26 (run 8)**" in validation and "three-VM rehearsal **passed on 2026-10-27**" in validation
        and "passed the required disposable k3d rehearsal" in readme and "three-VM rehearsal passed on 2026-10-27" in readme
        and "passed the required disposable k3d rehearsal" in arch and "three-VM rehearsal passed on 2026-10-27" in arch
        and all(x in s1_obs for x in ("S2 and S3 exited 143; **S1 exited 1**", "was not OOM-killed and was not restarted",
                                      "The cause of the exit status 1 was not determined",
                                      "not as expected behavior and not as evidence of failure",
                                      "**It did not reproduce under systemd:**"))
        and "did not compare their inode or modification time after the restore" in doc
        and "not applicable** in disposable k3d and are not claimed as passed" in doc)


require("docs: k3d and three-VM rehearsals recorded as passed (three-VM record sanitized, with both corrections and the evidence); live rollout recorded as complete in a sanitized record; post-rotation decode window in the procedure; no stale or overclaimed status; S1's k3d exit 1 recorded with the systemd result",
        docs_status_current(ROLLBACK_DOC, README_TEXT, VALIDATION_DOC, ARCH_DOC))
require("docs: restore impact and acknowledgment, p0 definition, official restore sequence with S2/S3, acceptance criteria, disable not used",
        docs_restore_defined(ROLLBACK_DOC, README_TEXT, VALIDATION_DOC))
KEY_MATERIAL = ("### Key material and the off-node recovery copy", "## Fresh Builds and Replacement Joins")


def docs_key_recovery_aligned(doc):
    """The key-recovery section matches the merged home-cluster encryption-config helper (pull request #21, 3bb8199): its
    comparisons report MATCH, DIFFER or ERROR, and it never records the source or plaintext size."""
    sec = doc_section(doc, *KEY_MATERIAL)
    return (sec != "" and "`MATCH`, `DIFFER` or `ERROR`" in sec and "never report the plaintext's size or hash" in sec
            and "pull request #21 (commit `3bb8199`)" in sec
            and not re.search(r"MISMATCH|source file's size|(source|plaintext)( file)?'?s? size and", sec))


require("docs: the key-recovery section matches the home-cluster encryption-config helper (MATCH, DIFFER or ERROR; no source size)",
        docs_key_recovery_aligned(ROLLBACK_DOC))
require("gate.yml: every check before any write",
        order_ok("gate", ["Gather the cluster state", "Evaluate preservation and snapshot freshness", "Enforce the common health gate",
                          "Enforce the exclusive enable restart round", "Enforce snapshot and database preservation", "Enforce snapshot freshness", "Refuse a confirmation that was already used",
                          "Ensure the Stage 3 state directory exists on every server", "Require a root-only state directory on every server",
                          "Record the preservation baseline on every server", "Record the confirmation as used"]))
require("snapshot.yml: unique name, metadata before, save, metadata after, preservation re-checked",
        order_ok("snapshot", ["Require a unique snapshot name", "Record the snapshot metadata before the save", "Take the on-demand etcd snapshot",
                              "Compare the snapshot metadata", "Require exactly one new snapshot and no protected change",
                              "Re-evaluate preservation after the snapshot", "Require preservation after the snapshot"]))
verify_block = next(t for t in task_files["canary"] if t.get("name") == "Verify encryption with the canaries")
require("canary.yml: verify always cleans up; create-control cleans up on failure",
        [t["name"] for t in verify_block["always"]] == ["Clean up the canaries after verification"]
        and next(t for t in task_files["canary"] if t.get("name") == "Create the positive controls")["rescue"][0]["name"]
        == "Clean up after a failed control creation")

# k3s-server and site.yml.
inc = next(t for t in k3s_server_tasks if t.get("name") == "Install the secrets-encryption drop-in before K3s first starts")
require("k3s-server: default keeps fresh builds unencrypted until the post-live flip",
        k3s_server_defaults == {"k3s_secrets_encryption_enabled": False})
require("k3s-server: installed-server markers are role vars", k3s_server_vars == {"k3s_server_binary_path": "/usr/local/bin/k3s",
                                                                                  "k3s_server_data_dir": "/var/lib/rancher/k3s"})
require("k3s-server: the drop-in only when enabled and neither the K3s binary nor K3s data exists, before any K3s install",
        inc["when"] == ["k3s_secrets_encryption_enabled | bool", "not k3s_server_binary.stat.exists", "not k3s_server_data.stat.exists"]
        and inc["ansible.builtin.include_role"] == {"name": "secrets-encryption", "tasks_from": "dropin.yml"}
        and inc["vars"] == {"secrets_encryption_dropin_state": "present"}
        and k3s_server_tasks.index(inc) < min(i for i, t in enumerate(k3s_server_tasks) if "Install pinned k3s" in t.get("name", "")))
require("k3s-server: the role never removes the drop-in and never restarts K3s",
        not any(t.get("vars", {}).get("secrets_encryption_dropin_state") == "absent" or "ansible.builtin.systemd_service" in t
                for t in k3s_server_tasks))
require("site.yml: Stage 3 is not activated", "secrets-encryption" not in site_text and "secrets_encryption" not in site_text)

# The corrected step 1 and the enable restart round (k3d rehearsal, 2026-10-23:
# status is unavailable between enable and the first restart round). Each
# predicate is applied to the real files here and to mutated copies below.
ENABLE_BLOCK = "Enable secrets encryption with an identity configuration"
ROUND_CHECK = "Validate the status after the enable restart round"
ROUND_ENFORCE = "Enforce the enable restart round"
ROUND_INNER = ["Wait for a readable status on every server after the enable restart round",
               "Reset the status parsed after the enable restart round", "Parse the status after the enable restart round",
               "Require Disabled, start and matching hashes on every server after the enable restart round"]


def status_reads(tasks):
    return [t.get("name") for t in walk(tasks)
            if t.get("ansible.builtin.command", {}).get("argv", [None])[1:3] == ["secrets-encrypt", "status"]
            or "parse_status.yml" in str(t.get("ansible.builtin.include_tasks", ""))]


def enable_reads_no_status(tasks):
    return status_reads(tasks) == [] and "secrets_encryption_parsed" not in json.dumps(tasks)


def enable_result_exact(tasks):
    block = next((t for t in walk(tasks) if t.get("name") == ENABLE_BLOCK), {}).get("block", [])
    if [t.get("name") for t in block][:4] != ["Run secrets-encrypt enable on the first server", "Require the documented enable result",
                                               "Read the time after enable", "Record the enable change"]:
        return False
    run, req, _, rec = block[:4]
    that = req.get("ansible.builtin.assert", {}).get("that", [])
    marker_writes = [t for t in walk(tasks) if "/last-change" in str(t.get("ansible.builtin.copy", {}).get("dest", ""))]
    return (run.get("failed_when") is False and "secrets_encryption_enable_result.rc == 0" in that
            and "secrets_encryption_enable_result.stdout_lines | default([]) == ['secrets-encryption enabled']" in that
            and marker_writes == [rec] and rec["ansible.builtin.copy"]["content"].endswith(" enable\n"))


def restart_validates_round(tasks):
    names = [t.get("name") for t in tasks]
    if ROUND_CHECK not in names or "Read the time of the passed post-restart gate" not in names:
        return False
    v = tasks[names.index(ROUND_CHECK)]
    inner = v.get("block", [])
    req = json.dumps(inner[-1]) if inner else ""
    return (names.index("Require a healthy cluster and no unplanned restarts") < names.index(ROUND_CHECK)
            < names.index("Read the time of the passed post-restart gate") < names.index("Record the passed post-restart gate")
            and v.get("when") == ["secrets_encryption_marker.phase == 'enable'", "secrets_encryption_flag_state == 'present'",
                                  "inventory_hostname == groups['servers'][-1]"]
            and [t.get("name") for t in inner] == ROUND_INNER and inner[0].get("no_log") is True
            and all(s in req for s in ("p.parsed | default(false) | bool", "p.encryption | default('') == 'disabled'",
                                       "p.stage | default('') == 'start'", "p.hashes_match | default(false) | bool", "se_not_ready == ''")))


def restart_enforces_round(tasks):
    names = [t.get("name") for t in tasks]
    if ROUND_ENFORCE not in names:
        return False
    t = tasks[names.index(ROUND_ENFORCE)]
    return (names.index("Enforce the restart order") < names.index(ROUND_ENFORCE) < names.index("Apply the requested drop-in state")
            and t["ansible.builtin.assert"]["that"] == ["se_round.ledger_ok | bool", "se_round.checkpoint_ok | bool", "se_round.out_of_order == ''",
                                                        "not (se_round.complete | bool)", "inventory_hostname == se_round.next"]
            and t.get("when") == ["secrets_encryption_marker.phase == 'enable'", "secrets_encryption_flag_state == 'present'"])


def tolerance_scoped(evaluate_text, restart_text, summarize_text):
    ev = [line for line in evaluate_text.splitlines() if "status.unavailable" in line]
    rs = [line for line in restart_text.splitlines() if "st.unavailable" in line]
    return (len(ev) == 1 and "not (se_round.tolerate_unavailable_status | bool and s.status.unavailable" in ev[0]
            and 'se_round: "{{ secrets_encryption_enable_round }}"' in evaluate_text
            and len(rs) == 1 and "se_tolerate | bool and (st.unavailable" in rs[0]
            and 'se_tolerate: "{{ secrets_encryption_enable_round.tolerate_unavailable_status | bool }}"' in restart_text
            and all(s in summarize_text for s in (
                "se_active | bool and not se_complete | bool and se_out_of_order == ''",
                "and se_ledger_ok | bool and se_checkpoint_ok | bool",
                "and (secrets_encryption_phase | default('')) == 'restart'",
                "and secrets_encryption_flag_state == 'present' }}",
                'se_complete: "{{ se_prefix | int == se_servers | length }}"')))


def no_status_option(defaults, vars_, guard_tasks):
    pattern = re.compile(r"ignore|tolerat|unavailable|skip|allow_unparsed|status_optional|lenient")
    gathered = vars_.get("secrets_encryption_gathered_facts", [])
    refuse = next((t for t in guard_tasks if t.get("name") == "Refuse injected gathered state"), {})
    return (not any(pattern.search(k) for k in list(defaults) + list(vars_))
            and {"secrets_encryption_enable_round", "secrets_encryption_servers", "secrets_encryption_status_by_server",
                 "secrets_encryption_marker", "secrets_encryption_ledger_events", "secrets_encryption_storage"} <= set(gathered)
            and refuse.get("loop") == "{{ secrets_encryption_gathered_facts }}"
            and refuse.get("ansible.builtin.assert", {}).get("that")
            == ["lookup('ansible.builtin.vars', item, default='__not-defined__') == '__not-defined__'"])


def unavailable_is_narrow(parse_text):
    return ('level=fatal msg="Error: see server log for details: Internal error occurred: secret-encrypt error ID [0-9]{1,8}"$' in parse_text
            and "se_rc | int not in [0, -1] and se_lines | length == 0" in parse_text
            and "and se_err_lines | select('search', se_unavailable_re) | list | length == 1" in parse_text
            and "and se_err_lines | select('search', 'level=fatal') | list | length == 1" in parse_text
            and "parsed: \"{{ se_problems | length == 0 }}\"" in parse_text)


require("enable.yml: no secrets-encrypt status is read after enable (status is unavailable before the first restart round)",
        enable_reads_no_status(task_files["enable"]))
require("enable.yml: the exact result (exit 0, exactly 'secrets-encryption enabled') is checked before the only marker write",
        enable_result_exact(task_files["enable"]))
require("restart.yml: the last server's run requires Disabled/start/matching hashes on every server before the verified record",
        restart_validates_round(task_files["restart"]))
require("restart.yml: the enable round requires ledger, checkpoint, no out-of-order evidence, an incomplete round and the next server",
        restart_enforces_round(task_files["restart"]))
require("evaluate.yml, restart.yml, summarize.yml: an unavailable status is tolerated only inside the computed enable restart round",
        tolerance_scoped(task_text["evaluate"], task_text["restart"], task_text["summarize"]))
require("role: no variable relaxes status handling, and the guard refuses injected gathered state",
        no_status_option(role_defaults, role_vars, task_files["guard"]))
require("parse_status.yml: 'unavailable' is only the observed failure, and never makes a result parsed",
        unavailable_is_narrow(task_text["parse_status"]))
require("role: 'unavailable' appears only in parse_status, summarize, evaluate and restart",
        sorted(f for f, text in task_text.items() if "unavailable" in text) == ["evaluate", "parse_status", "restart", "summarize"])
require("rotate.yml: the enabling rotation still requires every server Disabled at start, verified, with the drop-in and matching hashes",
        all(s in task_text["rotate"] for s in ("se_encryptions == ['disabled'] and se_stages == ['start']",
                                                "selectattr('checkpoint_reached', 'equalto', false)", "selectattr('dropin_present', 'equalto', false)",
                                                "selectattr('hashes_match', 'equalto', false)")))

# Structural mutations: each reintroduces a defect and must be detected.
OLD_POST_ENABLE = [
    {"name": "Read the first server's status after enable",
     "ansible.builtin.command": {"argv": ["{{ secrets_encryption_k3s_bin }}", "secrets-encrypt", "status"]},
     "register": "secrets_encryption_after_enable", "changed_when": False, "failed_when": False, "no_log": True},
    {"name": "Parse the status after enable", "ansible.builtin.include_tasks": "parse_status.yml",
     "vars": {"secrets_encryption_status_input": "{{ secrets_encryption_after_enable }}"}},
    {"name": "Require an identity configuration without encryption",
     "ansible.builtin.assert": {"that": ["secrets_encryption_parsed.parsed | bool", "secrets_encryption_parsed.encryption == 'disabled'"],
                                "quiet": True}}]


def mutate(tasks, fn):
    out = copy.deepcopy(tasks)
    fn(out)
    return out


def enable_block_of(tasks):
    return next(t for t in walk(tasks) if t.get("name") == ENABLE_BLOCK)["block"]


def insert_old_status(tasks):
    b = enable_block_of(tasks)
    i = [t["name"] for t in b].index("Show the next step after enable")
    b[i:i] = copy.deepcopy(OLD_POST_ENABLE)


def drop_that(task_name, item):
    def fn(tasks):
        t = next(t for t in walk(tasks) if t.get("name") == task_name)
        t["ansible.builtin.assert"]["that"].remove(item)
    return fn


def marker_first(tasks):
    b = enable_block_of(tasks)
    b.insert(1, b.pop(3))


def remove_named(name):
    def fn(tasks):
        tasks[:] = [t for t in tasks if t.get("name") != name]
    return fn


def validation_after_record(tasks):
    names = [t.get("name") for t in tasks]
    v = tasks.pop(names.index(ROUND_CHECK))
    tasks.append(v)


def validation_everywhere(tasks):
    next(t for t in tasks if t.get("name") == ROUND_CHECK)["when"] = ["secrets_encryption_marker.phase == 'enable'"]


def validation_ignores_hashes(tasks):
    req = next(t for t in tasks if t.get("name") == ROUND_CHECK)["block"][-1]
    req["vars"]["se_not_ready"] = req["vars"]["se_not_ready"].replace(" and p.hashes_match | default(false) | bool", "")


EV, RS, SM = task_text["evaluate"], task_text["restart"], task_text["summarize"]
structural_mutants = [
    ("the old post-enable status assertion", lambda: enable_reads_no_status(mutate(task_files["enable"], insert_old_status))),
    ("the enable result checked by exit status only", lambda: enable_result_exact(mutate(task_files["enable"], drop_that(
        "Require the documented enable result", "secrets_encryption_enable_result.stdout_lines | default([]) == ['secrets-encryption enabled']")))),
    ("the enable result checked by output only", lambda: enable_result_exact(mutate(task_files["enable"], drop_that(
        "Require the documented enable result", "secrets_encryption_enable_result.rc == 0")))),
    ("the enable marker written before the result check", lambda: enable_result_exact(mutate(task_files["enable"], marker_first))),
    ("the post-round validation removed", lambda: restart_validates_round(mutate(task_files["restart"], remove_named(ROUND_CHECK)))),
    ("the post-round validation after the verified record", lambda: restart_validates_round(mutate(task_files["restart"], validation_after_record))),
    ("the post-round validation on every server's run", lambda: restart_validates_round(mutate(task_files["restart"], validation_everywhere))),
    ("the post-round validation ignoring hashes", lambda: restart_validates_round(mutate(task_files["restart"], validation_ignores_hashes))),
    ("the round enforcement removed", lambda: restart_enforces_round(mutate(task_files["restart"], remove_named(ROUND_ENFORCE)))),
    ("the round without the next-server check", lambda: restart_enforces_round(mutate(task_files["restart"], drop_that(
        ROUND_ENFORCE, "inventory_hostname == se_round.next")))),
    ("the round without the out-of-order check", lambda: restart_enforces_round(mutate(task_files["restart"], drop_that(
        ROUND_ENFORCE, "se_round.out_of_order == ''")))),
    ("the tolerance without the round in evaluate.yml", lambda: tolerance_scoped(
        EV.replace("se_round.tolerate_unavailable_status | bool and s.status.unavailable", "s.status.unavailable"), RS, SM)),
    ("the tolerance without the round in restart.yml", lambda: tolerance_scoped(EV, RS.replace("se_tolerate | bool and (st.unavailable", "(st.unavailable"), SM)),
    ("the round tolerating out-of-order evidence", lambda: tolerance_scoped(EV, RS, SM.replace(
        "not se_complete | bool and se_out_of_order == ''", "not se_complete | bool"))),
    ("the round without ledger and checkpoint", lambda: tolerance_scoped(EV, RS, SM.replace("and se_ledger_ok | bool and se_checkpoint_ok | bool", ""))),
    ("the round in any phase", lambda: tolerance_scoped(EV, RS, SM.replace("and (secrets_encryption_phase | default('')) == 'restart'", ""))),
    ("a status-ignore default", lambda: no_status_option(dict(role_defaults, secrets_encryption_ignore_status_errors=False), role_vars,
                                                         task_files["guard"])),
    ("the round no longer refused as an injected fact", lambda: no_status_option(role_defaults, dict(role_vars, secrets_encryption_gathered_facts=[
        f for f in role_vars["secrets_encryption_gathered_facts"] if f != "secrets_encryption_enable_round"]), task_files["guard"])),
    ("the injection guard removed", lambda: no_status_option(role_defaults, role_vars, mutate(task_files["guard"],
                                                                                              remove_named("Refuse injected gathered state")))),
    ("any status failure marked unavailable", lambda: unavailable_is_narrow(task_text["parse_status"].replace(
        "and se_err_lines | select('search', se_unavailable_re) | list | length == 1", ""))),
    ("an unavailable status counted as parsed", lambda: unavailable_is_narrow(task_text["parse_status"].replace(
        "parsed: \"{{ se_problems | length == 0 }}\"", "parsed: \"{{ se_problems | length == 0 or se_rc | int != 0 }}\""))),
]
LOCK = "Enforce the exclusive enable restart round"
LOCK_THAT = ["not (se_round.active | bool) or se_round_restart | bool or (se_round.complete | bool and se_round.ledger_ok | bool "
             "and se_round.checkpoint_ok | bool and se_round.out_of_order == '')"]
VALIDATE_EVAL = "Evaluate the expected state"
VALIDATE_ENFORCE = "Enforce the gate and the expected state"


def gate_round_exclusive(tasks):
    names = [t.get("name") for t in tasks]
    if LOCK not in names:
        return False
    t = tasks[names.index(LOCK)]
    that = [" ".join(x.split()) for x in t.get("ansible.builtin.assert", {}).get("that", [])]
    return (names.index("Enforce the common health gate") < names.index(LOCK) < names.index("Ensure the Stage 3 state directory exists on every server")
            and t["vars"] == {"se_round": "{{ secrets_encryption_enable_round }}",
                              "se_round_restart": "{{ secrets_encryption_phase == 'restart' and secrets_encryption_flag_state == 'present' }}"}
            and that == [" ".join(x.split()) for x in LOCK_THAT] and "when" not in t)


def validate_blocks_round(tasks):
    ev = next((t for t in tasks if t.get("name") == VALIDATE_EVAL), {})
    en = next((t for t in tasks if t.get("name") == VALIDATE_ENFORCE), {})
    blocking = " ".join(str(ev.get("vars", {}).get("se_round_blocking", "")).split())
    met = " ".join(str(ev.get("ansible.builtin.set_fact", {}).get("secrets_encryption_expectation", {}).get("met", "")).split())
    return (blocking == ("{{ se_round.active | bool and not (se_round.complete | bool and se_round.ledger_ok | bool and "
                         "se_round.checkpoint_ok | bool and se_round.out_of_order == '') }}")
            and met.startswith("{{ not se_round_blocking | bool and (")
            and "not secrets_encryption_expectation.enable_round_blocking | bool" in en.get("ansible.builtin.assert", {}).get("that", []))


def lock_mutate(fn):
    def apply(tasks):
        fn(next(t for t in tasks if t.get("name") == LOCK))
    return apply


require("gate.yml: an incomplete or inconsistent enable restart round admits only the restart with the drop-in, before any write",
        gate_round_exclusive(task_files["gate"]))
require("validate-secrets-encryption.yml: an incomplete or inconsistent enable restart round fails enforced validation",
        validate_blocks_round(validate_pb[0]["tasks"]))
structural_mutants += [
    ("the exclusive round lock removed", lambda: gate_round_exclusive(mutate(task_files["gate"], remove_named(LOCK)))),
    ("the lock admitting drop-in removal", lambda: gate_round_exclusive(mutate(task_files["gate"], lock_mutate(
        lambda t: t["vars"].update(se_round_restart="{{ secrets_encryption_phase == 'restart' }}"))))),
    ("the lock without the ledger, checkpoint and order evidence", lambda: gate_round_exclusive(mutate(task_files["gate"], lock_mutate(
        lambda t: t["ansible.builtin.assert"].update(that=["not (se_round.active | bool) or se_round_restart | bool or se_round.complete | bool"]))))),
    ("the lock after the ledger write", lambda: gate_round_exclusive(mutate(task_files["gate"], lambda ts: ts.append(
        ts.pop([x.get("name") for x in ts].index(LOCK)))))),
    ("validation without the round", lambda: validate_blocks_round(mutate(validate_pb[0]["tasks"], lambda ts: next(
        t for t in ts if t.get("name") == VALIDATE_ENFORCE)["ansible.builtin.assert"]["that"].remove(
        "not secrets_encryption_expectation.enable_round_blocking | bool")))),
]
def add_reencrypt_task(task_map):
    out = copy.deepcopy(task_map)
    out["rotate"].append({"name": "legacy rollback", "ansible.builtin.command": {
        "argv": ["{{ secrets_encryption_k3s_bin }}", "secrets-encrypt", "reencrypt", "--force", "--skip"]}})
    return out


def rotate_decision_after_disable(tasks):
    t = next(t for t in tasks if t.get("name") == "Decide the rotation purpose")
    t["ansible.builtin.set_fact"]["secrets_encryption_rotation_purpose"] = t["ansible.builtin.set_fact"][
        "secrets_encryption_rotation_purpose"].replace("else 'refuse'", "else 'plaintext' if secrets_encryption_marker.phase == 'disable' else 'refuse'")


structural_mutants += [
    ("a reintroduced reencrypt --force --skip rollback task", lambda: no_inplace_rollback(
        add_reencrypt_task(task_files), task_text, PLAYBOOK_NAMES, role_vars)),
    ("disable reintroduced as a mutating phase", lambda: no_inplace_rollback(
        task_files, task_text, PLAYBOOK_NAMES, dict(role_vars, secrets_encryption_mutating_phases=role_vars["secrets_encryption_mutating_phases"] + ["disable"]))),
    ("a reintroduced rollback playbook", lambda: no_inplace_rollback(task_files, task_text, PLAYBOOK_NAMES + ["secrets-encryption-reencrypt"], role_vars)),
    ("drop-in removal after a rollback re-encryption marker", lambda: flag_removal_preactivation_only(task_text["restart"].replace(
        "secrets_encryption_marker.phase == 'enable')", "secrets_encryption_marker.phase in ['enable', 'reencrypt-after-disable'])"), task_text["guard"])),
    ("the enabling rotation without the pre-enable snapshot", lambda: rotation_requires_p0(mutate(task_files["rotate"], drop_that(
        "Enforce the rotation preconditions", next(x for x in next(t for t in task_files["rotate"] if t.get("name") == "Enforce the rotation preconditions")
                                                   ["ansible.builtin.assert"]["that"] if "checkpoint_ok" in x))))),
    ("rotate-keys used as a plaintext rollback after disable", lambda: rotate_never_plaintext(mutate(task_files["rotate"], rotate_decision_after_disable))),
    ("documentation naming the R3 rollback playbook", lambda: docs_rollback_consistent(
        ROLLBACK_DOC + "\nansible-playbook secrets-encryption-reencrypt.yml --limit k3s01\n", README_TEXT, VALIDATION_DOC)),
]
def token_with_checksum(tasks):
    next(x for x in tasks if x.get("name") == "Inspect the server token file without reading it")["ansible.builtin.stat"]["get_checksum"] = True


def token_debugged(tasks):
    tasks.append({"name": "Show the token stat", "ansible.builtin.debug": {"var": "secrets_encryption_token_stat"}})


def enable_without_p0(tasks):
    next(x for x in tasks if x.get("name") == "Require the recorded pre-enable checkpoint")["ansible.builtin.assert"]["that"] = ["true"]


def round_unrecorded(tasks):
    rt = next(x for x in tasks if x.get("name") == "Summarize the enable restart round")
    rt["vars"]["se_checkpoint_ok"] = rt["vars"]["se_checkpoint_ok"].replace(
        "and secrets_encryption_p0.p0_records | select('search', key | regex_escape) | list | length > 0", "")


VALIDATE_TEXT = (ans / "validate-secrets-encryption.yml").read_text()
structural_mutants += [
    ("the token file inspected with a checksum", lambda: token_stat_only(dict(task_files, snapshot=mutate(task_files["snapshot"], token_with_checksum)))),
    ("the token stat shown in a report", lambda: token_stat_only(dict(task_files, snapshot=mutate(task_files["snapshot"], token_debugged)))),
    ("the checkpoint record without the token confirmation", lambda: checkpoint_record_fixed(mutate(task_files["snapshot"], lambda ts: next(
        x for x in ts if x.get("name") == "Record the checkpoint metadata")["ansible.builtin.lineinfile"].update(line="{{ x }}")), task_text["summarize"])),
    ("enable without the p0 requirement", lambda: enable_requires_p0(mutate(task_files["enable"], enable_without_p0), task_text["summarize"])),
    ("p0 accepted without the last-invocation rule", lambda: enable_requires_p0(task_files["enable"], task_text["summarize"].replace(
        "se_newest_records | length == 1 and se_last_snapshot | bool", "se_newest_records | length == 1"))),
    ("the round accepting an unrecorded snapshot", lambda: round_requires_recorded_p0(mutate(task_files["summarize"], round_unrecorded))),
    ("configured-disabled accepted after activation", lambda: configured_disabled_preactivation(VALIDATE_TEXT.replace(
        "\n                and secrets_encryption_marker.phase == 'enable')", ")"), task_text["parse_status"])),
    ("Disabled no longer parsed", lambda: configured_disabled_preactivation(VALIDATE_TEXT, task_text["parse_status"].replace(
        "      Disabled: disabled\n", ""))),
    ("documentation without the operator impact acknowledgment", lambda: docs_restore_defined(ROLLBACK_DOC.replace(
        "No future live restore starts without a written acknowledgment", "A restore may start"), README_TEXT, VALIDATION_DOC)),
    ("documentation claiming disable restores plaintext", lambda: docs_restore_defined(
        ROLLBACK_DOC + "\n`disable` successfully rewrites Secretbox records to plaintext.\n", README_TEXT, VALIDATION_DOC)),
    ("documentation taking p0 before the canary controls", lambda: docs_restore_defined(ROLLBACK_DOC.replace(
        "secrets_encryption_snapshot_checkpoint=p0-pre-enable\n", "secrets_encryption_snapshot_checkpoint=p0-pre-enable-moved\n").replace(
        "secrets_encryption_snapshot_checkpoint=baseline\n", "secrets_encryption_snapshot_checkpoint=p0-pre-enable\n"), README_TEXT, VALIDATION_DOC)),
    ("documentation treating static tests as completion", lambda: docs_restore_defined(
        ROLLBACK_DOC.replace("A passing static test run is not completion.", ""), README_TEXT, VALIDATION_DOC)),
    ("documentation delivering the real-server reset through configuration-file fields", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "Never deliver the reset by writing `cluster-reset` fields into a configuration file",
        "Deliver the reset by writing these fields into a configuration file:\n\ncluster-reset: true\n\nand never by command line"))),
    ("documentation presenting the Docker runner as the real-server recovery method", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "5. **Start K3s on `k3s01` normally:**", "5. Alternatively run the reset in a docker runner with --volumes-from.\n5. **Start K3s on `k3s01` normally:**"))),
    ("documentation accepting a reset by exit status alone", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "The ERROR level of that line is not a failure, and exit status 0 alone is not success", "Exit status 0 is sufficient"))),
    ("documentation without the reset flag requirement", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "/var/lib/rancher/k3s/server/db/reset-flag", "<none>"))),
    ("documentation treating retained encryption files as active encryption", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "**Their presence alone must not be interpreted as active encryption**", "**Their presence means encryption is active**"))),
    ("documentation without the free-address check before the runner attaches", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "held by no endpoint and reserved by no other container; otherwise stop", "available"))),
    ("documentation without the unchanged-identity check after reconnect", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "the container identity, hostname, network, address, prefix, gateway, aliases and volumes must be unchanged", "the container runs"))),
    ("documentation allowing S1's container or volumes to be recreated", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "Its container and volumes are never deleted or recreated", "Its container may be recreated"))),
    ("documentation running the runner while S1 stays attached", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "4. **Disconnect only S1**", "4. **Keep S1 attached**"))),
    ("documentation removing the runner after S1 is reconnected", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "**Remove the runner, prove the address is free again, and reconnect the original S1**", "**Reconnect the original S1, then remove the runner**"))),
    ("documentation stopping the k3d servers one after another", lambda: docs_restore_mechanism(ROLLBACK_DOC.replace(
        "**Stop all three server containers concurrently**", "**Stop the server containers one after another**"))),
    ("a stale claim that the k3d rehearsal has not passed", lambda: docs_status_current(
        ROLLBACK_DOC + "\nThe k3d rehearsal has **not** passed.\n", README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a stale README status", lambda: docs_status_current(ROLLBACK_DOC, README_TEXT.replace(
        "passed the required disposable k3d rehearsal, including", "not yet passed a rehearsal, including", 1), VALIDATION_DOC, ARCH_DOC)),
    ("a stale claim that the three-VM rehearsal is pending", lambda: docs_status_current(ROLLBACK_DOC, README_TEXT,
        VALIDATION_DOC + "\nThe three-VM rehearsal is still pending.\n", ARCH_DOC)),
    ("a stale claim that the live rollout is not approved", lambda: docs_status_current(
        ROLLBACK_DOC + "\nThe live rollout is not approved.\n", README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the live rollout record removed", lambda: docs_status_current(ROLLBACK_DOC.replace(
        LIVE_RECORD[0], "### Live rollout notes"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the live record without the counter defect", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "systemd reset its `NRestarts` from 59 to 0", "the restart was slow"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the live record without the p2 manifest", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "`6f7a54c20814228a0640029f9bb9e21f6f2db06c6770f7a8d7c11b44b532dab6`", "(kept by the operator)"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the live record claiming raw checks", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "Raw etcd checks were **not run**", "Raw etcd checks were run live"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a live restore claimed", lambda: docs_status_current(ROLLBACK_DOC, README_TEXT,
        VALIDATION_DOC + "\nA live restore was performed from p2.\n", ARCH_DOC)),
    ("a host address in the live record", lambda: docs_status_current(ROLLBACK_DOC.replace(
        LIVE_RECORD[0] + "\n", LIVE_RECORD[0] + "\n\nThe first server was 192.0.2.41.\n"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a workstation path in the live record", lambda: docs_status_current(ROLLBACK_DOC.replace(
        LIVE_RECORD[0] + "\n", LIVE_RECORD[0] + "\n\nEvidence in /home/operator/evidence.\n"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the decode window dropped from the procedure", lambda: docs_status_current(ROLLBACK_DOC.replace(
        DECODE_WINDOW[0], "### After rotate-keys"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the second round still waiting 10 minutes per server", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "without the 10-minute waits", "with a 10-minute wait after each"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a manual reconcile allowed after the round", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "returns to Ready by itself, with no `flux reconcile`", "is reconciled with `flux reconcile`"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the decode-window stop exception dropped", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "except the [decode window](#after-rotate-keys-the-secret-decode-window)", "always"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the three-VM record removed", lambda: docs_status_current(ROLLBACK_DOC.replace(
        THREE_VM_RECORD[0], "### Three-VM rehearsal notes"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the three-VM record without the evidence hash", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "078219c49d7572bab3f128cefd6496f3e94536349fb97490e8c83c549bf2ab80", "(see the operator)"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the three-VM record without the first correction", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "0dea72001a3c757bc946e3f7259a9595ab242806", "an earlier commit"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the three-VM record claimed as approval", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "The rehearsal **is not approval**", "The rehearsal **approves the live rollout**"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("three-VM Flux acceptance claimed as passed", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "**not applicable** in this rehearsal", "**passed** in this rehearsal"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a host address in the three-VM record", lambda: docs_status_current(ROLLBACK_DOC.replace(
        THREE_VM_RECORD[0] + "\n", THREE_VM_RECORD[0] + "\n\nThe first server was 192.0.2.41.\n"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a MAC address in the three-VM record", lambda: docs_status_current(ROLLBACK_DOC.replace(
        THREE_VM_RECORD[0] + "\n", THREE_VM_RECORD[0] + "\n\nNIC 00:00:5e:00:53:01.\n"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a workstation path in the three-VM record", lambda: docs_status_current(ROLLBACK_DOC.replace(
        THREE_VM_RECORD[0] + "\n", THREE_VM_RECORD[0] + "\n\nKept in C:\\evidence.\n"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the systemd stop result dropped", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "**It did not reproduce under systemd:**", "It is unexplained:"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("a stale architecture claim of no encryption at rest", lambda: docs_status_current(ROLLBACK_DOC, README_TEXT, VALIDATION_DOC,
        ARCH_DOC + "\nKubernetes Secrets are stored in etcd without encryption at rest.\n")),
    ("a stale claim that Stage 3 is not complete", lambda: docs_status_current(
        ROLLBACK_DOC + "\n- **Stage 3 is not complete** and has not been applied to the real cluster.\n", README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the README live status dropped", lambda: docs_status_current(ROLLBACK_DOC, README_TEXT.replace(
        "Active on the live cluster since 2026-10-29", "Pending on the live cluster"), VALIDATION_DOC, ARCH_DOC)),
    ("the three-VM rehearsal no longer recorded as passed", lambda: docs_status_current(ROLLBACK_DOC, README_TEXT, VALIDATION_DOC,
        ARCH_DOC.replace("three-VM rehearsal passed on 2026-10-27", "three-VM rehearsal follows"))),
    ("S1's exit 1 called expected", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "not as expected behavior and not as evidence of failure", "as expected behavior"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("S1's undetermined cause dropped", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "The cause of the exit status 1 was not determined", "The exit status 1 is harmless"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("Flux acceptance claimed as passed", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "not applicable** in disposable k3d and are not claimed as passed", "passed** in disposable k3d"), README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("post-restore encryption-file metadata claimed as compared", lambda: docs_status_current(ROLLBACK_DOC.replace(
        "did not compare their inode or modification time after the restore", "compared their inode and modification time after the restore"),
        README_TEXT, VALIDATION_DOC, ARCH_DOC)),
    ("the key-recovery comparison reported as MATCH or MISMATCH", lambda: docs_key_recovery_aligned(ROLLBACK_DOC.replace(
        "`MATCH`, `DIFFER` or `ERROR`", "`MATCH` or `MISMATCH`"))),
    ("the key-recovery record holding the source file's size", lambda: docs_key_recovery_aligned(ROLLBACK_DOC.replace(
        "the ciphertext's size and SHA-256, and the object key", "the source file's size and mode, the ciphertext's size and SHA-256, and the object key"))),
    ("the key-recovery section without the merged helper reference", lambda: docs_key_recovery_aligned(ROLLBACK_DOC.replace(
        "pull request #21 (commit `3bb8199`)", "a future pull request"))),
]


# YAML ends a plain scalar at a comma in a flow sequence, so an unquoted
# `--opt=a,b` in `argv: [...]` silently becomes several arguments. The three-VM
# rehearsal (2026-10-27) found systemctl receiving ActiveEnterTimestamp and
# NRestarts as unit names, which left every server's service state unreadable.
def flow_argv_commas(texts):
    """(file, line) of every comma in a flow-style argv that is neither quoted nor followed by a space (an item separator)."""
    bad = []
    for name, text in texts.items():
        for m in re.finditer(r"\bargv:\s*\[", text):
            i, quote = m.end(), None
            while i < len(text) and (quote or text[i] != "]"):
                c = text[i]
                if quote == '"' and c == "\\":
                    i += 1
                elif quote:
                    quote = None if c == quote else quote
                elif c in "\"'":
                    quote = c
                elif c == "," and text[i + 1:i + 2] not in (" ", "\n"):
                    bad.append((name, text.count("\n", 0, i) + 1))
                i += 1
    return bad


SVC_ARGV = ["systemctl", "show", "k3s.service", "--timestamp=unix", "--property=ActiveState,ActiveEnterTimestamp,NRestarts"]
SVC_QUOTED = '"--property=ActiveState,ActiveEnterTimestamp,NRestarts"'
SVC_UNQUOTED = "--property=ActiveState,ActiveEnterTimestamp,NRestarts"
yaml_texts = {str(p.relative_to(ans)): p.read_text() for p in sorted(ans.rglob("*.yml"))}


def service_argv(tasks):
    return next(t["ansible.builtin.command"]["argv"] for t in walk(tasks) if t.get("name") == "Read the K3s service state on every server")


require("ansible/: no flow-style argv has an unquoted comma inside an argument (YAML would split it into separate arguments)",
        flow_argv_commas(yaml_texts) == [])
require("flow-style argv check: quoted commas and item separators pass, an unquoted comma inside an item is reported",
        flow_argv_commas({"s": 'argv: [a, "--x=b,c", \'--y=d,e\', "{{ f | default(\'g,h\') }}", "i\\",j"]\n'}) == []
        and flow_argv_commas({"s": "- x\n  argv: [a, --x=b,c]\n"}) == [("s", 2)])
require("gather.yml: the service probe passes the property list to systemctl as one argument", service_argv(task_files["gather"]) == SVC_ARGV)
structural_mutants += [
    ("the service probe's property list unquoted (flow-style argv check)",
     lambda: task_text["gather"].count(SVC_QUOTED) != 1 or flow_argv_commas({"gather": task_text["gather"].replace(SVC_QUOTED, SVC_UNQUOTED)}) == []),
    ("the service probe's property list unquoted (exact argv)",
     lambda: service_argv(yaml.safe_load(task_text["gather"].replace(SVC_QUOTED, SVC_UNQUOTED))) == SVC_ARGV),
]


# The drop-in removal round (three-VM rehearsal, 2026-10-27): summarized from
# recorded state after the enable restart round, refused as an injected fact,
# and used only by the restart preconditions.
def removal_round_wired(vars_, summarize_tasks, task_map):
    names = [t.get("name") for t in summarize_tasks]
    users = sorted(f for f, ts in task_map.items() for t in walk(ts) if "secrets_encryption_removal_round" in json.dumps(t)
                   and t.get("name") != "Summarize the drop-in removal round")
    return ("secrets_encryption_removal_round" in vars_["secrets_encryption_gathered_facts"]
            and "Summarize the drop-in removal round" in names
            and names.index("Summarize the enable restart round") < names.index("Summarize the drop-in removal round")
            < names.index("Evaluate the common health gate")
            and users == ["restart"])


require("summarize.yml: the drop-in removal round follows the enable restart round, is refused as an injected fact and used only by the restart preconditions",
        removal_round_wired(role_vars, task_files["summarize"], task_files))
structural_mutants += [
    ("the removal round no longer refused as an injected fact", lambda: removal_round_wired(dict(role_vars, secrets_encryption_gathered_facts=[
        f for f in role_vars["secrets_encryption_gathered_facts"] if f != "secrets_encryption_removal_round"]), task_files["summarize"], task_files)),
    ("the removal round summarized before the enable restart round", lambda: removal_round_wired(role_vars, mutate(task_files["summarize"], lambda ts: ts.insert(
        0, ts.pop([x.get("name") for x in ts].index("Summarize the drop-in removal round")))), task_files)),
    ("the removal round used by the gate", lambda: removal_round_wired(role_vars, task_files["summarize"], dict(task_files, gate=task_files["gate"] + [
        {"name": "use", "ansible.builtin.debug": {"msg": "{{ secrets_encryption_removal_round }}"}}]))),
]


# Live-readiness review (2026-10-27): drop-in removal before activation is the
# only rehearsal-approved path, and the guard still refuses any other path live.
def approval_exact(vars_, guard_text):
    return (vars_["secrets_encryption_rehearsal_approved_paths"] == ["flag-removal"]
            and "or se_path in secrets_encryption_rehearsal_approved_paths" in guard_text
            and "se_path == '' or secrets_encryption_environment == 'rehearsal'" in guard_text)


# The p0 latch is evaluated only in checks.yml, and the gate still enforces freshness after the exclusive-round lock.
def latch_wired(checks_text, gate_tasks):
    names = [t.get("name") for t in gate_tasks]
    return (checks_text.count("se_p0_latched") == 3 and "or se_p0_latched | bool }}" in checks_text
            and not any("p0_latched" in task_text[f] for f in task_text if f != "checks")
            and names.index("Enforce the exclusive enable restart round") < names.index("Enforce snapshot freshness"))


# Phase binding (live-readiness review, 2026-10-27): every guarded play has
# exactly one committed mapping entry, from its exact name to its own phase.
GUARDED_FILES = sorted(p.stem for p in ans.glob("*.yml") if "tasks_from: guard.yml" in p.read_text())
BIND_THAT = ["se_expected in se_allowed", "secrets_encryption_phase | default('') == se_expected"]


def play_binding_ok(vars_, defaults_, guard_tasks, books):
    m = vars_.get("secrets_encryption_play_phases")
    if not isinstance(m, dict):
        return False
    plays_ = {b[0]["name"]: b[0]["vars"]["secrets_encryption_phase"] for b in books.values()}
    phases = [ph for v in m.values() for ph in (v if isinstance(v, list) else [None])]

    def phase_ok(name, var):
        v = m.get(name)
        if not isinstance(v, list) or not v:
            return False
        if "{{" in var:  # the canary play: its action selects one of its own phases
            return var.startswith("canary-{{") and len(v) > 1 and all(str(x).startswith("canary-") for x in v)
        return v == [var]

    bind = guard_tasks[0] if guard_tasks else {}
    return (sorted(m) == sorted(plays_) and len(plays_) == len(books)
            and all(phase_ok(n, v) for n, v in plays_.items())
            and len(phases) == len(set(phases)) and sorted(phases) == sorted(vars_["secrets_encryption_mutating_phases"])
            and "secrets_encryption_play_phases" not in defaults_
            and bind.get("name") == "Bind the phase to the running play"
            and bind.get("ansible.builtin.assert", {}).get("that") == BIND_THAT
            and bind.get("vars", {}).get("se_allowed") == "{{ secrets_encryption_play_phases[ansible_play_name] | default([]) }}")


def with_phases(fn):
    m = copy.deepcopy(role_vars["secrets_encryption_play_phases"])
    fn(m)
    return dict(role_vars, secrets_encryption_play_phases=m)


RESTART_PLAY = "Restart one K3s server for the secrets-encryption procedure"
require("phase playbooks: exactly the six mutating playbooks import the guard", GUARDED_FILES == sorted(MUTATING))
require("vars and guard.yml: every guarded play is bound to its own committed phase, first in the guard, before facts",
        play_binding_ok(role_vars, role_defaults, task_files["guard"], playbooks))
structural_mutants += [
    ("a guarded play without a mapping", lambda: play_binding_ok(with_phases(lambda m: m.pop(RESTART_PLAY)), role_defaults,
                                                                 task_files["guard"], playbooks)),
    ("a play mapped to another phase", lambda: play_binding_ok(with_phases(lambda m: m.update({RESTART_PLAY: ["restart-x"]})), role_defaults,
                                                               task_files["guard"], playbooks)),
    ("a phase mapped twice", lambda: play_binding_ok(with_phases(lambda m: m.update({"Take a Stage 3 on-demand etcd snapshot": ["snapshot", "restart"]})),
                                                     role_defaults, task_files["guard"], playbooks)),
    ("a mapping for a play that does not exist", lambda: play_binding_ok(with_phases(lambda m: m.update({"Some other play": ["enable-x"]})),
                                                                         role_defaults, task_files["guard"], playbooks)),
    ("an injectable mapping (a default)", lambda: play_binding_ok(role_vars, dict(role_defaults, secrets_encryption_play_phases={}),
                                                                  task_files["guard"], playbooks)),
    ("the binding not first in the guard", lambda: play_binding_ok(role_vars, role_defaults, mutate(task_files["guard"], lambda ts: ts.insert(
        1, ts.pop(0))), playbooks)),
    ("the binding without the phase equality", lambda: play_binding_ok(role_vars, role_defaults, mutate(task_files["guard"], lambda ts: ts[0][
        "ansible.builtin.assert"]["that"].pop()), playbooks)),
]
require("vars and guard: only flag-removal is rehearsal-approved, and the guard still refuses unapproved paths live",
        approval_exact(role_vars, task_text["guard"]))
require("checks.yml: the p0 latch is evaluated only there, and the gate keeps the exclusive-round lock before freshness",
        latch_wired(task_text["checks"], task_files["gate"]))
structural_mutants += [
    ("a second approved path", lambda: approval_exact(dict(role_vars, secrets_encryption_rehearsal_approved_paths=["flag-removal", "reencrypt"]),
                                                     task_text["guard"])),
    ("the approval removed", lambda: approval_exact(dict(role_vars, secrets_encryption_rehearsal_approved_paths=[]), task_text["guard"])),
    ("the guard admitting any path live", lambda: approval_exact(role_vars, task_text["guard"].replace(
        "se_path == '' or secrets_encryption_environment == 'rehearsal'", "true or secrets_encryption_environment == 'rehearsal'"))),
    ("the latch not applied to freshness", lambda: latch_wired(task_text["checks"].replace("or se_p0_latched | bool }}", "}}"), task_files["gate"])),
    ("freshness enforced before the exclusive-round lock", lambda: latch_wired(task_text["checks"], mutate(task_files["gate"], lambda ts: ts.insert(
        [x.get("name") for x in ts].index("Enforce the exclusive enable restart round"),
        ts.pop([x.get("name") for x in ts].index("Enforce snapshot freshness")))))),
]
for label, check in structural_mutants:
    require(f"mutation (structure): {label} is detected", check() is False)

if structure_failures:
    print(f"structure checks failed: {structure_failures}", flush=True)
    sys.exit(1)

# ====================================================================== verifier
sys.dont_write_bytecode = True  # no __pycache__ inside the role's files directory
spec = importlib.util.spec_from_file_location("etcd_value_verify", role / "files/etcd_value_verify.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
SB = "k8s:enc:secretbox:v1:"
KEY = "/registry/secrets/default/stage3-canary-post-encryption"
ENC = b"k8s:enc:secretbox:v1:secretboxkey-2026-10-20T10:" + b"\x01" * 60


def etcd_json(records, count=None, more=False, raw=None):
    if raw is not None:
        return raw
    doc = {"header": {"cluster_id": 1, "member_id": 2, "revision": 9, "raft_term": 3}}
    if records:
        doc["kvs"] = [{"key": base64.b64encode(k.encode()).decode(), "create_revision": 5, "mod_revision": 9, "version": 2,
                       "value": base64.b64encode(v).decode()} for k, v in records]
    c = len(records) if count is None else count
    if c:
        doc["count"] = c
    if more:
        doc["more"] = True
    return json.dumps(doc).encode()


verifier_cases = [
    ("one exact secretbox record", etcd_json([(KEY, ENC)]), "encrypted", KEY, "PASS"),
    ("missing key", etcd_json([]), "encrypted", KEY, "FAIL-MISSING"),
    ("two records (a range)", etcd_json([(KEY, ENC), (KEY + "-x", ENC)]), "encrypted", KEY, "FAIL-MULTIPLE"),
    ("count above one", etcd_json([(KEY, ENC)], count=2), "encrypted", KEY, "FAIL-MULTIPLE"),
    ("more records pending", etcd_json([(KEY, ENC)], more=True), "encrypted", KEY, "FAIL-MULTIPLE"),
    ("record for a longer key (a prefix match)", etcd_json([(KEY + "-x", ENC)]), "encrypted", KEY, "FAIL-KEY"),
    ("record for another key", etcd_json([("/registry/secrets/default/other", ENC)]), "encrypted", KEY, "FAIL-KEY"),
    ("not JSON", etcd_json([], raw=b"k8s:enc:secretbox:v1:k1:" + b"\x00" * 60), "encrypted", KEY, "FAIL-JSON"),
    ("JSON list", etcd_json([], raw=b"[]"), "encrypted", KEY, "FAIL-JSON"),
    ("invalid base64 value", etcd_json([], raw=json.dumps({"kvs": [{"key": base64.b64encode(KEY.encode()).decode(), "value": "%%%"}],
                                                           "count": 1}).encode()), "encrypted", KEY, "FAIL-JSON"),
    ("empty value", etcd_json([(KEY, b"")]), "encrypted", KEY, "FAIL-EMPTY"),
    ("payload one byte short", etcd_json([(KEY, b"k8s:enc:secretbox:v1:k1:" + b"\x00" * 40)]), "encrypted", KEY, "FAIL-MALFORMED"),
    ("no key name", etcd_json([(KEY, b"k8s:enc:secretbox:v1::" + b"\x00" * 60)]), "encrypted", KEY, "FAIL-MALFORMED"),
    ("aescbc where secretbox is expected", etcd_json([(KEY, b"k8s:enc:aescbc:v1:k1:" + b"\x00" * 60)]), "encrypted", KEY, "FAIL-PREFIX"),
    ("plaintext where encryption is expected", etcd_json([(KEY, b"k8s\x00\x0a\x0csecret-value")]), "encrypted", KEY, "FAIL-PREFIX"),
    ("identity provider output", etcd_json([(KEY, b"k8s:enc:identity:v1:")]), "encrypted", KEY, "FAIL-PREFIX"),
    ("plaintext protobuf control", etcd_json([(KEY, b"k8s\x00\x0a\x0dv1\x12\tConfigMap")]), "plaintext", KEY, "PASS"),
    ("encrypted where plaintext is expected", etcd_json([(KEY, ENC)]), "plaintext", KEY, "FAIL-ENCRYPTED"),
    ("JSON value where protobuf is expected", etcd_json([(KEY, b'{"kind":"ConfigMap"}')]), "plaintext", KEY, "FAIL-MALFORMED"),
]
verifier_failures = []
for label, payload, mode, key, expected in verifier_cases:
    token, value = verifier.record(payload, key)
    got = token if token is not None else verifier.verdict(value, mode, SB)
    ok = got == expected
    print(f"{'PASS' if ok else 'FAIL'}  verifier: {label} -> {got}", flush=True)
    if not ok:
        verifier_failures.append(label)
for label, payload, args, expected_out, expected_rc in (
        ("exit status 0 only for PASS; nothing but the token printed", etcd_json([(KEY, b"k8s:enc:secretbox:v1:k1:" + b"RAWSENTINEL" * 8)]),
         ["encrypted", SB, KEY], "PASS", 0),
        ("oversize input", b"{" + b" " * (5 << 20) + b"}", ["encrypted", SB, KEY], "FAIL-OVERSIZE", 1),
        ("missing arguments", b"", [], "FAIL-USAGE", 1),
        ("unknown mode", etcd_json([(KEY, ENC)]), ["other", SB, KEY], "FAIL-USAGE", 1),
        ("unknown provider prefix", etcd_json([(KEY, ENC)]), ["encrypted", "k8s:enc:kms:v2:", KEY], "FAIL-USAGE", 1),
        ("a key prefix instead of a key", etcd_json([(KEY, ENC)]), ["encrypted", SB, "/registry/secrets/default/"], "FAIL-USAGE", 1),
        ("a key outside the registry", etcd_json([(KEY, ENC)]), ["encrypted", SB, "/other/key"], "FAIL-USAGE", 1),
        ("a failure prints only the token", etcd_json([(KEY + "-x", b"RAWSENTINEL")]), ["encrypted", SB, KEY], "FAIL-KEY", 1)):
    r = subprocess.run([sys.executable, "-I", str(role / "files/etcd_value_verify.py")] + args, input=payload, capture_output=True)
    ok = r.stdout.decode().strip() == expected_out and r.returncode == expected_rc and r.stderr == b"" and b"RAWSENTINEL" not in r.stdout
    print(f"{'PASS' if ok else 'FAIL'}  verifier: {label}", flush=True)
    if not ok:
        verifier_failures.append(label)
if verifier_failures:
    print(f"verifier checks failed: {verifier_failures}", flush=True)
    sys.exit(1)

# ====================================================================== scenarios
SENTINELS = ["node-sentinel-a", "node-sentinel-b", "RAWSENTINEL", "readback-sentinel", "protected-sentinel"]
plays = []
SERVERS = ["k3s01", "k3s02", "k3s03"]
UID = os.getuid()


def play(name, mocks, tasks, expect_fail, checks=(), extra_vars=None, host="k3s01", setup=(), invert=False):
    """expect_fail is False, or the name of the task that must fail. invert: the expected outcome must NOT occur (a killed mutant)."""
    pre = [{"name": f"mock {k}", "ansible.builtin.set_fact": {k: v}} for k, v in mocks.items()]
    body = [{"name": "reset outcome", "ansible.builtin.set_fact": {"harness_failed": False, "harness_failed_task": ""}},
            {"block": copy.deepcopy(tasks), "rescue": [{"name": "record failure", "ansible.builtin.set_fact": {
                "harness_failed": True, "harness_failed_task": "{{ ansible_failed_task.name | default('') }}"}}]}]
    expect = [f"harness_failed | bool == {bool(expect_fail)}"]
    if expect_fail:
        expect.append(f"harness_failed_task == {json.dumps(expect_fail)}")
    that = expect + list(checks)
    if invert:
        that = ["not (" + " and ".join(f"({c})" for c in that) + ")"]
    post = [{"name": f"check: {name}", "ansible.builtin.assert": {"that": that, "quiet": True}}]
    vars_ = dict(role_defaults)
    vars_.update(role_vars)
    vars_.update({"secrets_encryption_environment": "live"})
    vars_.update(extra_vars or {})
    return {"name": name, "hosts": host, "gather_facts": False, "vars": vars_, "tasks": list(setup) + pre + body + post}


# ---------------------------------------------------------------- status parsing
parse = picks("parse_status", "Parse the secrets-encryption status")
P = "secrets_encryption_parsed"


def status(lines, rc=0):
    return {"secrets_encryption_status_input": {"rc": rc, "stdout_lines": lines}}


KEYS = ["", "Active  Key Type           Name", "------  --------           ----"]
ENABLED = ["Encryption Status: Enabled", "Current Rotation Stage: reencrypt_finished", "Server Encryption Hashes: All hashes match"] + KEYS + [
    " *      XSalsa20-POLY1305  secretboxkey-2026-10-20T10:15:05Z"]
IDENTITY = ["Encryption Status: Disabled", "Current Rotation Stage: start", "Server Encryption Hashes: All hashes match"]
NOCONF_LINES = ["Encryption Status: Disabled, no configuration file found"]
parse_ok = [
    ("no configuration", NOCONF_LINES, {"encryption": "disabled-no-config", "stage": "none", "key_count": 0}),
    ("no configuration with stage and hash lines", NOCONF_LINES + ["Current Rotation Stage: start", "Server Encryption Hashes: All hashes match"],
     {"encryption": "disabled-no-config", "stage": "start"}),
    ("identity configuration after enable", IDENTITY,
     {"encryption": "disabled", "stage": "start", "hashes_match": True, "key_count": 0, "active_key_type": "none"}),
    ("enabled with a secretbox key", ENABLED,
     {"encryption": "enabled", "stage": "reencrypt_finished", "hashes_match": True, "key_count": 1,
      "active_key_type": "XSalsa20-POLY1305", "active_key_name": "secretboxkey-2026-10-20T10:15:05Z"}),
    ("enabled with an inactive aescbc key", ENABLED + ["        AES-CBC            aescbckey-2026-10-19T10:00:00Z"],
     {"encryption": "enabled", "key_count": 2, "active_key_type": "XSalsa20-POLY1305"}),
    ("hash mismatch reduced to a boolean", IDENTITY[:2] + ["Server Encryption Hashes: hash does not match between node-sentinel-a and node-sentinel-b"],
     {"hashes_match": False, "hash_state": "mismatch"}),
    ("re-encryption in progress is parsed (and refused by the gate)", ["Encryption Status: Enabled", "Current Rotation Stage: reencrypt_active",
                                                                       "Server Encryption Hashes: All hashes match"] + KEYS
     + [" *      XSalsa20-POLY1305  secretboxkey-1"], {"stage": "reencrypt_active"}),
    ("legacy stage is parsed (and refused by the gate)", ["Encryption Status: Enabled", "Current Rotation Stage: prepare",
                                                          "Server Encryption Hashes: All hashes match"] + KEYS
     + [" *      AES-CBC  aescbckey-1"], {"stage": "prepare"}),
]
for label, lines, expected in parse_ok:
    checks = [f"{P}.parsed | bool", f"{P} | to_json is not search('sentinel')"]
    checks += [f"({P}.{k} | bool) == {v}" if isinstance(v, bool) else f"({P}.{k} | int) == {v}" if isinstance(v, int)
               else f"{P}.{k} == {json.dumps(v)}" for k, v in expected.items()]
    plays.append(play(f"parse: {label}", status(lines), parse, False, checks))
parse_bad = [
    ("empty output", [], 0, "empty-output"),
    ("command failure", ["Encryption Status: Enabled"], 1, "status-command-failed"),
    ("unknown encryption status", ["Encryption Status: Maybe"] + IDENTITY[1:], 0, "encryption-status"),
    ("unknown stage", ["Encryption Status: Disabled", "Current Rotation Stage: rotate_soon", "Server Encryption Hashes: All hashes match"], 0, "stage-value"),
    ("missing stage", ["Encryption Status: Disabled", "Server Encryption Hashes: All hashes match"], 0, "stage-line"),
    ("duplicate stage", IDENTITY[:2] + IDENTITY[1:], 0, "stage-line"),
    ("duplicate encryption status", ["Encryption Status: Disabled", "Encryption Status: Enabled"] + IDENTITY[1:], 0, "encryption-status"),
    ("missing hash line", IDENTITY[:2], 0, "hash-line"),
    ("unknown hash text", IDENTITY[:2] + ["Server Encryption Hashes: maybe"], 0, "hash-value"),
    ("unrecognized line", IDENTITY + ["Something new: value"], 0, "unrecognized-lines"),
    ("enabled without an active key", ENABLED[:3], 0, "enabled-without-active-key"),
    ("two active keys", ENABLED + [" *      AES-CBC  aescbckey-2"], 0, "key-table"),
    ("key row without a header", ENABLED[:3] + [" *      XSalsa20-POLY1305  k1"], 0, "key-table"),
    ("unknown key type", ENABLED[:-1] + [" *      KMS-V2  key"], 0, "unrecognized-lines"),
    ("no configuration but keys listed", NOCONF_LINES + KEYS + ["        AES-CBC  k1"], 0, "no-config-with-keys"),
]
for label, lines, rc, problem in parse_bad:
    plays.append(play(f"parse fails closed: {label}", status(lines, rc), parse, False,
                      [f"not ({P}.parsed | bool)", f"'{problem}' in {P}.problems"]))
plays.append(play("parse fails closed: missing result", {"secrets_encryption_status_input": {}}, parse, False,
                  [f"not ({P}.parsed | bool)", f"'status-command-failed' in {P}.problems", f"not ({P}.unavailable | bool)"]))

# The result observed between enable and the first restart round (k3d, 2026-10-23).
CA_WARNING = ('time="2026-10-23T16:09:01Z" level=warning msg="Cluster CA certificate is not trusted by the host CA bundle, '
              'but the token does not include a CA hash."')
FATAL_INTERNAL = 'time="2026-10-23T16:09:01Z" level=fatal msg="Error: see server log for details: Internal error occurred: secret-encrypt error ID 00459"'


def unavailable(rc=1, err=(CA_WARNING, FATAL_INTERNAL), out=()):
    return {"rc": rc, "stdout_lines": list(out), "stderr_lines": list(err)}


plays.append(play("parse: the observed post-enable failure is unparsed and marked unavailable",
                  {"secrets_encryption_status_input": unavailable()}, parse, False,
                  [f"not ({P}.parsed | bool)", f"{P}.unavailable | bool", f"'status-command-failed' in {P}.problems",
                   f"{P}.encryption == 'unknown'", f"{P} | to_json is not search('00459|CA hash')"]))
for label, result in (
        ("another server error", unavailable(err=['level=fatal msg="Error: Get \\"https://127.0.0.1:6443\\": connection refused"'])),
        ("exit status 0 with no output", unavailable(rc=0)),
        ("standard output present", unavailable(out=["Encryption Status: Disabled"])),
        ("no error output", unavailable(err=())),
        ("two fatal lines", unavailable(err=(FATAL_INTERNAL, FATAL_INTERNAL))),
        ("a non-numeric error ID", unavailable(err=(FATAL_INTERNAL.replace("00459", "x"),))),
        ("text after the error", unavailable(err=(FATAL_INTERNAL + " retry",))),
        ("missing exit status", {"stdout_lines": [], "stderr_lines": [FATAL_INTERNAL]})):
    plays.append(play(f"parse: not unavailable with {label}", {"secrets_encryption_status_input": result}, parse, False,
                      [f"not ({P}.parsed | bool)", f"not ({P}.unavailable | bool)"]))

# ---------------------------------------------------------------- gather summary and health gate
NOW = 100000
STATE_FILES = role_vars["secrets_encryption_state_files"]
CHRONY_OK = "A1B2C3D4,pool.example,2,1792483200.1,0.000012,-0.000001,0.000020,-12.3,-0.001,0.01,0.001,0.002,64.2,Normal"


def b64(s):
    return base64.b64encode(s.encode()).decode()


def results(values):
    return {"results": [dict(v, item=h) for h, v in zip(SERVERS, values)]}


def absent():
    return {"failed": True, "msg": "file not found"}


def statefiles(overrides=None):
    out = []
    for h in SERVERS:
        for f in STATE_FILES:
            out.append({"item": [h, f], "stat": (overrides or {}).get((h, f), {"exists": False})})
    return {"results": out}


def probes(svc=None, ver=None, readyz=None, etcd=None, chrony=None, swap=None, dropin=None, change=None, verified=None,
           statedir=None, sfiles=None, status_lines=None, nodes=None, etcd_nodes=None, flux=None, flux_rc=0, helm=None, helm_rc=0,
           deploy=None, sts=None, ds=None, df=None, snaps=None, dbs=None, baseline=None, marker=None, ledger=None, protected=None,
           status_results=None, checkpoints=None):
    six = ["flux-system/flux-system", "flux-system/infrastructure-controllers", "flux-system/infrastructure-configs",
           "flux-system/monitoring", "flux-system/monitoring-configs", "flux-system/apps"]
    return {
        "secrets_encryption_service_probe": results(svc or [{"rc": 0, "stdout": "NRestarts=0\nActiveState=active\nActiveEnterTimestamp=@50000"}] * 3),
        "secrets_encryption_version_probe": results(ver or [{"rc": 0, "stdout_lines": ["k3s version v1.36.4+k3s1 (0123abcd)", "go version go1.25"]}] * 3),
        "secrets_encryption_readyz_probe": results(readyz or [{"rc": 0, "stdout": "ok"}] * 3),
        "secrets_encryption_etcd_probe": results(etcd or [{"rc": 0, "stdout": "ok"}] * 3),
        "secrets_encryption_chrony_probe": results(chrony or [{"rc": 0, "stdout": CHRONY_OK}] * 3),
        "secrets_encryption_swap_probe": results(swap or [{"rc": 0, "stdout_lines": []}] * 3),
        "secrets_encryption_dropin_probe": results(dropin or [{"stat": {"exists": False}}] * 3),
        "secrets_encryption_dropin_change_probe": results(change or [absent()] * 3),
        "secrets_encryption_verified_probe": results(verified or [absent()] * 3),
        "secrets_encryption_statedir_probe": results(statedir or [{"stat": {"exists": False}}] * 3),
        "secrets_encryption_statefile_probe": sfiles or statefiles(),
        "secrets_encryption_status_probe": results(status_results or [{"rc": 0, "stdout_lines": s} for s in (status_lines or [NOCONF_LINES] * 3)]),
        "secrets_encryption_nodes_probe": {"rc": 0, "stdout_lines": nodes if nodes is not None else [f"{h}|True|False|False|False" for h in SERVERS]},
        "secrets_encryption_etcd_nodes_probe": {"rc": 0, "stdout_lines": etcd_nodes if etcd_nodes is not None else [f"node/{h}" for h in SERVERS]},
        "secrets_encryption_flux_probe": {"rc": flux_rc, "stdout_lines": flux if flux is not None else [f"{k}=True" for k in six]},
        "secrets_encryption_helm_probe": {"rc": helm_rc, "stdout_lines": helm if helm is not None else
                                          ["metallb-system/metallb=True", "monitoring/kube-prometheus-stack=True"]},
        "secrets_encryption_deployments_probe": {"rc": 0, "stdout_lines": deploy if deploy is not None else
                                                 ["platform-demo/platform-canary=2/2", "monitoring/grafana=1/1"]},
        "secrets_encryption_statefulsets_probe": {"rc": 0, "stdout_lines": sts if sts is not None else
                                                  ["monitoring/prometheus-main=1/1", "monitoring/alertmanager-main=1/1"]},
        "secrets_encryption_daemonsets_probe": {"rc": 0, "stdout_lines": ds if ds is not None else ["monitoring-node-exporter/node-exporter=3/3"]},
        "secrets_encryption_df_probe": results(df or [{"rc": 0, "stdout_lines": ["Avail", "50000M"]}] * 3),
        "secrets_encryption_snapshots_probe": results(snaps or [{"files": [{"path": "/s/etcd-snapshot-x-1", "mtime": 1, "size": 1}]}] * 3),
        "secrets_encryption_db_probe": results(dbs or [{"files": [{"path": "/db/etcd"}]}] * 3),
        "secrets_encryption_baseline_probe": results(baseline or [absent()] * 3),
        "secrets_encryption_marker_probe": {"content": b64(marker)} if marker else absent(),
        "secrets_encryption_ledger_probe": {"content": b64(ledger)} if ledger else absent(),
        "secrets_encryption_checkpoints_probe": {"content": b64(checkpoints)} if checkpoints else absent(),
        "secrets_encryption_now_probe": {"rc": 0, "stdout": str(NOW)},
        "secrets_encryption_protected_probe": {"results": protected or []},
    }


summary_tasks = picks("gather", "Reset the parsed status", "Parse the status of each server", "Summarize the gathered state")
HP = "secrets_encryption_report.health_problems"
NO_IP = r"secrets_encryption_report | to_json is not search('\\b[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\b')"


def health(label, mocks, problem=None, checks=(), extra_vars=None, tasks=None, setup=()):
    c = [f"{HP} | length == 0"] if problem is None else [f"{HP} | select('search', {json.dumps(problem)}) | list | length > 0"]
    c += ["secrets_encryption_report | to_json is not search('sentinel')", NO_IP]
    plays.append(play(f"health: {label}", mocks, tasks or summary_tasks, False, c + list(checks), extra_vars, setup=setup))


REHEARSAL_GATE = {"secrets_encryption_expected_kustomizations": [], "secrets_encryption_min_helmreleases": 0,
                  "secrets_encryption_monitoring_namespaces": [], "secrets_encryption_min_monitoring_statefulsets": 0,
                  "secrets_encryption_min_monitoring_daemonsets": 0, "secrets_encryption_canary_deployment": ""}
health("healthy cluster passes", probes(), checks=[
    "secrets_encryption_servers.k3s02.start_epoch == 50000", "secrets_encryption_servers.k3s02.version == 'v1.36.4+k3s1'",
    "secrets_encryption_servers.k3s03.free_mb == 50000", "secrets_encryption_servers.k3s01.swap_bytes | int == 0",
    "secrets_encryption_servers.k3s01.chrony_synchronized | bool", "secrets_encryption_servers.k3s01.state_safe | bool",
    "not secrets_encryption_marker.present | bool", "secrets_encryption_used_confirmations == []"])
health("checkpoint: restarted after the change and verified afterwards",
       probes(marker="40000 enable", verified=[{"content": b64("55000")}, {"content": b64("45000")}, absent()],
              change=[absent(), absent(), {"content": b64("60000")}]),
       checks=["secrets_encryption_servers.k3s01.checkpoint_reached | bool",
               "secrets_encryption_servers.k3s02.restarted_since_change | bool and not secrets_encryption_servers.k3s02.checkpoint_reached | bool",
               "not secrets_encryption_servers.k3s03.restarted_since_change | bool and not secrets_encryption_servers.k3s03.checkpoint_reached | bool",
               "secrets_encryption_marker.phase == 'enable' and secrets_encryption_marker.epoch | int == 40000"])
health("used confirmations are read from the ledger", probes(ledger="20261020T080000Z enable k3s01\n20261020T081000Z restart k3s02\n"),
       checks=["secrets_encryption_used_confirmations == ['20261020T080000Z', '20261020T081000Z']"])
health("inactive service", probes(svc=[{"rc": 0, "stdout": "ActiveState=failed\nActiveEnterTimestamp=@1\nNRestarts=3"}] * 3), "k3s.service not active")
health("unreadable service state", probes(svc=[{"rc": 1, "stdout": ""}] * 3), "service state unreadable")
health("other K3s version", probes(ver=[{"rc": 0, "stdout_lines": ["k3s version v1.36.5+k3s1 (x)"]}] * 3), "expected v1.36.4")
health("empty version output", probes(ver=[{"rc": 0, "stdout_lines": []}] * 3), "K3s unknown")
health("local /readyz not ok on one server", probes(readyz=[{"rc": 0, "stdout": "ok"}, {"rc": 1, "stdout": ""}, {"rc": 0, "stdout": "ok"}]),
       "k3s02: local /readyz")
health("local etcd not ok on one server", probes(etcd=[{"rc": 0, "stdout": "ok"}, {"rc": 0, "stdout": "ok"}, {"rc": 0, "stdout": "[-]etcd failed"}]),
       "k3s03: local /readyz/etcd")
health("unparsed status", probes(status_lines=[["garbage"]] * 3), "status not parsed")
health("re-encryption active on one server", probes(status_lines=[
    ["Encryption Status: Enabled", "Current Rotation Stage: reencrypt_active", "Server Encryption Hashes: All hashes match"] + KEYS
    + [" *      XSalsa20-POLY1305  k1"]] + [ENABLED] * 2), "rotation stage reencrypt_active is not settled")
health("hash mismatch names are never reported", probes(status_lines=[IDENTITY[:2] + [
    "Server Encryption Hashes: hash does not match between node-sentinel-a and node-sentinel-b"]] * 3),
    checks=["not (secrets_encryption_servers.k3s01.status.hashes_match | bool)"])
health("Chrony not synchronized", probes(chrony=[{"rc": 0, "stdout": CHRONY_OK.replace("Normal", "Not synchronised")}] + [{"rc": 0, "stdout": CHRONY_OK}] * 2),
       "k3s01: Chrony not synchronized")
health("Chrony unreadable", probes(chrony=[{"rc": 1, "stdout": ""}] * 3), "Chrony not synchronized or unreadable")
health("Chrony offset too large", probes(chrony=[{"rc": 0, "stdout": CHRONY_OK.replace(",0.000012,", ",0.25,")}] * 3), "Chrony offset")
health("swap unreadable", probes(swap=[{"rc": 1, "stdout_lines": []}] * 3), "swap state unreadable")
health("swap changed since the baseline", probes(swap=[{"rc": 0, "stdout_lines": ["2147483648"]}] + [{"rc": 0, "stdout_lines": []}] * 2,
       baseline=[{"content": b64(json.dumps({"snapshots": [], "db_dirs": [], "protected": {}, "swap_bytes": 0}))}] + [absent()] * 2),
       "k3s01: swap changed")
health("swap unchanged since the baseline passes", probes(swap=[{"rc": 0, "stdout_lines": ["1024", "1024"]}] * 3,
       baseline=[{"content": b64(json.dumps({"snapshots": [], "db_dirs": [], "protected": {}, "swap_bytes": 2048}))}] * 3))
health("state directory is a symbolic link", probes(statedir=[{"stat": {"exists": True, "isdir": False, "islnk": True, "uid": 0, "mode": "0777"}}]
       + [{"stat": {"exists": False}}] * 2), "k3s01: state directory")
health("state directory not root-only", probes(statedir=[{"stat": {"exists": True, "isdir": True, "islnk": False, "uid": 0, "mode": "0755"}}] * 3),
       "state directory")
health("confirmation ledger is a symbolic link", probes(sfiles=statefiles({("k3s01", "confirmations"):
       {"exists": True, "isreg": False, "islnk": True, "uid": 0}})), "k3s01: state directory or a state file")
health("state file not owned by root", probes(sfiles=statefiles({("k3s02", "last-change"): {"exists": True, "isreg": True, "islnk": False, "uid": 1000}})),
       "k3s02: state directory or a state file")
health("state file probe incomplete", probes(sfiles={"results": statefiles()["results"][:-1]}), "k3s03: state directory or a state file")
health("node not Ready", probes(nodes=["k3s01|True|False|False|False", "k3s02|False|False|False|False", "k3s03|True|False|False|False"]),
       "node not Ready: k3s02")
health("node under memory pressure", probes(nodes=["k3s01|True|True|False|False", "k3s02|True|False|False|False", "k3s03|True|False|False|False"]),
       "node under pressure or unreported: k3s01")
health("node pressure unreported", probes(nodes=["k3s01|True|||", "k3s02|True|False|False|False", "k3s03|True|False|False|False"]),
       "node under pressure or unreported: k3s01")
health("extra node", probes(nodes=[f"{h}|True|False|False|False" for h in SERVERS + ["agent01"]]), "nodes: expected exactly")
health("duplicated node", probes(nodes=[f"{h}|True|False|False|False" for h in SERVERS + ["k3s01"]]), "nodes: expected exactly")
health("node list empty", probes(nodes=[]), "nodes: expected exactly")
health("etcd member missing", probes(etcd_nodes=["node/k3s01", "node/k3s02"]), "etcd member nodes: expected exactly")
health("unexpected etcd member", probes(etcd_nodes=["node/k3s01", "node/k3s02", "node/k3s03", "node/other"]), "etcd member nodes: expected exactly")
health("Kustomization missing", probes(flux=["flux-system/flux-system=True"]), "flux-system/apps: present 0 times")
health("unexpected Kustomization not Ready", probes(flux=[f"{k}=True" for k in ["flux-system/flux-system", "flux-system/infrastructure-controllers",
       "flux-system/infrastructure-configs", "flux-system/monitoring", "flux-system/monitoring-configs", "flux-system/apps"]]
       + ["flux-system/extra="]), "Kustomization not Ready: flux-system/extra")
health("Kustomization read failure", probes(flux_rc=1), "Flux Kustomizations: read failed")
health("HelmRelease not Ready", probes(helm=["metallb-system/metallb=True", "monitoring/kube-prometheus-stack=False"]),
       "HelmRelease not Ready: monitoring/kube-prometheus-stack")
health("too few HelmReleases", probes(helm=["metallb-system/metallb=True"]), "HelmReleases: 1 found, 2 required")
health("duplicated HelmRelease", probes(helm=["metallb-system/metallb=True", "metallb-system/metallb=True"]), "HelmReleases: duplicated")
health("HelmRelease read failure", probes(helm_rc=1), "HelmReleases: read failed")
health("Deployment unavailable", probes(deploy=["platform-demo/platform-canary=2/2", "monitoring/grafana=0/1"]), "monitoring/grafana=0/1")
health("canary Deployment missing", probes(deploy=["monitoring/grafana=1/1"]), "canary Deployment platform-demo/platform-canary")
health("canary Deployment scaled to zero", probes(deploy=["platform-demo/platform-canary=/0"]), "canary Deployment platform-demo/platform-canary")
health("StatefulSet not ready (null readyReplicas)", probes(sts=["monitoring/prometheus-main=/1", "monitoring/alertmanager-main=1/1"]),
       "StatefulSets not fully ready: monitoring/prometheus-main=/1")
health("DaemonSet not ready", probes(ds=["monitoring-node-exporter/node-exporter=2/3"]), "DaemonSets not fully ready")
health("too few monitoring StatefulSets", probes(sts=["monitoring/prometheus-main=1/1"]), "monitoring StatefulSets: 1 found")
health("monitoring namespace empty", probes(ds=[]), "monitoring-node-exporter: no StatefulSets or DaemonSets")
health("low free space", probes(df=[{"rc": 0, "stdout_lines": ["Avail", "100M"]}] * 3), "free space")
health("snapshot directory unreadable", probes(snaps=[{"failed": True, "msg": "permission denied"}] * 3), "snapshot or database directory unreadable")
health("malformed state marker", probes(marker="soon enable"), "state marker malformed")
health("rehearsal without Flux, Helm or monitoring passes", probes(flux=[], flux_rc=1, helm=[], helm_rc=1, deploy=[], sts=[], ds=[]),
       extra_vars=REHEARSAL_GATE)

# ---------------------------------------------------------------- the enable restart round (gathered state)
# Marker at 40000 (enable); a pre-enable Stage 3 snapshot at 39000 on k3s01;
# servers that have not restarted since enable started at 30000.
LEDGER_OK = "20261023T160800Z snapshot k3s01\n20261023T160830Z enable k3s01\n"
PRE_SNAP = [{"files": [{"path": "/s/stage3-p0-pre-enable-20261023t160817z-k3s01-1", "mtime": 39000, "size": 10},
                       {"path": "/s/etcd-snapshot-x-1", "mtime": 1, "size": 1}]}] + [{"files": [{"path": "/s/etcd-snapshot-x-1", "mtime": 1, "size": 1}]}] * 2
SHA = "a" * 64
CP_OK = f"39000 p0-pre-enable stage3-p0-pre-enable-20261023t160817z-k3s01-1 10 {SHA} token=present\n"
P0_TASK = "Summarize the checkpoint records and the pre-enable checkpoint"
UNAV3 = [unavailable()] * 3
NOT_PARSED = "secrets-encrypt status not parsed"


def round_probes(started=(30000, 30000, 30000), verified=(None, None, None), dropin=(False, False, False), status=None,
                 ledger=LEDGER_OK, snaps=None, marker="40000 enable", change=None, checkpoints=CP_OK):
    return probes(svc=[{"rc": 0, "stdout": f"NRestarts=0\nActiveState=active\nActiveEnterTimestamp=@{s}"} for s in started],
                  verified=[{"content": b64(str(v))} if v else absent() for v in verified],
                  dropin=[{"stat": {"exists": d, "isreg": d, "islnk": False}} for d in dropin],
                  change=change, status_results=status or UNAV3, ledger=ledger, snaps=snaps or PRE_SNAP, marker=marker,
                  checkpoints=checkpoints)


RESTART = {"secrets_encryption_phase": "restart"}
ROUND = "secrets_encryption_enable_round"
health("enable round: an unavailable status on every server is tolerated before k3s01 restarts", round_probes(), extra_vars=RESTART,
       checks=[f"{ROUND}.tolerate_unavailable_status | bool", f"{ROUND}.next == 'k3s01'", f"not ({ROUND}.complete | bool)",
               f"{ROUND}.out_of_order == ''", "secrets_encryption_servers.k3s02.status.unavailable | bool",
               "secrets_encryption_report.encryption.k3s01.unavailable | bool"])
health("enable round: tolerated for k3s02 after k3s01 passed", round_probes(started=(50000, 30000, 30000), verified=(55000, None, None),
       dropin=(True, False, False), change=[{"content": b64("45000")}, absent(), absent()]), extra_vars=RESTART,
       checks=[f"{ROUND}.next == 'k3s02'", f"{ROUND}.verified | int == 1", f"{ROUND}.tolerate_unavailable_status | bool"])
health("enable round: tolerated for k3s03's own restart before it is verified",
       round_probes(started=(50000, 50000, 50000), verified=(55000, 55000, None), dropin=(True, True, True)), extra_vars=RESTART,
       checks=[f"{ROUND}.next == 'k3s03'", f"{ROUND}.tolerate_unavailable_status | bool"])
health("enable round: a readable Disabled status is accepted during the round",
       round_probes(status=[{"rc": 0, "stdout_lines": IDENTITY}] + [unavailable()] * 2), extra_vars=RESTART)
health("enable round: a readable Enabled status during the round fails",
       round_probes(status=[{"rc": 0, "stdout_lines": ENABLED}] + [unavailable()] * 2), "encryption Enabled during the enable restart round",
       extra_vars=RESTART)
for label, mocks, extra, checks in (
        ("in the snapshot phase (checkpoint p1)", round_probes(), {"secrets_encryption_phase": "snapshot"}, []),
        ("in the rotate-keys phase", round_probes(), {"secrets_encryption_phase": "rotate-keys"}, []),
        ("in the read-only validation (no phase)", round_probes(), {}, []),
        ("with the drop-in removal requested", round_probes(), dict(RESTART, secrets_encryption_flag_state="absent"), []),
        ("without an enable marker", round_probes(marker=None), RESTART, [f"not ({ROUND}.active | bool)"]),
        ("after a later recorded change (rotate-keys marker)", round_probes(marker="40000 rotate-keys"), RESTART, []),
        ("when the ledger lacks enable", round_probes(ledger="20261023T160800Z snapshot k3s01\n"), RESTART, [f"not ({ROUND}.ledger_ok | bool)"]),
        ("when the ledger has no snapshot before enable", round_probes(ledger="20261023T160830Z enable k3s01\n20261023T160900Z snapshot k3s01\n"),
         RESTART, [f"not ({ROUND}.ledger_ok | bool)"]),
        ("when the marker is stale (ledger records rotate-keys)", round_probes(ledger=LEDGER_OK + "20261023T170000Z rotate-keys k3s01\n"), RESTART,
         [f"not ({ROUND}.ledger_ok | bool)"]),
        ("when the marker is stale (ledger records disable)", round_probes(ledger=LEDGER_OK + "20261023T170000Z disable k3s01\n"), RESTART,
         [f"not ({ROUND}.ledger_ok | bool)"]),
        ("with a malformed ledger line", round_probes(ledger=LEDGER_OK + "garbage\n"), RESTART, [f"not ({ROUND}.ledger_ok | bool)"]),
        ("without a recorded p0 checkpoint", round_probes(checkpoints=""), RESTART, [f"not ({ROUND}.checkpoint_ok | bool)"]),
        ("when the p0 record's size differs", round_probes(checkpoints=CP_OK.replace(" 10 ", " 11 ")), RESTART,
         [f"not ({ROUND}.checkpoint_ok | bool)"]),
        ("with a malformed checkpoint record", round_probes(checkpoints=CP_OK + "garbage\n"), RESTART, [f"not ({ROUND}.checkpoint_ok | bool)"]),
        ("without a snapshot older than enable", round_probes(snaps=[{"files": [{"path": "/s/stage3-p1-late-k3s01-1", "mtime": 45000, "size": 10}]}]
                                                              + PRE_SNAP[1:]), RESTART, [f"not ({ROUND}.checkpoint_ok | bool)"]),
        ("when k3s03 restarted before k3s02 (out of order)", round_probes(started=(50000, 30000, 50000), verified=(55000, None, None),
                                                                          dropin=(True, False, False)), RESTART, [f"{ROUND}.out_of_order == 'k3s03'"]),
        ("when k3s03 carries a drop-in before k3s01 passed (partial round)", round_probes(dropin=(False, False, True)), RESTART,
         [f"{ROUND}.out_of_order == 'k3s03'"]),
        ("when k3s02 recorded a verified restart before k3s01 (skipped node)", round_probes(verified=(None, 45000, None)), RESTART,
         [f"{ROUND}.out_of_order == 'k3s02'"]),
        ("after the round completed", round_probes(started=(50000, 50000, 50000), verified=(55000, 55000, 55000), dropin=(True, True, True)),
         RESTART, [f"{ROUND}.complete | bool", f"{ROUND}.next == ''"]),
        ("for any other status failure", round_probes(status=[unavailable(err=['level=fatal msg="connection refused"'])] + UNAV3[1:]),
         RESTART, [f"{ROUND}.tolerate_unavailable_status | bool"])):
    health(f"enable round: an unavailable status fails {label}", mocks, NOT_PARSED, extra_vars=extra,
           checks=checks + ([] if label == "for any other status failure" else [f"not ({ROUND}.tolerate_unavailable_status | bool)"]))

# Real stat tasks against a local state directory with a symbolic-link ledger.
tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="secrets-encryption-test."))
sd = tmp_root / "statedir"
sd.mkdir(mode=0o700)
os.chmod(sd, 0o700)
(tmp_root / "elsewhere").write_text("x")
os.symlink(tmp_root / "elsewhere", sd / "confirmations")
real_state_stat = picks("gather", "Inspect the Stage 3 state directory on every server", "Inspect the Stage 3 state files on every server")
mocked = {k: v for k, v in probes().items() if k not in ("secrets_encryption_statedir_probe", "secrets_encryption_statefile_probe")}
health("real lstat of a symbolic-link ledger fails the gate", mocked, "state directory or a state file",
       extra_vars={"secrets_encryption_state_dir": str(sd), "secrets_encryption_state_owner_uid": UID}, tasks=real_state_stat + summary_tasks)
sd_ok = tmp_root / "statedir-ok"
sd_ok.mkdir(mode=0o700)
os.chmod(sd_ok, 0o700)
(sd_ok / "confirmations").write_text("20261020T080000Z enable k3s01\n")
health("real lstat of a safe state directory passes", mocked, None, checks=["secrets_encryption_servers.k3s01.state_safe | bool"],
       extra_vars={"secrets_encryption_state_dir": str(sd_ok), "secrets_encryption_state_owner_uid": UID}, tasks=real_state_stat + summary_tasks)

# ---------------------------------------------------------------- confirmation replay (gate)
replay = picks("gate", "Refuse a confirmation that was already used")
RF = "Refuse a confirmation that was already used"
plays.append(play("confirmation: a new value passes", {"secrets_encryption_used_confirmations": ["20261020T080000Z"],
                                                       "secrets_encryption_confirm_id": "20261020T090000Z"}, replay, False))
plays.append(play("confirmation: replay of the same value is refused", {"secrets_encryption_used_confirmations": ["20261020T080000Z"],
                                                                        "secrets_encryption_confirm_id": "20261020T080000Z"}, replay, RF))
plays.append(play("confirmation: a value used by another phase or host is refused",
                  {"secrets_encryption_used_confirmations": ["20261020T070000Z", "20261020T080000Z"],
                   "secrets_encryption_confirm_id": "20261020T070000Z"}, replay, RF))
plays.append(play("confirmation: a malformed value is refused", {"secrets_encryption_used_confirmations": [],
                                                                 "secrets_encryption_confirm_id": "now"}, replay, RF))

# Real state-directory creation and checks, unprivileged.
mk = unroot(picks("gate", "Ensure the Stage 3 state directory exists on every server", "Re-inspect the Stage 3 state directory on every server",
                  "Require a root-only state directory on every server"))
for t in mk:
    t.pop("delegate_to", None)
mk[0]["loop"] = ["k3s01"]
mk[1]["loop"] = ["k3s01"]
plays.append(play("state directory: created root-only and accepted", {}, mk, False,
                  extra_vars={"secrets_encryption_state_dir": str(tmp_root / "statedir-new"), "secrets_encryption_state_owner_uid": UID}))
(tmp_root / "real-dir").mkdir()
os.symlink(tmp_root / "real-dir", tmp_root / "statedir-link")
plays.append(play("state directory: a symbolic link is refused before any write", {}, mk, "Ensure the Stage 3 state directory exists on every server",
                  extra_vars={"secrets_encryption_state_dir": str(tmp_root / "statedir-link"), "secrets_encryption_state_owner_uid": UID}))

# ---------------------------------------------------------------- preservation and freshness
checks_tasks = picks("checks", "Evaluate snapshot and database preservation", "Evaluate snapshot freshness")


def storage(snapshot_names=("etcd-snapshot-k3s01-1", "on-demand-stage2-1"), db_dirs=("etcd-old-1",), baseline=None, stage3=(), protected=None):
    return {"snapshots_read": True, "db_read": True, "snapshot_names": list(snapshot_names), "db_dirs": list(db_dirs),
            "stage3_snapshots": [{"path": f"/s/{n}", "mtime": m, "size": 10} for n, m in stage3], "baseline": baseline,
            "protected": protected or {}}


def store(first, others=None):
    return {"secrets_encryption_storage": {"k3s01": first, "k3s02": others or storage(), "k3s03": others or storage()},
            "secrets_encryption_now_epoch": NOW, "secrets_encryption_marker": {"present": True, "malformed": False, "epoch": 90000, "phase": "enable"}}


PP = "secrets_encryption_preservation_problems"
FR = "secrets_encryption_snapshot_gate.fresh | bool"
base = {"snapshots": ["on-demand-stage2-1"], "db_dirs": ["etcd-old-1"]}
plays.append(play("preservation: no baseline yet passes", store(storage()), checks_tasks, False, [f"{PP} == ''"]))
plays.append(play("preservation: everything in the baseline still present", store(storage(baseline=base)), checks_tasks, False, [f"{PP} == ''"]))
plays.append(play("preservation: a pruned scheduled snapshot is not a problem",
                  store(storage(snapshot_names=["on-demand-stage2-1"], baseline=base)), checks_tasks, False, [f"{PP} == ''"]))
plays.append(play("preservation: a missing on-demand snapshot fails", store(storage(snapshot_names=["etcd-snapshot-k3s01-1"], baseline=base)),
                  checks_tasks, False, [f"{PP} is search('snapshot missing since baseline: on-demand-stage2-1')"]))
plays.append(play("preservation: a missing preserved database directory fails", store(storage(baseline=base), storage(db_dirs=[], baseline=base)),
                  checks_tasks, False, [f"{PP} is search('k3s02: database directory missing since baseline: etcd-old-1')"]))
plays.append(play("preservation: a malformed baseline fails", store(storage(baseline={"snapshots": []})), checks_tasks, False,
                  [f"{PP} is search('baseline malformed')"]))
PDIR = "/protected-sentinel/db/etcd-old-1"
PFILE = "/protected-sentinel/snap-1"
prot_vars = {"secrets_encryption_protected_paths": {"k3s02": [PDIR, PFILE]}}
pdir_ok = {"exists": True, "isdir": True, "isreg": False, "islnk": False, "size": 4096, "mtime": 10}
pfile_ok = {"exists": True, "isdir": False, "isreg": True, "islnk": False, "size": 500, "mtime": 20}
pbase = dict(base, protected={PDIR: pdir_ok, PFILE: pfile_ok})
for label, prot, baseline, problem in (
        ("present and unchanged", {PDIR: pdir_ok, PFILE: pfile_ok}, pbase, None),
        ("present, first baseline", {PDIR: pdir_ok, PFILE: pfile_ok}, None, None),
        ("a directory missing", {PDIR: {"exists": False}, PFILE: pfile_ok}, pbase, "k3s02: protected artifact #1 missing"),
        ("a file never inspected", {PDIR: pdir_ok}, pbase, "k3s02: protected artifact #2 missing"),
        ("a file changed size", {PDIR: pdir_ok, PFILE: dict(pfile_ok, size=501)}, pbase, "k3s02: protected artifact #2 changed"),
        ("a file changed time", {PDIR: pdir_ok, PFILE: dict(pfile_ok, mtime=21)}, pbase, "k3s02: protected artifact #2 changed"),
        ("a directory replaced by a file", {PDIR: dict(pfile_ok), PFILE: pfile_ok}, pbase, "k3s02: protected artifact #1 changed"),
        ("a symbolic link", {PDIR: dict(pdir_ok, islnk=True), PFILE: pfile_ok}, pbase, "k3s02: protected artifact #1 is not a plain")):
    checks = [f"{PP} == ''"] if problem is None else [f"{PP} is search({json.dumps(problem)})", f"{PP} is not search('sentinel')"]
    plays.append(play(f"protected artifacts: {label}", store(storage(), storage(baseline=baseline, protected=prot)), checks_tasks, False,
                      checks, prot_vars))
plays.append(play("freshness: a recent Stage 3 snapshot is fresh", store(storage(stage3=[("stage3-p0-x", NOW - 600)])), checks_tasks, False, [FR]))
plays.append(play("freshness: no Stage 3 snapshot is not fresh", store(storage()), checks_tasks, False, [f"not {FR}"]))
plays.append(play("freshness: an old Stage 3 snapshot is not fresh", store(storage(stage3=[("stage3-p0-x", NOW - 3 * 3600)])),
                  checks_tasks, False, [f"not {FR}"]))
plays.append(play("freshness: the newest of several snapshots counts",
                  store(storage(stage3=[("stage3-a", NOW - 9000), ("stage3-b", NOW - 60)])), checks_tasks, False, [FR]))
plays.append(play("freshness: a snapshot older than the last change is refused when required",
                  store(storage(stage3=[("stage3-p1-x", 89000)])), checks_tasks, False, [f"not {FR}"],
                  {"secrets_encryption_snapshot_after_change": True, "secrets_encryption_snapshot_max_age_minutes": 1000}))
plays.append(play("freshness: a snapshot newer than the last change passes when required",
                  store(storage(stage3=[("stage3-p1-x", 95000)])), checks_tasks, False, [FR],
                  {"secrets_encryption_snapshot_after_change": True}))

# The p0 latch (live-readiness review, 2026-10-27): the exclusive enable round
# refuses new snapshots, so a round that outlasts the freshness limit must not
# refuse its own next restart. Marker 90000 (enable), p0 at 89000, now 100000:
# p0 is 11000 s old, beyond the 7200 s limit.
LATCH_ROUND = {"active": True, "complete": False, "next": "k3s02", "ledger_ok": True, "checkpoint_ok": True, "out_of_order": ""}
LATCH_P0 = {"newest_is_p0": True, "newest_recorded": True, "records_malformed": False}
LATCHED = "secrets_encryption_snapshot_gate.p0_latched | bool"


def latch_mocks(round_=None, p0=None, stage3=(("stage3-p0-pre-enable-x", 89000),), marker_epoch=90000):
    m = store(storage(stage3=list(stage3)))
    m["secrets_encryption_marker"] = dict(m["secrets_encryption_marker"], epoch=marker_epoch)
    m["secrets_encryption_enable_round"] = dict(LATCH_ROUND, **(round_ or {}))
    m["secrets_encryption_p0"] = dict(LATCH_P0, **(p0 or {}))
    return m


LATCH_CASES = {
    "the next restart of the round with a stale p0": (latch_mocks(), "k3s02", RESTART),
    "the first restart of the round with a stale p0": (latch_mocks({"next": "k3s01"}), "k3s01", RESTART),
    "enable with a stale p0": (latch_mocks(), "k3s02", {"secrets_encryption_phase": "enable"}),
    "rotation with a stale p0": (latch_mocks(), "k3s02", {"secrets_encryption_phase": "rotate-keys"}),
    "canary controls with a stale p0": (latch_mocks(), "k3s02", {"secrets_encryption_phase": "canary-create-control"}),
    "drop-in removal with a stale p0": (latch_mocks(), "k3s02", dict(RESTART, secrets_encryption_flag_state="absent")),
    "a skipped server": (latch_mocks(), "k3s03", RESTART),
    "a replayed server": (latch_mocks(), "k3s01", RESTART),
    "a completed round": (latch_mocks({"complete": True, "next": ""}), "k3s02", RESTART),
    "no active round": (latch_mocks({"active": False, "next": ""}), "k3s02", RESTART),
    "an inconsistent ledger": (latch_mocks({"ledger_ok": False}), "k3s02", RESTART),
    "no recorded pre-enable checkpoint": (latch_mocks({"checkpoint_ok": False}), "k3s02", RESTART),
    "an out-of-order round": (latch_mocks({"out_of_order": "k3s03"}), "k3s02", RESTART),
    "a newest snapshot that is not p0": (latch_mocks(p0={"newest_is_p0": False}), "k3s02", RESTART),
    "a p0 without a matching record": (latch_mocks(p0={"newest_recorded": False}), "k3s02", RESTART),
    "malformed checkpoint records": (latch_mocks(p0={"records_malformed": True}), "k3s02", RESTART),
    "a p0 newer than the enable marker": (latch_mocks(marker_epoch=80000, stage3=(("stage3-p0-pre-enable-x", 85000),)), "k3s02", RESTART),
    "no Stage 3 snapshot on the first server": (latch_mocks(stage3=()), "k3s02", RESTART),
}


def latch_scenario(base, label, case, fresh):
    mocks, host, extra = LATCH_CASES[case]
    tasks = picks("checks", "Evaluate snapshot and database preservation", "Evaluate snapshot freshness", base=base)
    checks = [FR, LATCHED] if fresh else [f"not {FR}", f"not {LATCHED}"]
    return dict(name=f"p0 latch: {label}", mocks=mocks, tasks=tasks, expect_fail=False, checks=checks, extra_vars=extra, host=host)


LATCH_ALLOWED = ("the next restart of the round with a stale p0", "the first restart of the round with a stale p0")
for case in LATCH_CASES:
    sc = latch_scenario(None, ("latched: " if case in LATCH_ALLOWED else "not latched: ") + case, case, case in LATCH_ALLOWED)
    plays.append(play(sc["name"], sc["mocks"], sc["tasks"], sc["expect_fail"], sc["checks"], sc["extra_vars"], sc["host"]))
plays.append(play("p0 latch: a fresh snapshot stays fresh outside the round", store(storage(stage3=[("stage3-p1-x", NOW - 600)])), checks_tasks, False,
                  [FR, f"not {LATCHED}"], RESTART))
# The real summaries: marker 40000 (enable), the recorded p0 at 39000, now 100000.
latch_real = picks("gather", "Reset the parsed status", "Parse the status of each server", "Summarize the gathered state") + checks_tasks
plays.append(play("p0 latch (gathered state): the round's next server restarts with the stale recorded p0", round_probes(), latch_real, False,
                  [FR, LATCHED, "secrets_encryption_enable_round.next == 'k3s01'"], RESTART))
plays.append(play("p0 latch (gathered state): any other server is refused", round_probes(), latch_real, False, [f"not {FR}"], RESTART, host="k3s02"))
# Phase binding, on the guard task itself: the scenario plays carry the exact play names.
BIND = "Bind the phase to the running play"
CANARY_PLAY = "Run the Stage 3 encryption canary"
BIND_CASES = {
    "restart as itself": (RESTART_PLAY, {"secrets_encryption_phase": "restart"}, False),
    "restart presented as enable": (RESTART_PLAY, {"secrets_encryption_phase": "enable"}, True),
    "canary verify as itself": (CANARY_PLAY, {"secrets_encryption_phase": "canary-verify", "secrets_encryption_canary_action": "verify"}, False),
    "canary verify presented as cleanup": (CANARY_PLAY, {"secrets_encryption_phase": "canary-cleanup", "secrets_encryption_canary_action": "verify"}, True),
    "a canary action without a committed phase": (CANARY_PLAY, {"secrets_encryption_phase": "canary-restart",
                                                                "secrets_encryption_canary_action": "restart"}, True),
    "an unmapped play": ("phase binding: an unmapped play", {"secrets_encryption_phase": "restart"}, True),
    "an unmapped play without a phase": ("phase binding: an unmapped play without a phase", {}, True),
}


def bind_scenario(base, case):
    name, extra, refused = BIND_CASES[case]
    return dict(name=name, mocks={}, tasks=picks("guard", BIND, base=base), expect_fail=refused and BIND, checks=[], extra_vars=extra)


for case in BIND_CASES:
    sc = bind_scenario(None, case)
    plays.append(play(sc["name"], sc["mocks"], sc["tasks"], sc["expect_fail"], sc["checks"], sc["extra_vars"]))
plays.append(play("p0 latch (gathered state): enable is refused with the stale p0", round_probes(marker=None, ledger="20261023T160800Z snapshot k3s01\n"),
                  latch_real, False, [f"not {FR}"], {"secrets_encryption_phase": "enable"}))

# ---------------------------------------------------------------- snapshot naming and metadata
snap_label = picks("snapshot", "Require a checkpoint label")
for label, value, fail in (("simple label", "p0-pre-enable", False), ("uppercase", "P0", True), ("double hyphen", "p0--x", True),
                           ("leading hyphen", "-p0", True), ("spaces", "p0 x", True), ("too long", "a" * 33, True)):
    plays.append(play(f"snapshot label: {label}", {}, snap_label, fail and "Require a checkpoint label",
                      extra_vars={"secrets_encryption_snapshot_checkpoint": value}))
plays.append(play("snapshot label: missing", {}, snap_label, "Require a checkpoint label"))
snap_name = picks("snapshot", "Name the snapshot", "Require a unique snapshot name")
plays.append(play("snapshot name: unique lowercase name from the server time",
                  {"secrets_encryption_now_epoch": 1792483200, "secrets_encryption_storage": {"k3s01": storage()}}, snap_name, False,
                  ["secrets_encryption_snapshot_name == 'stage3-p0-20261020t080000z'"], {"secrets_encryption_snapshot_checkpoint": "p0"}))
for label, existing in (("an existing file with that name", "stage3-p0-20261020t080000z-k3s01-1792483200"),
                        ("an existing file starting with that name", "stage3-p0-20261020t080000zz")):
    plays.append(play(f"snapshot name: refused when {label} exists",
                      {"secrets_encryption_now_epoch": 1792483200, "secrets_encryption_storage": {"k3s01": storage(snapshot_names=[existing])}},
                      snap_name, "Require a unique snapshot name", extra_vars={"secrets_encryption_snapshot_checkpoint": "p0"}))
snap_cmp = picks("snapshot", "Compare the snapshot metadata", "Require exactly one new snapshot and no protected change")
SN = "stage3-p0-20261020t080000z"
before = {"etcd-snapshot-k3s01-1": {"size": 10, "mtime": 1.5}, "etcd-snapshot-k3s01-2": {"size": 10, "mtime": 2.5},
          "on-demand-stage2": {"size": 30, "mtime": 3.5}}


def after_files(entries):
    return {"files": [{"path": f"/s/{n}", "size": m["size"], "mtime": m["mtime"]} for n, m in entries.items()]}


NEW = {f"{SN}-k3s01-1792483200": {"size": 99, "mtime": 9.0}}
snap_mock = {"secrets_encryption_snapshot_meta_before": before, "secrets_encryption_snapshot_name": SN}
RS = "Require exactly one new snapshot and no protected change"
for label, files, fail, checks in (
        ("exactly one new matching snapshot", dict(before, **NEW), False, ["secrets_encryption_snapshot_scheduled_changes == []"]),
        ("a scheduled snapshot pruned by K3s retention is reported, not refused",
         dict({k: v for k, v in before.items() if k != "etcd-snapshot-k3s01-1"}, **NEW), False,
         ["secrets_encryption_snapshot_scheduled_changes == ['etcd-snapshot-k3s01-1']"]),
        ("a non-scheduled snapshot disappeared", dict({k: v for k, v in before.items() if k != "on-demand-stage2"}, **NEW), RS, []),
        ("a non-scheduled snapshot changed size", dict(before, **NEW, **{"on-demand-stage2": {"size": 31, "mtime": 3.5}}), RS, []),
        ("a non-scheduled snapshot changed time", dict(before, **NEW, **{"on-demand-stage2": {"size": 30, "mtime": 4.5}}), RS, []),
        ("no new snapshot", before, RS, []),
        ("two new snapshots", dict(before, **NEW, **{f"{SN}-k3s01-2": {"size": 1, "mtime": 1}}), RS, []),
        ("new snapshot with another name", dict(before, **{"etcd-snapshot-k3s01-3": {"size": 1, "mtime": 1}}), RS, [])):
    plays.append(play(f"snapshot metadata: {label}", dict(snap_mock, secrets_encryption_snapshots_after=after_files(files)), snap_cmp, fail, checks))

# ---------------------------------------------------------------- phase decisions


def srv(enc="disabled-no-config", stage="none", hashes=True, restarted=True, dropin=False, key_type="none", parsed=True, nrestarts=0, verified=None,
        unavailable=False):
    return {"active": True, "start_epoch": 95000, "nrestarts": nrestarts, "version": "v1.36.4+k3s1", "readyz_ok": True, "etcd_ready": True,
            "dropin_present": dropin, "dropin_change_epoch": 0, "verified_epoch": 0, "free_mb": 50000, "restarted_since_change": restarted,
            "checkpoint_reached": restarted if verified is None else verified,
            "status": {"parsed": parsed, "problems": [], "unavailable": unavailable, "encryption": enc, "stage": stage, "hashes_match": hashes,
                       "hash_state": "match" if hashes else "mismatch", "key_count": 1 if key_type != "none" else 0,
                       "active_key_type": key_type, "active_key_name": "none"}}


def cl(s1, s2=None, s3=None, phase=None, epoch=90000, confirm_id="20261020T080000Z", events=("snapshot k3s01", "enable k3s01"),
       ledger_malformed=False, pre_enable_snapshot=True, stage3=None, checkpoints=None):
    first = storage(stage3=stage3 if stage3 is not None else
                    [("stage3-p0-pre-enable-x", 89000)] if pre_enable_snapshot else [("stage3-p1-x", 95000)])
    if checkpoints is None:
        checkpoints = f"89000 p0-pre-enable stage3-p0-pre-enable-x 10 {SHA} token=present\n" if pre_enable_snapshot else ""
    return {"secrets_encryption_servers": {"k3s01": s1, "k3s02": s2 or s1, "k3s03": s3 or s1},
            "secrets_encryption_marker": {"present": phase is not None, "malformed": False, "epoch": epoch if phase else 0, "phase": phase or "none"},
            "secrets_encryption_report": {"encryption": "mocked"}, "secrets_encryption_now_epoch": NOW,
            "secrets_encryption_confirm_id": confirm_id, "secrets_encryption_ledger_events": list(events),
            "secrets_encryption_ledger_malformed": ledger_malformed,
            "secrets_encryption_checkpoints_probe": {"content": b64(checkpoints)} if checkpoints else absent(),
            "secrets_encryption_storage": {"k3s01": first, "k3s02": storage(), "k3s03": storage()}}


NOCONF = srv()
IDENT = srv("disabled", "start", dropin=True)
IDENT_NODROP = srv("disabled", "start")
ENAB = srv("enabled", "reencrypt_finished", dropin=True, key_type="XSalsa20-POLY1305")
DISAB = srv("disabled", "reencrypt_finished", dropin=True)

enable_dec = (picks("summarize", P0_TASK)
              + picks("enable", "Decide whether enable is required", "Enforce the enable preconditions", "Require the recorded pre-enable checkpoint"))
D = "secrets_encryption_enable_decision"
EE = "Enforce the enable preconditions"
EP0 = "Require the recorded pre-enable checkpoint"
AFTER_P0 = ("snapshot k3s01",)
plays.append(play("enable: fresh cluster runs", cl(NOCONF, events=AFTER_P0), enable_dec, False, [f"{D} == 'run'", "secrets_encryption_p0.ok | bool"]))
plays.append(play("enable: idempotent after enable (identity configuration on the first server)", cl(IDENT_NODROP, NOCONF, NOCONF, phase="enable"),
                  enable_dec, False, [f"{D} == 'done'"]))
plays.append(play("enable: idempotent after enable and restarts", cl(IDENT, phase="enable"), enable_dec, False, [f"{D} == 'done'"]))
plays.append(play("enable: refused when encryption is already enabled", cl(ENAB, phase="rotate-keys"), enable_dec, EE))
plays.append(play("enable: refused with a drop-in already present", cl(srv(dropin=True)), enable_dec, EE))
plays.append(play("enable: refused with an unexplained identity configuration", cl(IDENT_NODROP, NOCONF, NOCONF), enable_dec, EE))
plays.append(play("enable: refused after a recorded disable", cl(DISAB, phase="disable"), enable_dec, EE))
P0X = f"89000 p0-pre-enable stage3-p0-pre-enable-x 10 {SHA} token=present\n"
for label, kw, checks in (
        ("the newest Stage 3 snapshot is not p0", dict(stage3=[("stage3-p0-pre-enable-x", 89000), ("stage3-baseline-x", 89500)]),
         ["not secrets_encryption_p0.newest_is_p0 | bool"]),
        ("no Stage 3 snapshot exists", dict(stage3=[], checkpoints=""), ["secrets_encryption_p0.newest == ''"]),
        ("p0 has no checkpoint record", dict(checkpoints=""), ["not secrets_encryption_p0.newest_recorded | bool"]),
        ("p0 is recorded under another label", dict(checkpoints=P0X.replace("p0-pre-enable stage3", "baseline stage3")),
         ["not secrets_encryption_p0.newest_recorded | bool"]),
        ("p0's size differs from its record", dict(checkpoints=P0X.replace(" 10 ", " 11 ")), ["not secrets_encryption_p0.newest_recorded | bool"]),
        ("p0 is recorded twice", dict(checkpoints=P0X + P0X), ["not secrets_encryption_p0.newest_recorded | bool"]),
        ("a checkpoint record is malformed", dict(checkpoints=P0X + "garbage\n"), ["secrets_encryption_p0.records_malformed | bool"]),
        ("a checkpoint record lacks the token confirmation", dict(checkpoints=P0X.replace(" token=present", "")),
         ["secrets_encryption_p0.records_malformed | bool"]),
        ("another invocation followed p0", dict(events=("snapshot k3s01", "canary-create-control k3s01")),
         ["not secrets_encryption_p0.last_event_snapshot | bool"]),
        ("a refused enable followed p0", dict(events=("snapshot k3s01", "enable k3s01")), ["not secrets_encryption_p0.last_event_snapshot | bool"]),
        ("the ledger is malformed", dict(events=AFTER_P0, ledger_malformed=True), [])):
    kw = dict({"events": AFTER_P0}, **kw)
    plays.append(play(f"enable: p0 refused when {label}", cl(NOCONF, **kw), enable_dec, EP0, [f"{D} == 'run'"] + checks))
plays.append(play("enable: p0 not required once enable is done", cl(IDENT, phase="enable", checkpoints=""), enable_dec, False, [f"{D} == 'done'"]))

# The record written by snapshot.yml, read back exactly as gather.yml reads it, is an acceptable p0.
cp_dir = tmp_root / "checkpoint-roundtrip"
cp_dir.mkdir()
cp_tasks = (unroot(picks("snapshot", "Record the checkpoint metadata"))
            + [{"name": "read back", "ansible.builtin.slurp": {"src": f"{cp_dir}/checkpoints"}, "register": "secrets_encryption_checkpoints_probe"}]
            + picks("summarize", P0_TASK))
cp_mocks = dict(cl(NOCONF, events=AFTER_P0, stage3=[("stage3-p0-pre-enable-20261026t100000z-k3s01-1", 89000)], checkpoints=""),
                secrets_encryption_snapshot_stat={"stat": {"mtime": 89000.5, "size": 10, "checksum": SHA}},
                secrets_encryption_snapshot_new=["stage3-p0-pre-enable-20261026t100000z-k3s01-1"])
plays.append(play("checkpoint: the record written by the snapshot phase is accepted as p0", cp_mocks, cp_tasks, False,
                  ["secrets_encryption_p0.ok | bool", "secrets_encryption_checkpoint_records | length == 1",
                   f"lookup('ansible.builtin.file', '{cp_dir}/checkpoints') is match('^89000 p0-pre-enable stage3-p0-pre-enable-20261026t100000z-k3s01-1 10 [0-9a-f]{{64}} token=present$')"],
                  extra_vars={"secrets_encryption_state_dir": str(cp_dir), "secrets_encryption_snapshot_checkpoint": "p0-pre-enable"}))


def token_scenario(base, label, path, fail, uid=None):
    tasks = picks("snapshot", "Inspect the server token file without reading it", "Require the server token file for a restorable checkpoint",
                  base=base)
    checks = ["secrets_encryption_token_stat.stat.checksum is not defined", "secrets_encryption_token_stat.stat.mimetype is not defined"]
    return dict(name=f"token check: {label}", mocks={}, tasks=tasks, expect_fail=fail and "Require the server token file for a restorable checkpoint",
                checks=checks, extra_vars={"secrets_encryption_token_file": str(path),
                                           "secrets_encryption_state_owner_uid": UID if uid is None else uid})


tok_dir = tmp_root / "token-stand-in"
tok_dir.mkdir()
(tok_dir / "present").write_text("stand-in\n")
(tok_dir / "empty").write_text("")
os.symlink(tok_dir / "present", tok_dir / "link")
TOKEN_OK = tok_dir / "present"
for label, path, fail, uid in (("a non-empty regular file owned by the state owner passes, by lstat only", TOKEN_OK, False, None),
                               ("a missing file fails", tok_dir / "missing", True, None),
                               ("an empty file fails", tok_dir / "empty", True, None),
                               ("a symbolic link fails", tok_dir / "link", True, None),
                               ("a file owned by another user fails", TOKEN_OK, True, UID + 1)):
    sc = token_scenario(None, label, path, fail, uid)
    plays.append(play(sc["name"], sc["mocks"], sc["tasks"], sc["expect_fail"], sc["checks"], sc["extra_vars"]))

REMOVAL_SUMMARY = "Summarize the drop-in removal round"
round_task = picks("summarize", P0_TASK, "Summarize the enable restart round", REMOVAL_SUMMARY)
restart_pre = round_task + picks("restart", "Enforce the restart preconditions", "Enforce the restart order", "Enforce the enable restart round")
RP_ = "Enforce the restart preconditions"
RO = "Enforce the restart order"
RE = "Enforce the enable restart round"
NOT_YET = srv("disabled", "start", restarted=False, verified=False)
plays.append(play("restart: k3s01 first after enable", cl(NOT_YET, phase="enable"), restart_pre, False))
plays.append(play("restart: refused without a recorded change", cl(NOCONF), restart_pre, RP_))
for st in ("reencrypt_active", "reencrypt_request", "rotate_keys", "prepare", "rotate"):
    plays.append(play(f"restart: impossible while a server is in stage {st}",
                      cl(ENAB, srv("enabled", st, dropin=True, key_type="XSalsa20-POLY1305"), phase="rotate-keys"), restart_pre, RP_))
plays.append(play("restart order: k3s02 refused before k3s01 restarted", cl(NOT_YET, NOT_YET, NOT_YET, phase="enable"), restart_pre, RO, host="k3s02"))
plays.append(play("restart order: k3s02 refused while k3s01 restarted but its post-restart gate is not recorded",
                  cl(srv("disabled", "start", dropin=True, restarted=True, verified=False), NOT_YET, NOT_YET, phase="enable"),
                  restart_pre, RO, host="k3s02"))
plays.append(play("restart order: k3s02 refused while k3s01 lacks the drop-in", cl(srv("disabled", "start", dropin=False), NOT_YET, NOT_YET,
                                                                                    phase="enable"), restart_pre, RO, host="k3s02"))
plays.append(play("restart order: k3s02 allowed after k3s01 reached the checkpoint", cl(IDENT, NOT_YET, NOT_YET, phase="enable"),
                  restart_pre, False, host="k3s02"))
plays.append(play("restart order: k3s03 refused before k3s02 (k3s01 done)", cl(IDENT, NOT_YET, NOT_YET, phase="enable"), restart_pre, RO, host="k3s03"))
plays.append(play("restart order: k3s03 refused while k3s02 is unverified", cl(IDENT, srv("disabled", "start", dropin=True, verified=False), NOT_YET,
                                                                              phase="enable"), restart_pre, RO, host="k3s03"))
plays.append(play("restart order: k3s03 allowed after k3s01 and k3s02", cl(IDENT, IDENT, NOT_YET, phase="enable"), restart_pre, False, host="k3s03"))
plays.append(play("restart order: after rotation k3s02 waits for k3s01 again",
                  cl(srv("enabled", "reencrypt_finished", dropin=True, restarted=False, verified=False, key_type="XSalsa20-POLY1305"),
                     phase="rotate-keys"), restart_pre, RO, host="k3s02"))
plays.append(play("restart: flag removal refused while encryption is enabled", cl(ENAB, phase="rotate-keys"), restart_pre, RP_,
                  extra_vars={"secrets_encryption_flag_state": "absent"}))
plays.append(play("restart: flag removal allowed before rotation (rehearsal state)", cl(IDENT_NODROP, phase="enable"), restart_pre, False,
                  extra_vars={"secrets_encryption_flag_state": "absent"}))
for legacy in ("disable", "reencrypt-after-disable"):
    plays.append(play(f"restart: drop-in removal refused for a legacy {legacy} marker (after activation only a snapshot restore)",
                      cl(DISAB, phase=legacy), restart_pre, RP_, extra_vars={"secrets_encryption_flag_state": "absent"}))
plays.append(play("restart: unknown flag state refused", cl(IDENT, phase="enable"), restart_pre, RP_,
                  extra_vars={"secrets_encryption_flag_state": "maybe"}))
# The enable restart round: status is unavailable until the round completes.
UNAV = srv("unknown", "none", hashes=False, restarted=False, verified=False, parsed=False, unavailable=True)
UNAV_DONE = srv("unknown", "none", hashes=False, restarted=True, verified=True, parsed=False, unavailable=True, dropin=True)
UNAV_RESTARTED = srv("unknown", "none", hashes=False, restarted=True, verified=False, parsed=False, unavailable=True, dropin=True)
STALE = ("snapshot k3s01", "enable k3s01", "rotate-keys k3s01")
for label, mocks, host, fail in (
        ("k3s01 restarts while status is unavailable on every server", cl(UNAV, phase="enable"), "k3s01", False),
        ("k3s02 restarts after k3s01 passed, status still unavailable", cl(UNAV_DONE, UNAV, UNAV, phase="enable"), "k3s02", False),
        ("k3s03 restarts after k3s01 and k3s02, status still unavailable", cl(UNAV_DONE, UNAV_DONE, UNAV, phase="enable"), "k3s03", False),
        ("k3s03 may repeat its own restart that was not yet verified", cl(UNAV_DONE, UNAV_DONE, UNAV_RESTARTED, phase="enable"), "k3s03", False),
        ("refused without the enable marker", cl(UNAV), "k3s01", RP_),
        ("unavailable status refused when the ledger lacks enable", cl(UNAV, phase="enable", events=("snapshot k3s01",)), "k3s01", RP_),
        ("unavailable status refused without a pre-enable checkpoint", cl(UNAV, phase="enable", pre_enable_snapshot=False), "k3s01", RP_),
        ("unavailable status refused for a stale marker", cl(UNAV, phase="enable", events=STALE), "k3s01", RP_),
        ("refused without a pre-enable checkpoint (readable status)", cl(NOT_YET, phase="enable", pre_enable_snapshot=False), "k3s01", RE),
        ("refused when the ledger has no snapshot before enable", cl(NOT_YET, phase="enable", events=("enable k3s01", "snapshot k3s01")), "k3s01", RE),
        ("refused for a stale marker (readable status)", cl(NOT_YET, phase="enable", events=STALE), "k3s01", RE),
        ("refused with a malformed ledger", cl(NOT_YET, phase="enable", ledger_malformed=True), "k3s01", RE),
        ("k3s01 replayed after it passed is refused", cl(IDENT, NOT_YET, NOT_YET, phase="enable"), "k3s01", RE),
        ("k3s01 replayed after the round completed is refused", cl(IDENT, phase="enable"), "k3s01", RE),
        ("k3s03 replayed after the round completed is refused", cl(IDENT, phase="enable"), "k3s03", RE),
        ("k3s01 refused while k3s03 already restarted (out of order)",
         cl(NOT_YET, NOT_YET, srv("disabled", "start", dropin=True, restarted=True, verified=False), phase="enable"), "k3s01", RE),
        ("k3s02 refused while k3s03 carries a drop-in (partial round)",
         cl(IDENT, NOT_YET, srv("disabled", "start", dropin=True, restarted=False, verified=False), phase="enable"), "k3s02", RE),
        ("k3s02 refused before k3s01 restarted (skipped node)", cl(UNAV, phase="enable"), "k3s02", RO),
        ("k3s03 refused before k3s02 restarted (skipped node)", cl(UNAV_DONE, UNAV, UNAV, phase="enable"), "k3s03", RO),
        ("k3s03 refused while k3s02 restarted but is unverified", cl(UNAV_DONE, UNAV_RESTARTED, UNAV, phase="enable"), "k3s03", RO)):
    plays.append(play(f"enable round: {label}", mocks, restart_pre, fail, host=host, extra_vars=RESTART))
plays.append(play("enable round: an unavailable status is not tolerated by the restart after rotate-keys",
                  cl(srv("enabled", "reencrypt_finished", dropin=True, key_type="XSalsa20-POLY1305"), UNAV, UNAV, phase="rotate-keys"),
                  restart_pre, RP_, extra_vars=RESTART))


# ---------------------------------------------------------------- the drop-in removal round
# Three-VM rehearsal, 2026-10-27: after k3s01's drop-in removal it reported
# Disabled without a configuration file, and the preconditions refused k3s02.
# Epochs: enable marker 90000 (cl), enable round 901xx-903xx, removals from 91000.
def rs(enc, stage, dropin, change, start, verified, hashes=None, parsed=True, unavailable=False):
    s = srv(enc, stage, hashes=(enc == "disabled") if hashes is None else hashes, dropin=dropin, parsed=parsed, unavailable=unavailable)
    since = max(90000, change)
    s.update(dropin_change_epoch=change, start_epoch=start, verified_epoch=verified, restarted_since_change=start > since,
             checkpoint_reached=start > since and verified >= start and verified > since)
    return s


K1, K2, K3 = (rs("disabled", "start", True, c, c + 10, c + 50) for c in (90100, 90200, 90300))
R1, R2, R3 = (rs("disabled-no-config", "none", False, c, c + 10, c + 50) for c in (91000, 91100, 91200))
ABSENT_RUN = dict(RESTART, secrets_encryption_flag_state="absent")
REMOVAL_RR = "secrets_encryption_removal_round"
REMOVAL_CASES = {
    "k3s02 after k3s01 completed": (cl(R1, K2, K3, phase="enable"), "k3s02"),
    "earlier server without a recorded gate": (cl(rs("disabled-no-config", "none", False, 91000, 91010, 0), K2, K3, phase="enable"), "k3s02"),
    "earlier server with a gate recorded before its restart":
        (cl(rs("disabled-no-config", "none", False, 91000, 91010, 91005), K2, K3, phase="enable"), "k3s02"),
    "earlier server without a drop-in change record": (cl(rs("disabled-no-config", "none", False, 0, 91010, 91050), K2, K3, phase="enable"), "k3s02"),
    "earlier removal before the enable round completed (another round)":
        (cl(rs("disabled-no-config", "none", False, 90200, 90210, 90250), K2, K3, phase="enable"), "k3s02"),
    "earlier removal from before the enable marker (stale)":
        (cl(rs("disabled-no-config", "none", False, 89000, 89100, 89200), K2, K3, phase="enable"), "k3s02"),
    "k3s02 removed before k3s01's gate passed":
        (cl(R1, rs("disabled-no-config", "none", False, 91040, 91110, 91150), K3, phase="enable"), "k3s03"),
    "earlier no-config server still carrying its drop-in":
        (cl(rs("disabled-no-config", "none", True, 91000, 91010, 91050), K2, K3, phase="enable"), "k3s02"),
    "earlier server with an unparsed status": (cl(rs("disabled-no-config", "none", False, 91000, 91010, 91050, parsed=False), K2, K3,
                                                  phase="enable"), "k3s02"),
    "earlier server reporting Enabled": (cl(rs("enabled", "reencrypt_finished", False, 91000, 91010, 91050, hashes=True), K2, K3,
                                            phase="enable"), "k3s02"),
    "later server without its drop-in": (cl(R1, K2, rs("disabled", "start", False, 90300, 90310, 90350), phase="enable"), "k3s02"),
    "later server with mismatched hashes": (cl(R1, K2, rs("disabled", "start", True, 90300, 90310, 90350, hashes=False), phase="enable"), "k3s02"),
    "later server in stage reencrypt_finished": (cl(R1, K2, rs("disabled", "reencrypt_finished", True, 90300, 90310, 90350), phase="enable"),
                                                 "k3s02"),
    "later server reporting Enabled at stage start": (cl(R1, K2, rs("enabled", "start", True, 90300, 90310, 90350, hashes=True), phase="enable"),
                                                      "k3s02"),
    "later server with an unparsed status": (cl(R1, K2, rs("disabled", "start", True, 90300, 90310, 90350, parsed=False), phase="enable"), "k3s02"),
    "later server restarted after the removal began": (cl(R1, K2, rs("disabled", "start", True, 90300, 91020, 91030), phase="enable"), "k3s02"),
    "target already without configuration": (cl(R1, rs("disabled-no-config", "none", True, 90200, 90210, 90250), K3, phase="enable"), "k3s02"),
    "target with an unavailable status": (cl(R1, rs("unknown", "none", True, 90200, 90210, 90250, parsed=False, unavailable=True), K3,
                                             phase="enable"), "k3s02"),
    "out of order: k3s03 before k3s02": (cl(R1, K2, K3, phase="enable"), "k3s03"),
    "replay: k3s01 again": (cl(R1, K2, K3, phase="enable"), "k3s01"),
    "replay: k3s02 again after its removal": (cl(R1, R2, K3, phase="enable"), "k3s02"),
    "replay: k3s03 after the round completed": (cl(R1, R2, R3, phase="enable"), "k3s03"),
    "after rotate-keys": (cl(R1, K2, K3, phase="rotate-keys"), "k3s02"),
    "with an incomplete enable round": (cl(R1, K2, rs("disabled", "start", True, 90300, 90310, 0), phase="enable"), "k3s02"),
    "with a stale ledger (rotate-keys recorded)": (cl(R1, K2, K3, phase="enable", events=STALE), "k3s02"),
    "with a malformed ledger": (cl(R1, K2, K3, phase="enable", ledger_malformed=True), "k3s02"),
    "without a pre-enable checkpoint": (cl(R1, K2, K3, phase="enable", pre_enable_snapshot=False), "k3s02"),
}


def removal_scenario(base, label, case, fail, extra_vars=ABSENT_RUN, checks=()):
    mocks, host = REMOVAL_CASES[case]
    tasks = (picks("summarize", P0_TASK, "Summarize the enable restart round", REMOVAL_SUMMARY, base=base)
             + picks("restart", RP_, RO, ROUND_ENFORCE, base=base))
    return dict(name=f"removal round: {label}", mocks=mocks, tasks=tasks, expect_fail=fail, checks=list(checks), extra_vars=extra_vars, host=host)


def add_removal(sc):
    plays.append(play(sc["name"], sc["mocks"], sc["tasks"], sc["expect_fail"], sc["checks"], sc["extra_vars"], sc["host"]))


REMOVAL_CASES["k3s01 first, every server configured-disabled"] = (cl(K1, K2, K3, phase="enable"), "k3s01")
REMOVAL_CASES["k3s03 after k3s01 and k3s02 completed"] = (cl(R1, R2, K3, phase="enable"), "k3s03")
REMOVAL_CASES["k3s02 while k3s01 still carries its drop-in"] = (cl(K1, K2, K3, phase="enable"), "k3s02")
for case, fail, checks in (
        ("k3s01 first, every server configured-disabled", False, [f"{REMOVAL_RR}.next == 'k3s01'", f"{REMOVAL_RR}.removed == []", f"{REMOVAL_RR}.consistent | bool",
                                                                 f"not ({REMOVAL_RR}.active | bool)"]),
        ("k3s02 after k3s01 completed", False, [f"{REMOVAL_RR}.next == 'k3s02'", f"{REMOVAL_RR}.removed == ['k3s01']", f"{REMOVAL_RR}.active | bool",
                                                f"{REMOVAL_RR}.consistent | bool", f"{REMOVAL_RR}.problems == ''"]),
        ("k3s03 after k3s01 and k3s02 completed", False, [f"{REMOVAL_RR}.next == 'k3s03'", f"{REMOVAL_RR}.removed == ['k3s01', 'k3s02']"]),
        ("k3s02 while k3s01 still carries its drop-in", RO, [])):
    add_removal(removal_scenario(None, case, case, fail, checks=checks))
for case in [c for c in REMOVAL_CASES if c not in ("k3s01 first, every server configured-disabled", "k3s02 after k3s01 completed",
                                                   "k3s03 after k3s01 and k3s02 completed", "k3s02 while k3s01 still carries its drop-in")]:
    add_removal(removal_scenario(None, f"refused: {case}", case, RP_))
add_removal(removal_scenario(None, "refused: the stuck state with flag_state=present", "k3s02 after k3s01 completed", RP_, extra_vars=RESTART))
add_removal(removal_scenario(None, "refused: the stuck state outside the restart phase", "k3s02 after k3s01 completed", RP_,
                        extra_vars={"secrets_encryption_flag_state": "absent"}))

# ---------------------------------------------------------------- the exclusive enable restart round (gate.yml)
# k3d, 2026-10-24: status became readable and settled on every server after S1
# alone. The durable round state, not status readability, gates every phase.
LOCK_ONLY = "Enforce the exclusive enable restart round"


def add_sc(sc, invert=False, prefix=""):
    plays.append(play(prefix + sc["name"], sc["mocks"], sc["tasks"], sc["expect_fail"], sc["checks"], sc.get("extra_vars"),
                      sc.get("host", "k3s01"), sc.get("setup", ()), invert=invert))


OTHER_PHASES = [("checkpoint snapshot", "snapshot", "present"), ("canary create-control", "canary-create-control", "present"),
                ("canary verify", "canary-verify", "present"), ("canary cleanup", "canary-cleanup", "present"),
                ("rotation", "rotate-keys", "present"), ("a repeated enable", "enable", "present"),
                ("etcdctl installation", "install-etcdctl", "present"), ("drop-in removal", "restart", "absent")]


def lock_scenario(base, label, mocks, phase, fail, flag="present", host="k3s01"):
    tasks = picks("summarize", P0_TASK, "Summarize the enable restart round", base=base) + picks("gate", LOCK_ONLY, base=base)
    return dict(name=f"exclusive round: {label}", mocks=mocks, tasks=tasks, expect_fail=fail and LOCK_ONLY, checks=[], host=host,
                extra_vars={"secrets_encryption_phase": phase, "secrets_encryption_flag_state": flag})


VERIFIED_S3_PENDING = srv("disabled", "start", dropin=True, restarted=True, verified=False)
ROUND_STATES = [("before S1, status unavailable", cl(UNAV, phase="enable"), "k3s01"),
                ("after S1, status readable and settled everywhere", cl(IDENT, NOT_YET, NOT_YET, phase="enable"), "k3s02"),
                ("after S2, status readable and settled everywhere", cl(IDENT, IDENT, NOT_YET, phase="enable"), "k3s03"),
                ("S3 restarted, converged status readable, not yet verified", cl(IDENT, IDENT, VERIFIED_S3_PENDING, phase="enable"), "k3s03"),
                ("S2 restarted but its gate never passed (interrupted)", cl(IDENT, srv("disabled", "start", dropin=True, restarted=True, verified=False),
                                                                          NOT_YET, phase="enable"), "k3s02")]
for state, mocks, nxt in ROUND_STATES:
    for what, phase, flag in OTHER_PHASES:
        add_sc(lock_scenario(None, f"{state}: {what} is refused", mocks, phase, True, flag))
    add_sc(lock_scenario(None, f"{state}: the restart with the drop-in passes the gate", mocks, "restart", False))
    for host in SERVERS:
        tasks = restart_pre + picks("gate", LOCK_ONLY)
        fail = False if host == nxt else (RO if SERVERS.index(host) > SERVERS.index(nxt) else RE)
        plays.append(play(f"exclusive round: {state}: restart {host} {'is the only one allowed' if not fail else 'is refused'}",
                          mocks, tasks, fail, host=host, extra_vars=RESTART))

# Readable, settled, matching status is not completion: the gathered round stays incomplete and the gate refuses.
READABLE3 = [{"rc": 0, "stdout_lines": IDENTITY}] * 3
for label, probes_kw in (
        ("after S1", dict(started=(50000, 30000, 30000), verified=(55000, None, None), dropin=(True, False, False))),
        ("after S2", dict(started=(50000, 50000, 30000), verified=(55000, 55000, None), dropin=(True, True, False))),
        ("after S3's restart before its verified record", dict(started=(50000, 50000, 50000), verified=(55000, 55000, None),
                                                               dropin=(True, True, True)))):
    plays.append(play(f"exclusive round: readable Disabled/start/matching status {label} is healthy but not completion; p1 refused",
                      round_probes(status=READABLE3, **probes_kw), summary_tasks + picks("gate", LOCK_ONLY), LOCK_ONLY,
                      [f"{HP} | length == 0", f"not ({ROUND}.complete | bool)", f"{ROUND}.next != ''"],
                      {"secrets_encryption_phase": "snapshot"}))
plays.append(play("exclusive round: all three durably verified after the converged status: complete, p1 allowed",
                  round_probes(status=READABLE3, started=(50000, 50000, 50000), verified=(55000, 55000, 56000), dropin=(True, True, True)),
                  summary_tasks + picks("gate", LOCK_ONLY), False, [f"{ROUND}.complete | bool", f"{HP} | length == 0"],
                  {"secrets_encryption_phase": "snapshot"}))

# Once complete, the next lifecycle phases are eligible under their normal prerequisites.
for what, phase, flag in OTHER_PHASES:
    add_sc(lock_scenario(None, f"round complete: {what} passes the round gate", cl(IDENT, phase="enable"), phase, False, flag))
add_sc(lock_scenario(None, "round complete: a further restart passes the gate, then restart.yml refuses the replay", cl(IDENT, phase="enable"),
                  "restart", False))
plays.append(play("round complete: rotation preconditions are met", cl(IDENT, phase="enable"),
                  round_task + picks("gate", LOCK_ONLY) + picks("rotate", "Decide the rotation purpose", "Enforce the rotation preconditions"), False,
                  ["secrets_encryption_rotation_purpose == 'enabling'"], {"secrets_encryption_phase": "rotate-keys"}))
for ok_phase in ("snapshot", "canary-verify", "rotate-keys"):
    add_sc(lock_scenario(None, f"after the round (marker rotate-keys): {ok_phase} is not affected by the round gate",
                         cl(ENAB, phase="rotate-keys"), ok_phase, False))

# Interrupted or inconsistent evidence fails closed.
for label, mocks in (("a stale marker (ledger records rotate-keys)", cl(IDENT, phase="enable", events=STALE)),
                     ("a ledger without snapshot before enable", cl(IDENT, phase="enable", events=("enable k3s01", "snapshot k3s01"))),
                     ("a malformed ledger", cl(IDENT, phase="enable", ledger_malformed=True)),
                     ("no pre-enable checkpoint", cl(IDENT, phase="enable", pre_enable_snapshot=False)),
                     ("an interrupted rotation (rotate-keys recorded, marker still enable)",
                      cl(IDENT, phase="enable", events=("snapshot k3s01", "enable k3s01", "snapshot k3s01", "rotate-keys k3s01")))):
    for what, phase in (("checkpoint snapshot", "snapshot"), ("rotation", "rotate-keys"), ("canary verify", "canary-verify")):
        add_sc(lock_scenario(None, f"round complete with {label}: {what} is refused", mocks, phase, True))
    plays.append(play(f"round complete with {label}: no restart is admitted either", mocks, restart_pre + picks("gate", LOCK_ONLY), RE,
                      extra_vars=RESTART))

# Enforced validation follows the same rule.
validate_tasks = [pick("validate", n, tasks=validate_pb[0]["tasks"]) for n in ("Evaluate the expected state", "Enforce the gate and the expected state")]
VAL_ENF = "Enforce the gate and the expected state"


def validate_scenario(tasks, label, mocks, fail, expect=""):
    m = dict(mocks, secrets_encryption_report={"health_problems": []}, secrets_encryption_preservation_problems="",
             secrets_encryption_snapshot_gate={"age_seconds": 60})
    return dict(name=f"validation: {label}", mocks=m, tasks=round_task + tasks, expect_fail=fail and VAL_ENF,
                checks=[f"(secrets_encryption_expectation.enable_round_blocking | bool) == {bool(fail)}"],
                extra_vars={"secrets_encryption_enforce": True, "secrets_encryption_expect": expect})


for state, mocks, _ in ROUND_STATES:
    add_sc(validate_scenario(validate_tasks, f"enforced validation fails {state}", mocks, True))
add_sc(validate_scenario(validate_tasks, "enforced configured-disabled validation passes after the completed round", cl(IDENT, phase="enable"),
                      False, "configured-disabled"))
CD_AFTER = dict(validate_scenario(validate_tasks, "enforced configured-disabled validation fails after activation (Disabled after rotate-keys)",
                                   cl(DISAB, phase="rotate-keys", events=STALE), True, "configured-disabled"),
                checks=["not (secrets_encryption_expectation.met | bool)", "not (secrets_encryption_expectation.enable_round_blocking | bool)"])
add_sc(CD_AFTER)
add_sc(validate_scenario(validate_tasks, "enforced validation fails after a completed round with a stale marker",
                      cl(IDENT, phase="enable", events=STALE), True))

decide = picks("restart", "Decide the restart")
R = "secrets_encryption_restart_required | bool"
plays.append(play("restart decision: idempotent when already restarted and the drop-in is unchanged",
                  dict(cl(IDENT, phase="enable"), secrets_encryption_dropin_changed=False), decide, False, [f"not {R}"]))
plays.append(play("restart decision: restart when the drop-in changed", dict(cl(IDENT, phase="enable"), secrets_encryption_dropin_changed=True),
                  decide, False, [R]))
plays.append(play("restart decision: restart when started before the change",
                  dict(cl(srv("disabled", "start", dropin=True, restarted=False), phase="enable"), secrets_encryption_dropin_changed=False),
                  decide, False, [R]))

rot_pre = round_task + picks("rotate", "Decide the rotation purpose", "Enforce the rotation preconditions")
RPU = "secrets_encryption_rotation_purpose"
ER = "Enforce the rotation preconditions"
REASON = {"secrets_encryption_additional_rotation_reason": "annual rotation per the backup design"}
plays.append(play("rotation: enabling rotation after enable and all verified restarts", cl(IDENT, phase="enable"), rot_pre, False,
                  [f"{RPU} == 'enabling'"]))
plays.append(play("rotation: refused before every server restarted", cl(IDENT, IDENT, srv("disabled", "start", dropin=True, restarted=False),
                                                                       phase="enable"), rot_pre, ER))
plays.append(play("rotation: refused while the last post-restart gate is unrecorded",
                  cl(IDENT, IDENT, srv("disabled", "start", dropin=True, verified=False), phase="enable"), rot_pre, ER))
plays.append(play("rotation: refused while a server lacks the drop-in", cl(IDENT, IDENT, srv("disabled", "start"), phase="enable"), rot_pre, ER))
plays.append(play("rotation: refused before the post-round validation (k3s03 restarted, status still unavailable, not verified)",
                  cl(IDENT, IDENT, UNAV_RESTARTED, phase="enable"), rot_pre, ER))
plays.append(play("rotation: refused while every status is unavailable after the round", cl(UNAV_DONE, phase="enable"), rot_pre, ER))
plays.append(play("rotation: refused with mismatched hashes", cl(IDENT, srv("disabled", "start", dropin=True, hashes=False), phase="enable"),
                  rot_pre, ER))
plays.append(play("rotation: refused without enable", cl(NOCONF), rot_pre, ER))
plays.append(play("rotation: refused during re-encryption", cl(srv("enabled", "reencrypt_active", dropin=True), phase="rotate-keys"), rot_pre, ER))
plays.append(play("rotation: repeating a completed rotation is refused (no reason, no approval)", cl(ENAB, phase="rotate-keys"), rot_pre, ER))
plays.append(play("rotation: an additional rotation with a reason but no approval is refused", cl(ENAB, phase="rotate-keys"), rot_pre, ER,
                  extra_vars=REASON))
plays.append(play("rotation: an additional rotation approved for another confirmation is refused", cl(ENAB, phase="rotate-keys"), rot_pre, ER,
                  extra_vars=dict(REASON, secrets_encryption_additional_rotation_approval="additional-rotation:20261019T080000Z")))
plays.append(play("rotation: a too-short reason is refused", cl(ENAB, phase="rotate-keys"), rot_pre, ER,
                  extra_vars={"secrets_encryption_additional_rotation_reason": "because",
                              "secrets_encryption_additional_rotation_approval": "additional-rotation:20261020T080000Z"}))
plays.append(play("rotation: an additional rotation with a reason and an approval for this confirmation", cl(ENAB, phase="rotate-keys"), rot_pre, False,
                  [f"{RPU} == 'additional'"], dict(REASON, secrets_encryption_additional_rotation_approval="additional-rotation:20261020T080000Z")))
plays.append(play("rotation: refused after a legacy disable marker (rotate-keys is never a plaintext rollback)", cl(DISAB, phase="disable"),
                  rot_pre, ER))
plays.append(play("rotation: refused after a legacy rollback re-encryption marker", cl(DISAB, phase="reencrypt-after-disable"), rot_pre, ER))
plays.append(play("rotation: the enabling rotation is refused without the pre-enable snapshot (the rollback boundary)",
                  cl(IDENT, phase="enable", pre_enable_snapshot=False), rot_pre, ER))
plays.append(play("rotation: the enabling rotation is refused with a stale ledger", cl(IDENT, phase="enable", events=STALE), rot_pre, ER))
plays.append(play("rotation: the enabling rotation is refused with a malformed ledger", cl(IDENT, phase="enable", ledger_malformed=True),
                  rot_pre, ER))

can = picks("canary", "Require a canary action", "Decide the canary preconditions", "Enforce the canary preconditions")
EC = "Enforce the canary preconditions"
for label, mocks, action, fail in (
        ("create-control before enable", cl(NOCONF), "create-control", False),
        ("create-control after enable and restarts", cl(IDENT, phase="enable"), "create-control", False),
        ("create-control refused once encryption is enabled", cl(ENAB, phase="rotate-keys"), "create-control", EC),
        ("verify after rotation and verified restarts", cl(ENAB, phase="rotate-keys"), "verify", False),
        ("verify refused before the restarts", cl(srv("enabled", "reencrypt_finished", dropin=True, restarted=False), phase="rotate-keys"), "verify", EC),
        ("verify refused with mismatched hashes", cl(ENAB, srv("enabled", "reencrypt_finished", dropin=True, hashes=False), phase="rotate-keys"), "verify", EC),
        ("verify refused before encryption", cl(IDENT, phase="enable"), "verify", EC),
        ("cleanup always allowed", cl(srv("enabled", "reencrypt_active")), "cleanup", False),
        ("unknown action refused", cl(NOCONF), "inspect", "Require a canary action")):
    plays.append(play(f"canary preconditions: {label}", mocks, can, fail, extra_vars={"secrets_encryption_canary_action": action}))

# ---------------------------------------------------------------- stubs: k3s, etcdctl
STUB_K3S = r'''#!/usr/bin/env python3
import base64, pathlib, sys
state = pathlib.Path(%(state)r)
state.mkdir(parents=True, exist_ok=True)
a = sys.argv[1:]
with (state / "log").open("a") as f:
    f.write(" ".join(x for x in a if not x.startswith("--from-file")) + "\n")
def opt(prefix):
    return next((x.split("=", 1)[1] for x in a if x.startswith(prefix)), None)
def mode(name, default):
    p = state / name
    return p.read_text().strip() if p.exists() else default
if a[:1] == ["secrets-encrypt"]:
    sys.stderr.write('level=warning msg="Cluster CA certificate is not trusted by the host CA bundle"\n')
    if a[1:] == ["enable"]:
        out, rc = {"ok": ("secrets-encryption enabled\n", 0), "wrong": ("secrets-encryption already enabled\n", 0),
                   "extra": ("secrets-encryption enabled\nreencryption started\n", 0), "empty": ("", 0),
                   "rc1": ("secrets-encryption enabled\n", 1), "fail": ("", 1)}[mode("enable-mode", "ok")]
        sys.stdout.write(out); sys.exit(rc)
    if a[1:] == ["status"]:
        ident = "Encryption Status: Disabled\nCurrent Rotation Stage: start\n"
        m = mode("status-mode", "unavailable")
        if m == "unavailable":
            sys.stderr.write('level=fatal msg="Error: see server log for details: Internal error occurred: secret-encrypt error ID 00459"\n')
            sys.exit(1)
        sys.stdout.write({"identity": ident + "Server Encryption Hashes: All hashes match\n",
                          "identity-extra": ident + "Server Encryption Hashes: All hashes match\nSomething new: value\n",
                          "mismatch": ident + "Server Encryption Hashes: hash does not match between node-sentinel-a and node-sentinel-b\n",
                          "enabled": "Encryption Status: Enabled\nCurrent Rotation Stage: start\nServer Encryption Hashes: All hashes match\n\n"
                                     "Active  Key Type           Name\n------  --------           ----\n *      XSalsa20-POLY1305  k1\n",
                          "noconf": "Encryption Status: Disabled, no configuration file found\n"}[m])
        sys.exit(0)
    sys.exit(2)
if a[:1] != ["kubectl"]:
    sys.exit(2)
verb = a[1]
if verb == "create":
    kind = a[2]
    name = a[4] if kind == "secret" else a[3]
    obj = state / f"{kind}__{name}"
    if obj.exists():
        print("AlreadyExists", file=sys.stderr); sys.exit(1)
    if kind == "secret":
        value = pathlib.Path(opt("--from-file=").split("=", 1)[1]).read_bytes()
        with (state / "seen").open("ab") as f:
            f.write(value + b"\n")
    else:
        value = opt("--from-literal=").split("=", 1)[1].encode()
    obj.write_bytes(value)
    print(f"{kind}/{name}")
elif verb == "get":
    kind, name = a[2], a[3]
    obj = state / f"{kind}__{name}"
    if "--ignore-not-found=true" in a:
        print(f"{kind}/{name}" if obj.exists() else "", end="")
    elif not obj.exists():
        sys.exit(1)
    else:
        value = obj.read_bytes()
        if (state / "corrupt-readback").exists():
            value = b"readback-sentinel"
        sys.stdout.write(base64.b64encode(value).decode())
elif verb == "delete":
    kind, name = a[2], a[3]
    obj = state / f"{kind}__{name}"
    if obj.exists():
        obj.unlink(); print(f'{kind} "{name}" deleted')
elif verb == "label":
    pass
else:
    sys.exit(2)
'''
STUB_ETCDCTL = r'''#!/usr/bin/env python3
import base64, json, pathlib, sys
state = pathlib.Path(%(state)r)
a = sys.argv[1:]
if a[:1] == ["version"]:
    print("etcdctl version: 3.6.14\nAPI version: 3.6"); sys.exit(0)
with (state / "etcdctl-args").open("a") as f:
    f.write(" ".join(a) + "\n")
key = a[-1]
kind = "secret" if key.startswith("/registry/secrets/") else "configmap"
mode_file = state / f"mode_{kind}"
mode = mode_file.read_text().strip() if mode_file.exists() else "plain"
exists = (state / f"{kind}__{key.rsplit('/', 1)[1]}").exists()
def kv(k, v):
    return {"key": base64.b64encode(k.encode()).decode(), "value": base64.b64encode(v).decode(), "mod_revision": 9}
header = {"cluster_id": 1, "member_id": 2, "revision": 9}
enc = b"k8s:enc:secretbox:v1:secretboxkey-2026-10-20T10:15:05Z:" + b"RAWSENTINEL" * 6
out = sys.stdout
if mode == "error":
    print("context deadline exceeded", file=sys.stderr); sys.exit(1)
if not exists or mode == "missing":
    out.write(json.dumps({"header": header}) + "\n"); sys.exit(0)
records = {"enc": [kv(key, enc)], "aescbc": [kv(key, b"k8s:enc:aescbc:v1:aescbckey-1:" + b"RAWSENTINEL" * 6)],
           "short": [kv(key, b"k8s:enc:secretbox:v1:k1:RAWSENTINEL")], "multiple": [kv(key, enc), kv(key + "-x", enc)],
           "wrongkey": [kv(key + "-x", enc)], "plain": [kv(key, b"k8s\x00\x0a\x0dRAWSENTINEL-plaintext")],
           "enc-then-error": [kv(key, enc)], "huge": [kv(key, b"k8s:enc:secretbox:v1:k1:" + b"RAWSENTINEL" * 500000)]}
if mode == "badjson":
    out.write("RAWSENTINEL not json\n"); sys.exit(0)
recs = records[mode]
out.write(json.dumps({"header": header, "kvs": recs, "count": len(recs)}) + "\n")
out.flush()
sys.exit(1 if mode == "enc-then-error" else 0)
'''
LEAKY_VERIFIER = "#!/bin/sh\ncat\n"


def stubs(name):
    d = tmp_root / name
    state = d / "state"
    state.mkdir(parents=True)
    for fname, body in (("k3s", STUB_K3S), ("etcdctl", STUB_ETCDCTL)):
        p = d / fname
        p.write_text(body % {"state": str(state)})
        p.chmod(0o755)
    (d / "leaky-verify").write_text(LEAKY_VERIFIER)
    (d / "leaky-verify").chmod(0o755)
    return {"secrets_encryption_k3s_bin": str(d / "k3s"), "secrets_encryption_etcdctl_path": str(d / "etcdctl"),
            "secrets_encryption_verifier_path": str(role / "files/etcd_value_verify.py"),
            "secrets_encryption_canary_dir": str(d / "canary"), "secrets_encryption_tools_owner": os.environ.get("USER") or os.getlogin(),
            "stub_state": str(state)}


def set_mode(kind, mode):
    return {"name": f"stub mode {kind}={mode}", "ansible.builtin.copy": {"dest": "{{ stub_state }}/mode_" + kind, "content": mode}}


def touch(name):
    return {"name": f"stub flag {name}", "ansible.builtin.copy": {"dest": "{{ stub_state }}/" + name, "content": "1"}}


def obj(kind, name, value="x"):
    return {"name": f"stub object {kind}/{name}", "ansible.builtin.copy": {"dest": "{{ stub_state }}/" + f"{kind}__{name}", "content": value}}


# ---------------------------------------------------------------- raw verification pipeline
raw_tasks = absolutize(copy.deepcopy(task_files["raw_verify"]))
RR = "secrets_encryption_canary_results.raw_t"
PRE_KEY = "/registry/secrets/default/stage3-canary-pre-encryption"
CM_KEY = "/registry/configmaps/default/stage3-canary-plaintext-control"
for label, kind, mode, raw_mode, expected in (
        ("encrypted secretbox record passes", "secret", "enc", "encrypted", "PASS"),
        ("plaintext Secret fails the encrypted check", "secret", "plain", "encrypted", "FAIL-PREFIX"),
        ("aescbc record fails the secretbox check", "secret", "aescbc", "encrypted", "FAIL-PREFIX"),
        ("truncated record fails", "secret", "short", "encrypted", "FAIL-MALFORMED"),
        ("missing key fails", "secret", "missing", "encrypted", "FAIL-MISSING"),
        ("a multi-record (range) response fails", "secret", "multiple", "encrypted", "FAIL-MULTIPLE"),
        ("a response for another key fails", "secret", "wrongkey", "encrypted", "FAIL-KEY"),
        ("non-JSON output fails", "secret", "badjson", "encrypted", "FAIL-JSON"),
        ("etcdctl failure fails", "secret", "error", "encrypted", "FAIL-JSON"),
        ("valid output followed by an etcdctl failure fails", "secret", "enc-then-error", "encrypted", "FAIL-UNEXPECTED"),
        ("oversize response fails", "secret", "huge", "encrypted", "FAIL-OVERSIZE"),
        ("plaintext control passes", "configmap", "plain", "plaintext", "PASS"),
        ("encrypted record fails the plaintext control", "configmap", "enc", "plaintext", "FAIL-ENCRYPTED")):
    sv = stubs(f"raw-{len(plays)}")
    key = PRE_KEY if kind == "secret" else CM_KEY
    plays.append(play(f"raw verify: {label}", {}, raw_tasks, False,
                      [f"{RR} == '{expected}'", f"lookup('ansible.builtin.file', '{sv['stub_state']}/etcdctl-args') is search('get --write-out=json -- {key}$')"],
                      dict(sv, se_raw_key=key, se_raw_mode=raw_mode, se_raw_label="t"),
                      setup=[set_mode(kind, mode), obj(kind, key.rsplit("/", 1)[1])]))
sv = stubs("raw-leaky")
plays.append(play("raw verify: a verifier that echoes the record is reported as FAIL-UNEXPECTED, and hidden", {}, raw_tasks, False,
                  [f"{RR} == 'FAIL-UNEXPECTED'"], dict(sv, secrets_encryption_verifier_path=str(tmp_root / "raw-leaky/leaky-verify"),
                                                       se_raw_key=PRE_KEY, se_raw_mode="encrypted", se_raw_label="t"),
                  setup=[set_mode("secret", "enc"), obj("secret", "stage3-canary-pre-encryption")]))
for label, key, mode in (("a non-canary Secret key", "/registry/secrets/flux-system/flux-system", "encrypted"),
                         ("a key prefix", "/registry/secrets/default/", "encrypted"),
                         ("a whole registry range", "/registry/", "plaintext"),
                         ("an unknown mode", PRE_KEY, "raw")):
    sv = stubs(f"raw-key-{len(plays)}")
    plays.append(play(f"raw verify: refuses {label} before any query", {}, raw_tasks, "Require one of the fixed canary keys",
                      [f"not ('{sv['stub_state']}/etcdctl-args' is exists)"], dict(sv, se_raw_key=key, se_raw_mode=mode, se_raw_label="t")))

# ---------------------------------------------------------------- canary lifecycle
canary_tasks = unroot(absolutize(copy.deepcopy(task_files["canary"])))
CR = "secrets_encryption_canary_results"


def gone(sv):
    return [f"lookup('ansible.builtin.fileglob', '{sv['stub_state']}/secret__*', wantlist=True) | length == 0",
            f"lookup('ansible.builtin.fileglob', '{sv['stub_state']}/configmap__*', wantlist=True) | length == 0",
            f"not ('{sv['secrets_encryption_canary_dir']}' is exists)"]


life = stubs("lifecycle")
raw_on = dict(life, secrets_encryption_raw_verification=True, secrets_encryption_environment="rehearsal")
REQ = "Require every canary check to pass"
plays.append(play("canary: create-control creates the positive controls (raw: plaintext)", cl(NOCONF), canary_tasks, False, [
    f"{CR}.readback_pre == 'PASS'", f"{CR}.raw_pre_plaintext_control == 'PASS'", f"{CR}.raw_configmap_plaintext_control == 'PASS'",
    f"'{life['stub_state']}/secret__stage3-canary-pre-encryption' is exists",
    f"'{life['secrets_encryption_canary_dir']}/pre.value' is exists"],
    dict(raw_on, secrets_encryption_canary_action="create-control"), setup=[set_mode("secret", "plain")]))
plays.append(play("canary: create-control is idempotent", cl(IDENT, phase="enable"), canary_tasks, False, [f"{CR}.readback_pre == 'PASS'"],
                  dict(raw_on, secrets_encryption_canary_action="create-control"), setup=[set_mode("secret", "plain")]))
plays.append(play("canary: verify after rotation passes and cleans up (raw: encrypted, rewritten, control plaintext)",
                  cl(ENAB, phase="rotate-keys"), canary_tasks, False, [
                      f"{CR}.readback_post == 'PASS'", f"{CR}.readback_pre == 'PASS'", f"{CR}.raw_post_encrypted == 'PASS'",
                      f"{CR}.raw_pre_rewritten_encrypted == 'PASS'", f"{CR}.raw_configmap_plaintext_control == 'PASS'"] + gone(life),
                  dict(raw_on, secrets_encryption_canary_action="verify"), setup=[set_mode("secret", "enc")]))
plays.append(play("canary: cleanup after a completed run is a no-op", cl(ENAB), canary_tasks, False, gone(life),
                  dict(life, secrets_encryption_canary_action="cleanup")))
fail_raw = stubs("verify-raw-fail")
plays.append(play("canary: verify fails when the new Secret is stored in plaintext, and still cleans up",
                  cl(ENAB, phase="rotate-keys"), canary_tasks, REQ, gone(fail_raw) + [f"{CR}.raw_post_encrypted == 'FAIL-PREFIX'"],
                  dict(fail_raw, secrets_encryption_raw_verification=True, secrets_encryption_environment="rehearsal",
                       secrets_encryption_canary_action="verify"), setup=[set_mode("secret", "plain")]))
fail_multi = stubs("verify-raw-multiple")
plays.append(play("canary: verify fails on a multi-record etcd response, and still cleans up", cl(ENAB, phase="rotate-keys"), canary_tasks, REQ,
                  gone(fail_multi) + [f"{CR}.raw_post_encrypted == 'FAIL-MULTIPLE'"],
                  dict(fail_multi, secrets_encryption_raw_verification=True, secrets_encryption_environment="rehearsal",
                       secrets_encryption_canary_action="verify"), setup=[set_mode("secret", "multiple")]))
fail_rb = stubs("verify-readback-fail")
plays.append(play("canary: verify fails on a readback mismatch, and still cleans up", cl(ENAB, phase="rotate-keys"), canary_tasks, REQ,
                  gone(fail_rb) + [f"{CR}.readback_post == 'FAIL'"], dict(fail_rb, secrets_encryption_canary_action="verify"),
                  setup=[touch("corrupt-readback")]))
live_v = stubs("verify-live")
plays.append(play("canary: verify without raw verification (live) checks readback only", cl(ENAB, phase="rotate-keys"), canary_tasks, False,
                  [f"{CR}.readback_post == 'PASS'", f"{CR}.raw_post_encrypted is not defined",
                   f"not ('{live_v['stub_state']}/etcdctl-args' is exists)"] + gone(live_v),
                  dict(live_v, secrets_encryption_canary_action="verify")))
intr = stubs("interrupted")
interrupted_setup = [obj("secret", "stage3-canary-pre-encryption"), obj("secret", "stage3-canary-post-encryption"),
                     obj("configmap", "stage3-canary-plaintext-control"),
                     {"name": "leftover canary directory", "ansible.builtin.file": {"path": intr["secrets_encryption_canary_dir"], "state": "directory"}},
                     {"name": "leftover canary value", "ansible.builtin.copy": {"dest": intr["secrets_encryption_canary_dir"] + "/pre.value", "content": "x"}}]
plays.append(play("canary: cleanup after an interrupted run removes every canary and value", cl(ENAB), canary_tasks, False, gone(intr),
                  dict(intr, secrets_encryption_canary_action="cleanup"), setup=interrupted_setup))
plays.append(play("canary: cleanup repeated is a no-op", cl(ENAB), canary_tasks, False, gone(intr),
                  dict(intr, secrets_encryption_canary_action="cleanup")))
lost = stubs("lost-value")
plays.append(play("canary: create-control refuses a canary whose value file is gone, and cleans up", cl(NOCONF), canary_tasks, "Fail after cleanup",
                  gone(lost), dict(lost, secrets_encryption_canary_action="create-control"), setup=[obj("secret", "stage3-canary-pre-encryption")]))
inter_v = stubs("verify-after-interruption")
plays.append(play("canary: verify replaces a post-encryption canary left by an interrupted run", cl(ENAB, phase="rotate-keys"), canary_tasks,
                  False, [f"{CR}.readback_post == 'PASS'"] + gone(inter_v), dict(inter_v, secrets_encryption_canary_action="verify"),
                  setup=[obj("secret", "stage3-canary-post-encryption", "old")]))
notools = stubs("no-tools")
plays.append(play("canary: raw verification refuses a missing etcdctl before creating anything", cl(NOCONF), canary_tasks,
                  "Require the pinned etcdctl and the verifier", gone(notools),
                  dict(notools, secrets_encryption_raw_verification=True, secrets_encryption_environment="rehearsal",
                       secrets_encryption_etcdctl_path=str(tmp_root / "no-tools/missing-etcdctl"),
                       secrets_encryption_canary_action="create-control")))

# ---------------------------------------------------------------- step 1 and the post-round validation, with a stub k3s
# Scenario builders take the task directory (None: the role's own; otherwise a
# mutant copy) so that the same scenario serves as regression test and, with
# the outcome inverted, as the test that kills a mutant.
REQ_ENABLE = "Require the documented enable result"
REQ_ROUND = "Require Disabled, start and matching hashes on every server after the enable restart round"


def stub_file(name, content):
    return {"name": f"stub {name}={content}", "ansible.builtin.copy": {"dest": "{{ stub_state }}/" + name, "content": content}}


def stub_log(sv):
    return f"lookup('ansible.builtin.file', '{sv['stub_state']}/log')"


def enable_scenario(base, label, enable_mode, fail, status_mode="unavailable", mocks=None):
    sv = stubs(f"enable-{len(plays)}")
    sd = pathlib.Path(sv["stub_state"]).parent / "statedir"
    sd.mkdir()
    tasks = unroot(absolutize(load(base / "enable.yml") if base else copy.deepcopy(task_files["enable"]), base))
    checks = [f"('{sd}/last-change' is exists) == {not fail}", f"{stub_log(sv)} is search('secrets-encrypt enable')",
              f"{stub_log(sv)} is not search('secrets-encrypt status')"]
    if not fail:
        checks.append(f"lookup('ansible.builtin.file', '{sd}/last-change') is match('^[0-9]+ enable$')")
    tasks = picks("summarize", P0_TASK, base=base) + tasks
    return dict(name=f"step 1: {label}", mocks=mocks or cl(NOCONF, events=("snapshot k3s01",)), tasks=tasks, expect_fail=fail, checks=checks,
                extra_vars=dict(sv, secrets_encryption_state_dir=str(sd)),
                setup=[stub_file("enable-mode", enable_mode), stub_file("status-mode", status_mode)])


def round_scenario(base, label, status_mode, fail, host="k3s03", phase="enable", reads_status=True):
    sv = stubs(f"round-{len(plays)}")
    sd = pathlib.Path(sv["stub_state"]).parent / "statedir"
    sd.mkdir()
    tasks = unroot([pick("restart", ROUND_CHECK, base=base)]
                   + picks("restart", "Read the time of the passed post-restart gate", "Record the passed post-restart gate", base=base))
    checks = [f"('{sd}/restart-verified' is exists) == {not fail}"]
    checks.append(f"{stub_log(sv)} is search('secrets-encrypt status')" if reads_status else f"not ('{sv['stub_state']}/log' is exists)")
    return dict(name=f"post-round validation: {label}", mocks=cl(IDENT, phase=phase), tasks=tasks, expect_fail=fail, checks=checks, host=host,
                extra_vars=dict(sv, secrets_encryption_state_dir=str(sd), secrets_encryption_ready_retries=2,
                                secrets_encryption_ready_delay_seconds=0), setup=[stub_file("status-mode", status_mode)])


def health_scenario(base, label, mocks, problem, extra_vars):
    tasks = picks("gather", "Reset the parsed status", "Parse the status of each server", "Summarize the gathered state", base=base)
    checks = [f"{HP} | length == 0"] if problem is None else [f"{HP} | select('search', {json.dumps(problem)}) | list | length > 0"]
    return dict(name=f"health: {label}", mocks=mocks, tasks=tasks, expect_fail=False, checks=checks, extra_vars=extra_vars)


def restart_scenario(base, label, mocks, host, fail):
    tasks = (picks("summarize", P0_TASK, "Summarize the enable restart round", REMOVAL_SUMMARY, base=base)
             + picks("restart", "Enforce the restart preconditions", "Enforce the restart order", ROUND_ENFORCE, base=base))
    return dict(name=f"enable round: {label}", mocks=mocks, tasks=tasks, expect_fail=fail, checks=[], extra_vars=RESTART, host=host)


def parse_scenario(base, label, result, unavailable_expected):
    return dict(name=f"parse: {label}", mocks={"secrets_encryption_status_input": result},
                tasks=picks("parse_status", "Parse the secrets-encryption status", base=base), expect_fail=False,
                checks=[f"({P}.unavailable | bool) == {unavailable_expected}", f"not ({P}.parsed | bool)"])


def add(sc, invert=False, prefix=""):
    plays.append(play(prefix + sc["name"], sc["mocks"], sc["tasks"], sc["expect_fail"], sc["checks"], sc.get("extra_vars"),
                      sc.get("host", "k3s01"), sc.get("setup", ()), invert=invert))


for label, mode, fail in (("exit 0 with exactly the documented line records the marker and reads no status", "ok", False),
                          ("an unexpected line is refused and records nothing", "wrong", REQ_ENABLE),
                          ("an extra output line is refused and records nothing", "extra", REQ_ENABLE),
                          ("empty output is refused and records nothing", "empty", REQ_ENABLE),
                          ("the documented line with a non-zero exit is refused and records nothing", "rc1", REQ_ENABLE),
                          ("a failed command is refused and records nothing", "fail", REQ_ENABLE)):
    add(enable_scenario(None, label, mode, fail))
add(enable_scenario(None, "a readable status afterwards is still not read", "ok", False, status_mode="identity"))
NO_P0 = cl(NOCONF, events=("snapshot k3s01",), checkpoints="")
add(dict(enable_scenario(None, "without a recorded p0, enable is not run and nothing is recorded", "ok", "Require the recorded pre-enable checkpoint",
                         mocks=NO_P0), checks=[]))
for label, mode, fail in (("Disabled, start and matching hashes on every server complete the round", "identity", False),
                          ("an unavailable status fails and k3s03 is not recorded as verified", "unavailable", REQ_ROUND),
                          ("mismatched hashes fail", "mismatch", REQ_ROUND),
                          ("Enabled fails", "enabled", REQ_ROUND),
                          ("no configuration fails", "noconf", REQ_ROUND),
                          ("an unrecognized line fails (status must parse)", "identity-extra", REQ_ROUND)):
    add(round_scenario(None, label, mode, fail))
add(round_scenario(None, "k3s01's run does not read status and is recorded", "unavailable", False, host="k3s01", reads_status=False))
add(round_scenario(None, "k3s02's run does not read status and is recorded", "unavailable", False, host="k3s02", reads_status=False))
add(round_scenario(None, "a round after rotate-keys is not validated as the enable round", "unavailable", False, phase="rotate-keys",
                   reads_status=False))

# ---------------------------------------------------------------- mutants
OLD_POST_ENABLE_TEXT = """    - name: Read the first server's status after enable
      ansible.builtin.command:
        argv: ["{{ secrets_encryption_k3s_bin }}", secrets-encrypt, status]
      register: secrets_encryption_after_enable
      changed_when: false
      failed_when: false
      no_log: true

    - name: Parse the status after enable
      ansible.builtin.include_tasks: parse_status.yml
      vars:
        secrets_encryption_status_input: "{{ secrets_encryption_after_enable }}"

    - name: Require an identity configuration without encryption
      ansible.builtin.assert:
        that:
          - secrets_encryption_parsed.parsed | bool
          - secrets_encryption_parsed.encryption == 'disabled'
        quiet: true

"""


def marker_before_check(d):
    p = d / "enable.yml"
    ts = yaml.safe_load(p.read_text())
    b = enable_block_of(ts)
    b[1:4] = [b[2], b[3], b[1]]
    p.write_text(yaml.safe_dump(ts, sort_keys=False, width=200))


def mutant_dir(edits):
    d = tmp_root / f"mutant-{len(plays)}" / "tasks"
    shutil.copytree(role / "tasks", d)
    for edit in edits:
        if callable(edit):
            edit(d)
            continue
        file, old, new = edit
        p = d / f"{file}.yml"
        text = p.read_text()
        assert text.count(old) == 1, (file, old)
        p.write_text(text.replace(old, new))
    return d


SHOW = "    - name: Show the next step after enable\n"
mutants = [
    ("the old post-enable status assertion", [("enable", SHOW, OLD_POST_ENABLE_TEXT + SHOW)],
     lambda b: enable_scenario(b, "exact result, status unavailable", "ok", False)),
    ("the exact enable output no longer required",
     [("enable", "          - secrets_encryption_enable_result.stdout_lines | default([]) == ['secrets-encryption enabled']\n", "")],
     lambda b: enable_scenario(b, "unexpected line", "wrong", REQ_ENABLE)),
    ("the enable exit status no longer required", [("enable", "          - secrets_encryption_enable_result.rc == 0\n", "")],
     lambda b: enable_scenario(b, "non-zero exit", "rc1", REQ_ENABLE)),
    ("the enable marker written before the result check", [marker_before_check],
     lambda b: enable_scenario(b, "failed command", "fail", REQ_ENABLE)),
    ("the tolerance without the round (evaluate.yml)",
     [("evaluate", "se_round.tolerate_unavailable_status | bool and s.status.unavailable", "s.status.unavailable")],
     lambda b: health_scenario(b, "snapshot phase during the round", round_probes(), NOT_PARSED, {"secrets_encryption_phase": "snapshot"})),
    ("the round in any phase", [("summarize", "\n        and (secrets_encryption_phase | default('')) == 'restart'", "")],
     lambda b: health_scenario(b, "rotate-keys phase during the round", round_probes(), NOT_PARSED, {"secrets_encryption_phase": "rotate-keys"})),
    ("the round tolerating out-of-order evidence", [("summarize", "not se_complete | bool and se_out_of_order == ''", "not se_complete | bool")],
     lambda b: health_scenario(b, "k3s03 restarted out of order", round_probes(started=(50000, 30000, 50000), verified=(55000, None, None),
                                                                                dropin=(True, False, False)), NOT_PARSED, RESTART)),
    ("the round without the ledger", [("summarize", "and se_ledger_ok | bool and se_checkpoint_ok | bool", "and se_checkpoint_ok | bool")],
     lambda b: health_scenario(b, "stale marker", round_probes(ledger=LEDGER_OK + "20261023T170000Z rotate-keys k3s01\n"), NOT_PARSED, RESTART)),
    ("the round without the pre-enable checkpoint", [("summarize", "and se_ledger_ok | bool and se_checkpoint_ok | bool", "and se_ledger_ok | bool")],
     lambda b: health_scenario(b, "no pre-enable snapshot", round_probes(snaps=[{"files": [{"path": "/s/stage3-p1-late-k3s01-1", "mtime": 45000,
                                                                                            "size": 10}]}] + PRE_SNAP[1:]), NOT_PARSED, RESTART)),
    ("the round that never completes", [("summarize", 'se_complete: "{{ se_prefix | int == se_servers | length }}"', 'se_complete: "{{ false }}"')],
     lambda b: health_scenario(b, "after the round completed", round_probes(started=(50000, 50000, 50000), verified=(55000, 55000, 55000),
                                                                            dropin=(True, True, True)), NOT_PARSED, RESTART)),
    ("any status failure marked unavailable",
     [("parse_status", "\n        and se_err_lines | select('search', se_unavailable_re) | list | length == 1", "")],
     lambda b: parse_scenario(b, "another server error", unavailable(err=['level=fatal msg="connection refused"']), False)),
    ("the restart preconditions tolerating without the round", [("restart", "se_tolerate | bool and (st.unavailable", "(st.unavailable")],
     lambda b: restart_scenario(b, "ledger lacks enable", cl(UNAV, phase="enable", events=("snapshot k3s01",)), "k3s01", RP_)),
    ("the round without the next-server check", [("restart", "      - inventory_hostname == se_round.next\n", "")],
     lambda b: restart_scenario(b, "k3s01 replayed", cl(IDENT, NOT_YET, NOT_YET, phase="enable"), "k3s01", RE)),
    ("the round without the out-of-order check", [("restart", "      - se_round.out_of_order == ''\n", "")],
     lambda b: restart_scenario(b, "k3s03 restarted first", cl(NOT_YET, NOT_YET, srv("disabled", "start", dropin=True, restarted=True, verified=False),
                                                                  phase="enable"), "k3s01", RE)),
    ("the round without the ledger check", [("restart", "      - se_round.ledger_ok | bool\n", "")],
     lambda b: restart_scenario(b, "stale marker", cl(NOT_YET, phase="enable", events=STALE), "k3s01", RE)),
    ("the round without the checkpoint check", [("restart", "      - se_round.checkpoint_ok | bool\n", "")],
     lambda b: restart_scenario(b, "no pre-enable checkpoint", cl(NOT_YET, phase="enable", pre_enable_snapshot=False), "k3s01", RE)),
    ("the post-round validation skipped",
     [("restart", "    - inventory_hostname == groups['servers'][-1]\n  block:", "    - inventory_hostname == groups['servers'][-1]\n    - false\n  block:")],
     lambda b: round_scenario(b, "unavailable after the round", "unavailable", REQ_ROUND)),
    ("the post-round validation accepting an unparsed status", [("restart", "p.parsed | default(false) | bool and ", "")],
     lambda b: round_scenario(b, "unrecognized line", "identity-extra", REQ_ROUND)),
    ("the post-round validation ignoring hashes", [("restart", " and p.hashes_match | default(false) | bool", "")],
     lambda b: round_scenario(b, "hash mismatch", "mismatch", REQ_ROUND)),
    ("the post-round validation on every server's run", [("restart", "    - inventory_hostname == groups['servers'][-1]\n", "")],
     lambda b: round_scenario(b, "k3s01's run", "unavailable", False, host="k3s01", reads_status=False)),
]
AFTER_S1 = cl(IDENT, NOT_YET, NOT_YET, phase="enable")


def rotation_scenario(base, label, mocks, fail, extra_vars=None):
    tasks = (picks("summarize", P0_TASK, "Summarize the enable restart round", base=base)
             + picks("rotate", "Decide the rotation purpose", "Enforce the rotation preconditions", base=base))
    return dict(name=f"rotation: {label}", mocks=mocks, tasks=tasks, expect_fail=fail, checks=[], extra_vars=extra_vars)


def dropin_removal_scenario(base, label, mocks, fail):
    tasks = (picks("summarize", P0_TASK, "Summarize the enable restart round", REMOVAL_SUMMARY, base=base)
             + picks("restart", "Enforce the restart preconditions", base=base))
    return dict(name=f"drop-in removal: {label}", mocks=mocks, tasks=tasks, expect_fail=fail, checks=[],
                extra_vars={"secrets_encryption_flag_state": "absent"})


APPROVED_EXTRA = dict(REASON, secrets_encryption_additional_rotation_approval="additional-rotation:20261020T080000Z")


mutants += [
    ("the enabling rotation without the pre-enable snapshot",
     [("rotate", "      - >-\n        secrets_encryption_rotation_purpose != 'enabling'\n"
                 "        or (secrets_encryption_enable_round.checkpoint_ok | bool and secrets_encryption_enable_round.ledger_ok | bool)\n", "")],
     lambda b: rotation_scenario(b, "no pre-enable snapshot", cl(IDENT, phase="enable", pre_enable_snapshot=False), ER)),
    ("rotate-keys as a plaintext rollback after disable",
     [("rotate", "      else 'refuse' }}", "      else 'additional' if secrets_encryption_marker.phase == 'disable' else 'refuse' }}")],
     lambda b: rotation_scenario(b, "after a legacy disable marker, even with a reason and an approval", cl(IDENT, phase="disable"), ER,
                                 APPROVED_EXTRA)),
    ("drop-in removal after a rollback re-encryption",
     [("restart", "secrets_encryption_marker.phase == 'enable')", "secrets_encryption_marker.phase in ['enable', 'reencrypt-after-disable'])")],
     lambda b: dropin_removal_scenario(b, "legacy reencrypt-after-disable marker", cl(DISAB, phase="reencrypt-after-disable"), RP_)),
    ("the exclusive round lock disabled", [("gate", "not (se_round.active | bool) or se_round_restart | bool", "true or se_round_restart | bool")],
     lambda b: lock_scenario(b, "after S1 readable: checkpoint snapshot", AFTER_S1, "snapshot", True)),
    ("readable status counted as completion",
     [("gate", "or (se_round.complete | bool and se_round.ledger_ok",
       "or ((se_round.complete | bool or secrets_encryption_servers.values() | map(attribute='status') | selectattr('parsed') | list | length == 3)"
       " and se_round.ledger_ok")],
     lambda b: lock_scenario(b, "after S1 readable: rotation", AFTER_S1, "rotate-keys", True)),
    ("the lock admitting drop-in removal",
     [("gate", "se_round_restart: \"{{ secrets_encryption_phase == 'restart' and secrets_encryption_flag_state == 'present' }}\"",
       "se_round_restart: \"{{ secrets_encryption_phase == 'restart' }}\"")],
     lambda b: lock_scenario(b, "after S1 readable: drop-in removal", AFTER_S1, "restart", True, "absent")),
    ("the lock trusting an inconsistent completed round",
     [("gate", "se_round.complete | bool and se_round.ledger_ok | bool and se_round.checkpoint_ok | bool", "se_round.complete | bool")],
     lambda b: lock_scenario(b, "complete with a stale marker: checkpoint snapshot", cl(IDENT, phase="enable", events=STALE), "snapshot", True)),
    ("the lock lifted once the next server is the last one",
     [("gate", "not (se_round.active | bool) or se_round_restart | bool",
       "not (se_round.active | bool) or se_round_restart | bool or se_round.next == groups['servers'][-1]")],
     lambda b: lock_scenario(b, "after S2 readable: checkpoint snapshot", cl(IDENT, IDENT, NOT_YET, phase="enable"), "snapshot", True)),
]
mutants += [
    ("enable without the p0 requirement",
     [("enable", "      - secrets_encryption_enable_decision == 'done' or secrets_encryption_p0.ok | bool\n", "      - true\n")],
     lambda b: dict(enable_scenario(b, "no recorded p0", "ok", "Require the recorded pre-enable checkpoint", mocks=NO_P0), checks=[])),
    ("p0 without the last-invocation rule",
     [("summarize", "and se_newest_records | length == 1 and se_last_snapshot | bool", "and se_newest_records | length == 1")],
     lambda b: dict(enable_scenario(b, "another invocation after p0", "ok", "Require the recorded pre-enable checkpoint",
                                    mocks=cl(NOCONF, events=("snapshot k3s01", "canary-create-control k3s01"))), checks=[])),
    ("the token inspected with a checksum", [("snapshot", "    get_checksum: false\n    get_mime: false\n", "    get_checksum: true\n    get_mime: false\n")],
     lambda b: token_scenario(b, "checksum", TOKEN_OK, False)),
    ("the token stat following a link", [("snapshot", "    follow: false\n  register: secrets_encryption_token_stat\n",
                                          "    follow: true\n  register: secrets_encryption_token_stat\n")],
     lambda b: token_scenario(b, "link", tok_dir / "link", True)),
    ("the round accepting an unrecorded snapshot",
     [("summarize", "\n             and secrets_encryption_p0.p0_records | select('search', key | regex_escape) | list | length > 0", "")],
     lambda b: health_scenario(b, "p0 not recorded", round_probes(checkpoints=""), NOT_PARSED, RESTART)),
]

# ---------------------------------------------------------------- service probe argv
# The real service-state task runs against a stub systemctl that records its
# argv and answers as systemctl does: one block per named unit, holding only
# the requested properties.
STUB_SYSTEMCTL = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
with open(%(log)r, "a") as f:
    f.write(json.dumps([os.path.basename(sys.argv[0])] + a) + "\n")
props = [p for x in a if x.startswith("--property=") for p in x[len("--property="):].split(",")]
unix = "--timestamp=unix" in a
blocks = []
for unit in [x for x in a[1:] if not x.startswith("-")]:
    k3s = unit == "k3s.service"
    v = {"ActiveState": "active" if k3s else "inactive", "NRestarts": "0",
         "ActiveEnterTimestamp": ("@50000" if unix else "Mon 2026-10-26 01:00:00 UTC") if k3s else ""}
    blocks.append("\n".join(f"{p}={v[p]}" for p in props if p in v))
print("\n\n".join(blocks))
'''


def service_probe_scenario(base, label):
    d = tmp_root / f"systemctl-{len(plays)}"
    d.mkdir()
    log = d / "argv.log"
    (d / "systemctl").write_text(STUB_SYSTEMCTL % {"log": str(log)})
    (d / "systemctl").chmod(0o755)
    probe = pick("gather", "Read the K3s service state on every server", base=base)
    probe["environment"] = {"PATH": f"{d}:" + "{{ lookup('env', 'PATH') }}"}
    return dict(name=f"service probe: {label}", mocks={k: v for k, v in probes().items() if k != "secrets_encryption_service_probe"},
                tasks=[probe] + picks("gather", "Reset the parsed status", "Parse the status of each server", "Summarize the gathered state", base=base),
                expect_fail=False,
                checks=[f"lookup('file', {json.dumps(str(log))}).splitlines() | map('from_json') | list == {json.dumps([SVC_ARGV] * 3)}"]
                + [f"secrets_encryption_servers.{h}.start_epoch == 50000 and secrets_encryption_servers.{h}.nrestarts == 0"
                   f" and secrets_encryption_servers.{h}.active | bool" for h in SERVERS]
                + [f"{HP} | length == 0"])


add(service_probe_scenario(None, "systemctl receives the property list as one argument and every server's start and restart count parse"))
mutants += [
    ("the service probe's property list unquoted", [("gather", SVC_QUOTED, SVC_UNQUOTED)],
     lambda b: service_probe_scenario(b, "property list unquoted")),
]

# ---------------------------------------------------------------- the post-restart restart counters
# Live Stage 3, 2026-10-28: an explicit restart resets systemd's NRestarts. k3s01
# restarted healthy (59 -> 0) and the unchanged-counter rule refused it; every
# rehearsal counter had been 0. The real decision and post-restart assertion run
# with a stand-in for the restart and the gathered state after it.
NR = "Require a healthy cluster and no unplanned restarts"


def counter_scenario(base, label, before, after, fail, host="k3s01", restarted=False, dropin_changed=False):
    """before/after: NRestarts of k3s01..k3s03. restarted: the target already ran with the current configuration."""
    def servers(counts, target_restarted):
        return {h: srv("disabled", "start", dropin=True, nrestarts=n, restarted=target_restarted if h == host else True)
                for h, n in zip(SERVERS, counts)}
    stand_in = {"name": "stand-in for the restart and the state gathered after it",
                "ansible.builtin.set_fact": {"secrets_encryption_servers": servers(after, True)}}
    tasks = (picks("restart", "Record the pre-restart restart counters", "Decide the restart", base=base) + [stand_in]
             + picks("restart", NR, base=base))
    mocks = {"secrets_encryption_servers": servers(before, restarted), "secrets_encryption_dropin_changed": dropin_changed,
             "secrets_encryption_report": {"health_problems": []}}
    checks = [f"(secrets_encryption_restart_required | bool) == {dropin_changed or not restarted}"]
    return dict(name=f"restart counters: {label}", mocks=mocks, tasks=tasks, expect_fail=fail and NR, checks=checks, extra_vars=RESTART,
                host=host)


IDEM = {"restarted": True}
COUNTER_CASES = {
    # A restart by this run: the target's counter is reset to exactly 0, the others are unchanged.
    "a controlled restart resets the target's nonzero counter to 0": ((59, 141, 0), (0, 141, 0), False, {}),
    "a controlled restart with a drop-in change resets the target's counter": ((0, 141, 0), (0, 0, 0), False,
                                                                               {"host": "k3s02", "dropin_changed": True}),
    "a controlled restart of a server whose counter was 0 leaves it 0": ((0, 0, 0), (0, 0, 0), False, {"host": "k3s03"}),
    "another server's counter rising after a controlled restart fails": ((59, 141, 0), (0, 142, 0), True, {}),
    "another server's counter reset after a controlled restart fails": ((59, 141, 0), (0, 0, 0), True, {"host": "k3s02", "dropin_changed": True}),
    "the target's counter above 0 after a controlled restart fails": ((59, 141, 0), (1, 141, 0), True, {}),
    "the target's counter above its earlier value after a controlled restart fails": ((59, 141, 0), (60, 141, 0), True, {}),
    "the target's counter rising from 0 after a controlled restart fails": ((0, 141, 0), (0, 141, 1), True, {"host": "k3s03"}),
    "an unreadable target counter after a controlled restart fails": ((59, 141, 0), (-1, 141, 0), True, {}),
    # No restart by this run (idempotent): every counter is unchanged.
    "an idempotent run with every counter unchanged passes": ((0, 141, 0), (0, 141, 0), False, IDEM),
    "an idempotent run keeps a nonzero target counter": ((5, 141, 0), (5, 141, 0), False, IDEM),
    "an idempotent run with the target's counter rising fails": ((5, 141, 0), (6, 141, 0), True, IDEM),
    "an idempotent run with the target's counter reset fails": ((5, 141, 0), (0, 141, 0), True, IDEM),
    "an idempotent run with another server's counter changed fails": ((0, 141, 0), (0, 142, 0), True, IDEM),
}
for case, (before, after, fail, kw) in COUNTER_CASES.items():
    add(counter_scenario(None, case, before, after, fail, **kw))


def counter_mutant(label, old, new, case):
    before, after, fail, kw = COUNTER_CASES[case]
    return (f"restart counters: {label}", [("restart", old, new)], lambda b: counter_scenario(b, case, before, after, fail, **kw))


RESET = "combine({inventory_hostname: 0})"
mutants += [
    counter_mutant("every counter unchanged after a controlled restart (the live defect)", RESET, "combine({})",
                   "a controlled restart resets the target's nonzero counter to 0"),
    counter_mutant("the target's counter ignored after a controlled restart", RESET, "combine({inventory_hostname: se_after[inventory_hostname]})",
                   "the target's counter above 0 after a controlled restart fails"),
    counter_mutant("the target's counter only required not to rise", RESET,
                   "combine({inventory_hostname: [se_after[inventory_hostname], secrets_encryption_nrestarts_before[inventory_hostname]] | min})",
                   "the target's counter above 0 after a controlled restart fails"),
    counter_mutant("the other servers' counters ignored", "      - se_after == se_expected\n",
                   "      - se_after[inventory_hostname] == se_expected[inventory_hostname]\n",
                   "another server's counter rising after a controlled restart fails"),
    counter_mutant("the other servers' counters ignored (idempotent run)", "      - se_after == se_expected\n",
                   "      - se_after[inventory_hostname] == se_expected[inventory_hostname]\n",
                   "an idempotent run with another server's counter changed fails"),
    counter_mutant("the counter check removed", "      - se_after == se_expected\n", "", "the target's counter above 0 after a controlled restart fails"),
    counter_mutant("the reset expected without a restart", "\n         if secrets_encryption_restart_required | bool else secrets_encryption_nrestarts_before",
                   "", "an idempotent run with the target's counter reset fails"),
    counter_mutant("the counters ignored on an idempotent run", "else secrets_encryption_nrestarts_before }}", "else se_after }}",
                   "an idempotent run with the target's counter rising fails"),
    counter_mutant("the reset expected only without a restart", "if secrets_encryption_restart_required | bool else secrets_encryption_nrestarts_before",
                   "if not (secrets_encryption_restart_required | bool) else secrets_encryption_nrestarts_before",
                   "a controlled restart resets the target's nonzero counter to 0"),
    counter_mutant("the reset expected only after a drop-in change",
                   "if secrets_encryption_restart_required | bool else secrets_encryption_nrestarts_before",
                   "if secrets_encryption_dropin_changed | bool else secrets_encryption_nrestarts_before",
                   "a controlled restart resets the target's nonzero counter to 0"),
]


def rm_mutant(label, file, old, new, case, fail, **kw):
    return (f"removal round: {label}", [(file, old, new)], lambda b: removal_scenario(b, case, case, fail, **kw))


mutants += [
    rm_mutant("a removed server may keep its drop-in", "summarize", "ns.open and not s.dropin_present | bool and ", "ns.open and ",
              "earlier no-config server still carrying its drop-in", RP_),
    rm_mutant("a removed server's status need not parse", "summarize", " and s.status.parsed | bool\n", "\n",
              "earlier server with an unparsed status", RP_),
    rm_mutant("a removed server may report any encryption", "summarize", "             and s.status.encryption == 'disabled-no-config' -%}",
              "             -%}", "earlier server reporting Enabled", RP_),
    rm_mutant("removals need not follow one another", "summarize", "\n             <= secrets_encryption_servers[se_servers[i - 1]].verified_epoch | int",
              " < 0", "k3s02 removed before k3s01's gate passed", RP_),
    rm_mutant("a later server may lack its drop-in", "summarize", "{%- if not (s.dropin_present | bool and s.status.encryption == 'disabled'",
              "{%- if not (s.status.encryption == 'disabled'", "later server without its drop-in", RP_),
    rm_mutant("a later server may report any encryption", "summarize", "s.status.encryption == 'disabled' and s.status.stage == 'start'",
              "s.status.stage == 'start'", "later server reporting Enabled at stage start", RP_),
    rm_mutant("a later server may be in any settled stage", "summarize", " and s.status.stage == 'start'\n", "\n",
              "later server in stage reencrypt_finished", RP_),
    rm_mutant("a later server's hashes need not match", "summarize", "s.status.hashes_match | bool and (n == 0", "(n == 0",
              "later server with mismatched hashes", RP_),
    rm_mutant("a later server may have restarted during the removal round", "summarize", "(n == 0 or s.verified_epoch | int < first)", "true",
              "later server restarted after the removal began", RP_),
    rm_mutant("the first removal judged as if earlier servers were removed", "summarize", "(n == 0 or s.verified_epoch | int < first)",
              "(s.verified_epoch | int < first)", "k3s01 first, every server configured-disabled", False, checks=[f"{REMOVAL_RR}.consistent | bool"]),
    rm_mutant("the removal round without a complete enable round", "summarize", 'se_base: "{{ se_er.complete | bool and ', 'se_base: "{{ ',
              "with an incomplete enable round", RP_),
    rm_mutant("the removal round without a consistent ledger", "summarize", " and se_er.ledger_ok | bool and ", " and ",
              "with a stale ledger (rotate-keys recorded)", RP_),
    rm_mutant("the removal round without the pre-enable checkpoint", "summarize", " and se_er.checkpoint_ok | bool }}", " }}",
              "without a pre-enable checkpoint", RP_),
    rm_mutant("the tolerance with the drop-in requested", "restart", "{{ secrets_encryption_flag_state == 'absent' and (secrets_encryption_phase",
              "{{ (secrets_encryption_phase", "k3s02 after k3s01 completed", RP_, extra_vars=RESTART),
    rm_mutant("the tolerance outside the restart phase", "restart", " and (secrets_encryption_phase | default('')) == 'restart'\n", "\n",
              "k3s02 after k3s01 completed", RP_, extra_vars={"secrets_encryption_flag_state": "absent"}),
    rm_mutant("the tolerance for an inconsistent round", "restart", "and se_removal.consistent | bool and inventory_hostname", "and inventory_hostname",
              "later server without its drop-in", RP_),
    rm_mutant("the tolerance for any server", "restart", " and inventory_hostname == se_removal.next }}", " }}", "replay: k3s01 again", RP_),
    rm_mutant("the tolerance for servers that were not removed", "restart", "{%- elif se_removal_tolerate | bool and h in se_removal.removed -%}",
              "{%- elif se_removal_tolerate | bool -%}", "later server with an unparsed status", RP_),
    rm_mutant("the removal round not admitted", "restart", "        or se_removal_tolerate | bool\n", "", "k3s02 after k3s01 completed", False),
]


def latch_mutant(label, old, new, case):
    return (f"p0 latch: {label}", [("checks", old, new)], lambda b: latch_scenario(b, case, case, case in LATCH_ALLOWED))


mutants += [
    latch_mutant("for any phase", "(secrets_encryption_phase | default('')) == 'restart'\n      and ", "", "enable with a stale p0"),
    latch_mutant("for drop-in removal", "and (secrets_encryption_flag_state | default('present')) == 'present'\n      ", "",
                 "drop-in removal with a stale p0"),
    latch_mutant("without a consistent ledger", "and se_round.ledger_ok | default(false) | bool and ", "and ", "an inconsistent ledger"),
    latch_mutant("without the pre-enable checkpoint", " and se_round.checkpoint_ok | default(false) | bool", "", "no recorded pre-enable checkpoint"),
    latch_mutant("for an out-of-order round", "and se_round.out_of_order | default('unknown') == '' and ", "and ", "an out-of-order round"),
    latch_mutant("for any server", " and inventory_hostname == se_round.next | default('')", "", "a skipped server"),
    latch_mutant("when the newest snapshot is not p0", "and se_p0.newest_is_p0 | default(false) | bool and ", "and ", "a newest snapshot that is not p0"),
    latch_mutant("for an unrecorded p0", " and se_p0.newest_recorded | default(false) | bool", "", "a p0 without a matching record"),
    latch_mutant("with malformed checkpoint records", "      and not (se_p0.records_malformed | default(true) | bool)\n", "",
                 "malformed checkpoint records"),
    latch_mutant("without a snapshot", "and se_newest | int > 0 and se_newest | int < secrets_encryption_marker.epoch | int",
                 "and se_newest | int < secrets_encryption_marker.epoch | int", "no Stage 3 snapshot on the first server"),
    latch_mutant("for a p0 newer than the marker", " and se_newest | int < secrets_encryption_marker.epoch | int }}", " }}",
                 "a p0 newer than the enable marker"),
    latch_mutant("never applied", "        or se_p0_latched | bool }}", "        }}", "the next restart of the round with a stale p0"),
]
# Binding mutants keep the exact play name (the usual "mutant killed:" prefix
# would make every play unmapped), so they run here, inverted, without a prefix.
BIND_MUTANTS = [
    ([("guard", "      - secrets_encryption_phase | default('') == se_expected\n", "")], "restart presented as enable"),
    ([("guard", "      - se_expected in se_allowed\n", "")], "an unmapped play without a phase"),
    ([("guard", "else 'canary-' ~ (secrets_encryption_canary_action | default('unset')))", "else se_allowed[0])")], "canary verify as itself"),
    ([("guard", "secrets_encryption_play_phases[ansible_play_name] | default([]) }}",
       "secrets_encryption_play_phases[ansible_play_name] | default(['restart']) }}")], "an unmapped play"),
]
for label, edits, scenario in mutants:
    add(scenario(mutant_dir(edits)), invert=True, prefix=f"mutant killed: {label}: ")
for edits, case in BIND_MUTANTS:
    sc = bind_scenario(mutant_dir(edits), case)
    plays.append(play(sc["name"], sc["mocks"], sc["tasks"], sc["expect_fail"], sc["checks"], sc["extra_vars"], invert=True))
cd_mutant = copy.deepcopy(validate_tasks)
cd_met = cd_mutant[0]["ansible.builtin.set_fact"]["secrets_encryption_expectation"]
assert len(re.findall(r"\s*and secrets_encryption_marker\.phase == 'enable'\)", cd_met["met"])) == 1
cd_met["met"] = re.sub(r"\s*and secrets_encryption_marker\.phase == 'enable'\)", ")", cd_met["met"])
add(dict(CD_AFTER, tasks=round_task + cd_mutant), invert=True, prefix="mutant killed: configured-disabled accepted after activation: ")
validate_mutant = copy.deepcopy(validate_tasks)
validate_mutant[1]["ansible.builtin.assert"]["that"].remove("not secrets_encryption_expectation.enable_round_blocking | bool")
validate_mutant[0]["ansible.builtin.set_fact"]["secrets_encryption_expectation"]["met"] = \
    validate_mutant[0]["ansible.builtin.set_fact"]["secrets_encryption_expectation"]["met"].replace("not se_round_blocking | bool and (", "(", 1)
add(validate_scenario(validate_mutant, "after S1 readable: enforced validation", AFTER_S1, True), invert=True,
    prefix="mutant killed: validation without the round: ")

# ---------------------------------------------------------------- drop-in idempotence
dropin_copy = unroot(copy.deepcopy(task_files["dropin"]))
for t in dropin_copy:
    if "ansible.builtin.template" in t:
        t["ansible.builtin.template"]["src"] = str(role / "templates/secrets-encryption.yaml.j2")
dropin_file = tmp_root / "dropin-tasks.yml"
dropin_file.write_text(yaml.safe_dump(dropin_copy, sort_keys=False, width=200))
dd = tmp_root / "dropin/config.yaml.d/20-secrets-encryption.yaml"


def dropin_step(state, fact):
    return [{"name": f"drop-in {state}", "ansible.builtin.include_tasks": str(dropin_file), "vars": {"secrets_encryption_dropin_state": state}},
            {"name": f"record {fact}", "ansible.builtin.set_fact": {fact: "{{ secrets_encryption_dropin_changed | bool }}"}}]


plays.append(play("drop-in: install, unchanged rerun, remove, unchanged rerun", {},
                  dropin_step("present", "d1") + [{"name": "read drop-in", "ansible.builtin.slurp": {"src": str(dd)}, "register": "dslurp"},
                                                  {"name": "stat drop-in", "ansible.builtin.stat": {"path": str(dd)}, "register": "dstat"}]
                  + dropin_step("present", "d2") + dropin_step("absent", "d3") + dropin_step("absent", "d4"), False,
                  ["d1 | bool", "not d2 | bool", "d3 | bool", "not d4 | bool", f"not ('{dd}' is exists)", "dstat.stat.mode == '0600'",
                   "(dslurp.content | b64decode).splitlines()[2:] == ['secrets-encryption: true', 'secrets-encryption-provider: secretbox']"],
                  {"secrets_encryption_dropin_path": str(dd)}))
plays.append(play("drop-in: unknown state refused", {}, [{"name": "drop-in", "ansible.builtin.include_tasks": str(dropin_file),
                                                         "vars": {"secrets_encryption_dropin_state": "maybe"}}], "Require a drop-in state",
                  extra_vars={"secrets_encryption_dropin_path": str(dd)}))

# ---------------------------------------------------------------- k3s-server: fresh, existing, replacement, default
# The real stat tasks and the real `when` conditions; only the include target is
# swapped for the unprivileged copy of dropin.yml (include_role would load the
# role's root-owned /etc path).
ks_tasks = [copy.deepcopy(t) for t in k3s_server_tasks if t.get("name") in (
    "Check for an existing k3s binary", "Check for existing k3s data", "Install the secrets-encryption drop-in before K3s first starts")]
ks_tasks[2] = {"name": ks_tasks[2]["name"], "ansible.builtin.include_tasks": str(dropin_file), "vars": ks_tasks[2]["vars"],
               "when": ks_tasks[2]["when"]}
for label, enabled, binary, data, mode, written in (
        ("default (disabled) on a fresh server writes nothing", None, False, False, "init", False),
        ("enabled on a fresh first server writes the drop-in", True, False, False, "init", True),
        ("enabled on a replacement join writes the drop-in", True, False, False, "join", True),
        ("enabled on an installed server (binary present) writes nothing", True, True, False, "join", False),
        ("enabled with existing K3s data writes nothing", True, False, True, "join", False),
        ("disabled on an installed server writes nothing", False, True, True, "init", False)):
    d = tmp_root / f"k3s-server-{len(plays)}"
    d.mkdir()
    if binary:
        (d / "k3s").write_text("binary")
    if data:
        (d / "data").mkdir()
    target = d / "config.yaml.d/20-secrets-encryption.yaml"
    ev = {"k3s_server_binary_path": str(d / "k3s"), "k3s_server_data_dir": str(d / "data"), "k3s_mode": mode,
          "secrets_encryption_dropin_path": str(target), "k3s_secrets_encryption_enabled": False}
    if enabled is not None:
        ev["k3s_secrets_encryption_enabled"] = enabled
    plays.append(play(f"k3s-server: {label}", {}, ks_tasks, False, [f"('{target}' is exists) == {written}"], ev))

# ---------------------------------------------------------------- etcdctl installer: extracted-binary checks and cleanup
etc_checks = [pick("etcdctl", n, etc_block["block"]) for n in (
    "Inspect the extracted etcdctl", "Require the extracted etcdctl to be a regular file",
    "Run the extracted etcdctl from the working directory", "Require the extracted etcdctl to report the pinned version")]
mutation_marker = {"name": "stand-in for the first destination change", "ansible.builtin.set_fact": {"destination_changed": True}}


def etc_play(name, layout, fail_at):
    member = "{{ secrets_encryption_etcdctl_tmp.path }}/extract/etcd-v3.6.14-linux-amd64"
    setup = [{"name": "reset the destination marker", "ansible.builtin.set_fact": {"destination_changed": False}},
             {"name": "create a test working directory", "ansible.builtin.tempfile": {"state": "directory", "prefix": "etcdctl-test."},
              "register": "secrets_encryption_etcdctl_tmp"},
             {"name": "create the test extraction directory", "ansible.builtin.file": {"path": member, "state": "directory", "mode": "0700"}}]
    kind = layout[0]
    if kind in ("script", "symlink"):
        stdout, code, mode = layout[1:] if kind == "script" else ("etcdctl version: 3.6.14", 0, "0755")
        target = f"{member}/etcdctl" if kind == "script" else "{{ secrets_encryption_etcdctl_tmp.path }}/real-etcdctl"
        setup.append({"name": "write a stand-in etcdctl", "ansible.builtin.copy": {
            "dest": target, "mode": mode, "content": f"#!/bin/sh\nprintf '%s\\nAPI version: 3.6\\n' '{stdout}'\nexit {code}\n"}})
        if kind == "symlink":
            setup.append({"name": "link etcdctl to a correct stand-in", "ansible.builtin.file": {"src": target, "dest": f"{member}/etcdctl", "state": "link"}})
    elif kind == "directory":
        setup.append({"name": "put a directory at etcdctl", "ansible.builtin.file": {"path": f"{member}/etcdctl", "state": "directory"}})
    p = play(name, {}, etc_checks + [mutation_marker], fail_at,
             ["not (destination_changed | default(false))" if fail_at else "destination_changed | default(false)"], {}, setup=setup)
    p["tasks"].append({"name": "remove the test working directory", "ansible.builtin.file": {"path": "{{ secrets_encryption_etcdctl_tmp.path }}",
                                                                                           "state": "absent"}})
    return p


REG = "Require the extracted etcdctl to be a regular file"
VER = "Require the extracted etcdctl to report the pinned version"
plays.append(etc_play("etcdctl: a correct extracted binary may be installed", ("script", "etcdctl version: 3.6.14", 0, "0755"), False))
plays.append(etc_play("etcdctl: wrong version is rejected before any destination change", ("script", "etcdctl version: 3.6.13", 0, "0755"), VER))
plays.append(etc_play("etcdctl: pre-release version is rejected", ("script", "etcdctl version: 3.6.14-rc.0", 0, "0755"), VER))
plays.append(etc_play("etcdctl: a symbolic link is rejected even to a correct binary", ("symlink",), REG))
plays.append(etc_play("etcdctl: a directory is rejected", ("directory",), REG))
plays.append(etc_play("etcdctl: a missing binary is rejected", ("missing",), REG))
plays.append(etc_play("etcdctl: a non-executable binary is rejected", ("script", "etcdctl version: 3.6.14", 0, "0644"), VER))
plays.append(etc_play("etcdctl: a binary that exits non-zero is rejected", ("script", "etcdctl version: 3.6.14", 3, "0755"), VER))
etc_always = copy.deepcopy(etc_block["always"])
etc_tmp_tasks = unroot([pick("etcdctl", n, etc_block["block"]) for n in ("Create a private working directory", "Restrict the working directory to root")])
for label, body, fail_at in (("success", etc_tmp_tasks, False),
                             ("a failure", etc_tmp_tasks + [{"name": "simulate a failed download", "ansible.builtin.fail": {"msg": "simulated"}}],
                              "simulate a failed download"),
                             ("a failure before the directory exists", [{"name": "simulate a failed download", "ansible.builtin.fail": {"msg": "simulated"}}],
                              "simulate a failed download")):
    p = play(f"etcdctl: the working directory is removed after {label}", {}, [{"block": body, "always": etc_always}], fail_at,
             ["not (secrets_encryption_etcdctl_tmp.path | default('/nonexistent') is exists)"])
    plays.append(p)

# ====================================================================== run
env = dict(os.environ)
cfg = tmp_root / "ansible.cfg"
cfg.write_text("[defaults]\nretry_files_enabled = False\ninterpreter_python = auto_silent\nhost_key_checking = False\n")
env.update(ANSIBLE_CONFIG=str(cfg), ANSIBLE_ROLES_PATH=str(ans / "roles"), ANSIBLE_NOCOLOR="1")
local = f"\n[servers:vars]\nansible_connection=local\nansible_python_interpreter={sys.executable}\nk3s_version=v1.36.4+k3s1\n"
local_all = f"\n[all:vars]\nansible_connection=local\nansible_python_interpreter={sys.executable}\n"
inv = {}
for name, body in (("live", "[servers]\nk3s01\nk3s02\nk3s03\n"), ("reordered", "[servers]\nk3s02\nk3s01\nk3s03\n"),
                   ("rehearsal", "[servers]\ns3r01\ns3r02\ns3r03\n"), ("mixed", "[servers]\ns3r01\nk3s02\ns3r03\n"),
                   ("other-group", "[servers]\ns3r01\ns3r02\ns3r03\n[monitoring]\nk3s03\n"), ("two", "[servers]\nk3s01\nk3s02\n")):
    p = tmp_root / f"{name}.ini"
    p.write_text(body + local + local_all)
    inv[name] = p

# ---------------------------------------------------------------- syntax
syntax_failures = []
targets = sorted(ans.glob("*.yml"))
for f in sorted((role / "tasks").glob("*.yml")):
    wrapper = tmp_root / f"syntax-{f.stem}.yml"
    wrapper.write_text(yaml.safe_dump([{"name": f"syntax {f.stem}", "hosts": "servers", "gather_facts": False,
                                        "tasks": [{"ansible.builtin.import_tasks": str(f)}]}]))
    targets.append(wrapper)
for t in targets:
    r = subprocess.run(["ansible-playbook", "-i", str(inv["live"]), "--syntax-check", str(t)], env=env, capture_output=True, text=True)
    ok = r.returncode == 0
    print(f"{'PASS' if ok else 'FAIL'}  syntax: {t.name} (exit {r.returncode})", flush=True)
    if not ok:
        syntax_failures.append(t.name)
        print(r.stdout[-1500:], r.stderr[-1500:], sep="\n", flush=True)
if syntax_failures:
    print(f"syntax checks failed: {syntax_failures}", flush=True)
    sys.exit(1)

# ---------------------------------------------------------------- guard
# Refused invocations run the real phase playbook: they must fail inside the
# guard, before the fact-gathering pre-task or any other task. Allowed
# invocations run the real playbook's header and guard, with the setup task and
# the phase tasks replaced by a marker (so nothing escalates locally).
guard_names = {t["name"] for t in task_files["guard"]}
PB_OF = {"snapshot": "snapshot-etcd", "enable": "secrets-encryption-enable", "restart": "secrets-encryption-restart",
         "rotate-keys": "secrets-encryption-rotate", "canary": "secrets-encryption-canary", "install-etcdctl": "install-etcdctl-rehearsal"}
guard_only = {}
for key, pb_name in PB_OF.items():
    p = copy.deepcopy(playbooks[pb_name][0])
    p["pre_tasks"] = [p["pre_tasks"][0]]
    p["tasks"] = [{"name": "guard passed", "ansible.builtin.debug": {"msg": "GUARD-PASSED"}}]
    p["become"] = False
    path = tmp_root / f"guard-only-{pb_name}.yml"
    path.write_text(yaml.safe_dump([p], sort_keys=False, width=200))
    guard_only[key] = path


def C(phase, host, minutes_ago=1):
    return f"{phase}:{host}:{rid(minutes_ago)}"


def rid(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y%m%dT%H%M%SZ")


PROT = {"k3s02": ["/var/lib/rancher/k3s/server/db/etcd-old-example"]}
LIVE = {"secrets_encryption_environment": "live", "secrets_encryption_protected_paths": PROT}
REH = {"secrets_encryption_environment": "rehearsal"}
guard_cases = [
    # (label, playbook key, inventory, limit, extra vars, expected to pass)
    ("enable: exact k3s01 with a fresh confirmation", "enable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), True),
    ("enable: omitted limit", "enable", "live", None, dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: wildcard k3s0*", "enable", "live", "k3s0*", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: wildcard resolving to k3s01 only", "enable", "live", "k3s01*", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: regex resolving to k3s01 only", "enable", "live", "~k3s01$", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: two hosts", "enable", "live", "k3s01,k3s02", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: list ending in a comma", "enable", "live", "k3s01,", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: exclusion pattern", "enable", "live", "servers:!k3s02:!k3s03", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: wrong host", "enable", "live", "k3s02", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s02")), False),
    ("enable: group", "enable", "live", "servers", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: all", "enable", "live", "all", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: k3s01 is not the first server", "enable", "reordered", "k3s01", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: missing confirmation", "enable", "live", "k3s01", LIVE, False),
    ("enable: confirmation for another phase", "enable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("enable: confirmation for another host", "enable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s02")), False),
    ("enable: stale confirmation (45 minutes)", "enable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01", 45)), False),
    ("enable: confirmation from the future", "enable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01", -10)), False),
    ("enable: malformed confirmation time", "enable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm="enable:k3s01:now"), False),
    ("enable: bare phase confirmation", "enable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm="enable"), False),
    ("enable: missing environment", "enable", "live", "k3s01", {"secrets_encryption_confirm": C("enable", "k3s01")}, False),
    ("enable: unknown environment", "enable", "live", "k3s01", {"secrets_encryption_confirm": C("enable", "k3s01"),
                                                                "secrets_encryption_environment": "prod"}, False),
    ("enable: rehearsal declared against the live inventory", "enable", "live", "k3s01", dict(REH, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: live declared against a rehearsal inventory", "enable", "rehearsal", "s3r01", dict(LIVE, secrets_encryption_confirm=C("enable", "s3r01")), False),
    ("enable: rehearsal inventory with a live server name", "enable", "mixed", "s3r01", dict(REH, secrets_encryption_confirm=C("enable", "s3r01")), False),
    ("enable: rehearsal inventory with a live name in another group", "enable", "other-group", "s3r01",
     dict(REH, secrets_encryption_confirm=C("enable", "s3r01")), False),
    ("enable: two-server inventory", "enable", "two", "k3s01", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: rehearsal inventory and environment", "enable", "rehearsal", "s3r01", dict(REH, secrets_encryption_confirm=C("enable", "s3r01")), True),
    ("enable: live without protected Stage 2 artifacts", "enable", "live", "k3s01",
     {"secrets_encryption_environment": "live", "secrets_encryption_confirm": C("enable", "k3s01")}, False),
    ("enable: live with a relative protected path", "enable", "live", "k3s01",
     dict(LIVE, secrets_encryption_protected_paths={"k3s02": ["db/etcd-old"]}, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: live with a protected path for an unknown host", "enable", "live", "k3s01",
     dict(LIVE, secrets_encryption_protected_paths={"other": ["/x"]}, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: live with a relaxed gate value", "enable", "live", "k3s01",
     dict(LIVE, secrets_encryption_min_helmreleases=0, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: rehearsal with relaxed gate values", "enable", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_min_helmreleases=0, secrets_encryption_expected_kustomizations=[], secrets_encryption_confirm=C("enable", "s3r01")), True),
    ("enable: overriding a committed fixed value (provider)", "enable", "live", "k3s01",
     dict(LIVE, secrets_encryption_provider="aescbc", secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("enable: overriding the live host list", "enable", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_live_hosts=["s3r01", "s3r02", "s3r03"], secrets_encryption_environment="live",
          secrets_encryption_confirm=C("enable", "s3r01")), False),
    ("restart: exact k3s02 with its own confirmation", "restart", "live", "k3s02", dict(LIVE, secrets_encryption_confirm=C("restart", "k3s02")), True),
    ("restart: exact k3s03 with its own confirmation", "restart", "live", "k3s03", dict(LIVE, secrets_encryption_confirm=C("restart", "k3s03")), True),
    ("restart: confirmation naming another server", "restart", "live", "k3s02", dict(LIVE, secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("restart: range pattern resolving to one host", "restart", "live", "servers[1]", dict(LIVE, secrets_encryption_confirm=C("restart", "k3s02")), False),
    ("restart: flag removal is rehearsal-approved for live", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_flag_state="absent", secrets_encryption_confirm=C("restart", "k3s01")), True),
    ("restart: flag removal live still needs the protected artifacts", "restart", "live", "k3s01",
     {"secrets_encryption_environment": "live", "secrets_encryption_flag_state": "absent", "secrets_encryption_confirm": C("restart", "k3s01")}, False),
    ("restart: flag removal live still needs an exact single-host limit", "restart", "live", "k3s01,k3s02",
     dict(LIVE, secrets_encryption_flag_state="absent", secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("restart: flag removal allowed in a rehearsal", "restart", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_flag_state="absent", secrets_encryption_confirm=C("restart", "s3r01")), True),
    ("restart: an injected enable restart round is refused", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_enable_round={"tolerate_unavailable_status": True, "next": "k3s01", "ledger_ok": True, "checkpoint_ok": True,
                                                 "out_of_order": "", "complete": False}, secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("restart: an injected enable restart round is refused in a rehearsal too", "restart", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_enable_round={"tolerate_unavailable_status": True}, secrets_encryption_confirm=C("restart", "s3r01")), False),
    ("restart: an injected drop-in removal round is refused in a rehearsal", "restart", "rehearsal", "s3r02",
     dict(REH, secrets_encryption_flag_state="absent", secrets_encryption_removal_round={"consistent": True, "next": "s3r02", "removed": ["s3r01"]},
          secrets_encryption_confirm=C("restart", "s3r02")), False),
    ("restart: injected parsed status is refused", "restart", "live", "k3s02",
     dict(LIVE, secrets_encryption_status_by_server={}, secrets_encryption_confirm=C("restart", "k3s02")), False),
    ("restart: injected ledger events are refused", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_ledger_events=["snapshot k3s01", "enable k3s01"], secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("rotate-keys: injected server state is refused", "rotate-keys", "live", "k3s01",
     dict(LIVE, secrets_encryption_servers={}, secrets_encryption_confirm=C("rotate-keys", "k3s01")), False),
    ("snapshot: an injected health result is refused", "snapshot", "live", "k3s01",
     dict(LIVE, secrets_encryption_health_problems="", secrets_encryption_confirm=C("snapshot", "k3s01")), False),
    ("rotate-keys: fresh confirmation", "rotate-keys", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("rotate-keys", "k3s01")), True),
    ("rotate-keys: stale confirmation", "rotate-keys", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("rotate-keys", "k3s01", 31)), False),
    ("rotate-keys: confirmation for enable", "rotate-keys", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("enable", "k3s01")), False),
    ("canary-verify: live without raw verification", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="verify", secrets_encryption_confirm=C("canary-verify", "k3s01")), True),
    ("canary-verify: confirmation for another action", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="verify", secrets_encryption_confirm=C("canary-cleanup", "k3s01")), False),
    ("canary-verify: raw verification refused in a live environment", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="verify", secrets_encryption_raw_verification=True,
          secrets_encryption_confirm=C("canary-verify", "k3s01")), False),
    ("canary-verify: raw verification refused for the live inventory even when rehearsal is declared", "canary", "live", "k3s01",
     dict(REH, secrets_encryption_canary_action="verify", secrets_encryption_raw_verification=True,
          secrets_encryption_confirm=C("canary-verify", "k3s01")), False),
    ("canary-verify: raw verification refused with a live name in another group", "canary", "other-group", "s3r01",
     dict(REH, secrets_encryption_canary_action="verify", secrets_encryption_raw_verification=True,
          secrets_encryption_confirm=C("canary-verify", "s3r01")), False),
    ("canary-verify: raw verification allowed in a rehearsal", "canary", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_canary_action="verify", secrets_encryption_raw_verification=True,
          secrets_encryption_confirm=C("canary-verify", "s3r01")), True),
    ("install-etcdctl: refused in a live environment", "install-etcdctl", "live", "k3s01",
     dict(LIVE, secrets_encryption_confirm=C("install-etcdctl", "k3s01")), False),
    ("install-etcdctl: refused for the live inventory even when rehearsal is declared", "install-etcdctl", "live", "k3s01",
     dict(REH, secrets_encryption_confirm=C("install-etcdctl", "k3s01")), False),
    ("install-etcdctl: refused for a rehearsal inventory containing a live name", "install-etcdctl", "mixed", "s3r01",
     dict(REH, secrets_encryption_confirm=C("install-etcdctl", "s3r01")), False),
    ("install-etcdctl: refused with an overridden checksum", "install-etcdctl", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_etcdctl_sha256="0" * 64, secrets_encryption_confirm=C("install-etcdctl", "s3r01")), False),
    ("install-etcdctl: refused with an overridden URL", "install-etcdctl", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_etcdctl_url="https://example.invalid/etcd.tar.gz", secrets_encryption_confirm=C("install-etcdctl", "s3r01")), False),
    ("install-etcdctl: allowed in a rehearsal", "install-etcdctl", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_confirm=C("install-etcdctl", "s3r01")), True),
    ("snapshot: exact k3s01", "snapshot", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("snapshot", "k3s01")), True),
    ("restart: another approved path cannot be injected with extra vars", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_flag_state="absent", secrets_encryption_rehearsal_approved_paths=["flag-removal", "reencrypt"],
          secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("restart: the approved paths cannot be emptied with extra vars", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_rehearsal_approved_paths=[], secrets_encryption_confirm=C("restart", "k3s01")), False),
    # Phase binding (live-readiness review, 2026-10-27): -e secrets_encryption_phase=restart cannot disguise another phase.
    ("phase binding: snapshot disguised as restart", "snapshot", "live", "k3s01",
     dict(LIVE, secrets_encryption_phase="restart", secrets_encryption_confirm=C("restart", "k3s01")), False, BIND),
    ("phase binding: enable disguised as restart", "enable", "live", "k3s01",
     dict(LIVE, secrets_encryption_phase="restart", secrets_encryption_confirm=C("restart", "k3s01")), False, BIND),
    ("phase binding: rotate-keys disguised as restart", "rotate-keys", "live", "k3s01",
     dict(LIVE, secrets_encryption_phase="restart", secrets_encryption_confirm=C("restart", "k3s01")), False, BIND),
    ("phase binding: canary create-control disguised as restart", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="create-control", secrets_encryption_phase="restart",
          secrets_encryption_confirm=C("restart", "k3s01")), False, BIND),
    ("phase binding: canary verify disguised as restart", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="verify", secrets_encryption_phase="restart",
          secrets_encryption_confirm=C("restart", "k3s01")), False, BIND),
    ("phase binding: canary cleanup disguised as restart", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="cleanup", secrets_encryption_phase="restart",
          secrets_encryption_confirm=C("restart", "k3s01")), False, BIND),
    ("phase binding: etcdctl installation disguised as restart", "install-etcdctl", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_phase="restart", secrets_encryption_confirm=C("restart", "s3r01")), False, BIND),
    ("phase binding: restart disguised as enable", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_phase="enable", secrets_encryption_confirm=C("enable", "k3s01")), False, BIND),
    ("phase binding: canary verify disguised as cleanup", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="verify", secrets_encryption_phase="canary-cleanup",
          secrets_encryption_confirm=C("canary-cleanup", "k3s01")), False, BIND),
    ("phase binding: a canary action without a committed phase", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="restart", secrets_encryption_confirm=C("canary-restart", "k3s01")), False, BIND),
    ("phase binding: the play name cannot be overridden by extra vars", "restart", "live", "k3s01",
     dict(LIVE, ansible_play_name="Take a Stage 3 on-demand etcd snapshot", secrets_encryption_phase="snapshot",
          secrets_encryption_confirm=C("snapshot", "k3s01")), False, BIND),
    ("phase binding: an injected mapping is refused as a committed value", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="verify", secrets_encryption_phase="restart",
          secrets_encryption_play_phases=dict(role_vars["secrets_encryption_play_phases"], **{"Run the Stage 3 encryption canary": ["restart"]}),
          secrets_encryption_confirm=C("restart", "k3s01")), False, "Require the committed fixed values"),
    ("phase binding: canary cleanup as itself passes", "canary", "live", "k3s01",
     dict(LIVE, secrets_encryption_canary_action="cleanup", secrets_encryption_confirm=C("canary-cleanup", "k3s01")), True),
    ("restart: a reintroduced disable phase cannot be approved by extra vars", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_mutating_phases=["disable"], secrets_encryption_confirm=C("restart", "k3s01")), False),
]
TASK_RE = re.compile(r"^TASK \[(?:[^\]]+? : )?(.+?)\] \*+$", re.MULTILINE)
guard_failures = []
for case in guard_cases:
    label, key, inv_name, limit, extra, expect_pass = case[:6]
    refused_at = case[6] if len(case) > 6 else None  # the guard task that must refuse, where it matters
    book = guard_only[key] if expect_pass else ans / f"{PB_OF[key]}.yml"
    cmd = ["ansible-playbook", "-i", str(inv[inv_name]), str(book), "-e", json.dumps(extra)]
    if limit is not None:
        cmd += ["--limit", limit]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    seen = TASK_RE.findall(r.stdout)
    if expect_pass:
        ok = r.returncode == 0 and "GUARD-PASSED" in r.stdout
    else:
        ok = (r.returncode != 0 and "GUARD-PASSED" not in r.stdout and seen and set(seen) <= guard_names
              and "Gathering Facts" not in r.stdout and ("FAILED!" in r.stdout or re.search(r"^failed: \[", r.stdout, re.MULTILINE))
              and (refused_at is None or seen[-1] == refused_at))
    print(f"{'PASS' if ok else 'FAIL'}  guard: {label} ({'allowed' if expect_pass else 'refused in the guard'}"
          f"{' at ' + repr(refused_at) if refused_at else ''}; exit {r.returncode})", flush=True)
    if not ok:
        guard_failures.append(label)
        print(seen, r.stdout[-2500:], r.stderr[-2500:], sep="\n", flush=True)
if guard_failures:
    print(f"guard checks failed: {guard_failures}", flush=True)
    sys.exit(1)

# ---------------------------------------------------------------- scenarios
playbook = tmp_root / "secrets-encryption-expressions.yml"
playbook.write_text(yaml.safe_dump(plays, sort_keys=False, width=200))
print(f"scenarios: {len(plays)}", flush=True)
result = subprocess.run(["ansible-playbook", "-i", str(inv["live"]), str(playbook)], env=env, capture_output=True, text=True)
output = result.stdout + result.stderr
print(output, flush=True)
recap = re.findall(r"^(\S+)\s+: ok=\d+\s+changed=\d+\s+unreachable=(\d+)\s+failed=(\d+)", result.stdout, re.MULTILINE)
checked = len(re.findall(r"^TASK \[check: ", result.stdout, re.MULTILINE))
print(f"scenario playbook exit {result.returncode}; {checked} of {len(plays)} checks reached; recap {recap}", flush=True)
if result.returncode != 0 or checked != len(plays) or any(u != "0" or f != "0" for _, u, f in recap):
    sys.exit(result.returncode or 1)

# ---------------------------------------------------------------- output scan
seen_values = set()
for f in tmp_root.glob("*/state/seen"):
    seen_values.update(v for v in f.read_bytes().decode().splitlines() if v)
leaks = [s for s in SENTINELS if s in output] + [f"canary value #{i}" for i, v in enumerate(sorted(seen_values)) if v in output]
print(f"{'PASS' if not leaks and seen_values else 'FAIL'}  output: no canary value ({len(seen_values)} generated), raw etcd record, "
      f"readback value, hash-mismatch node name or protected path appears in the output", flush=True)
if leaks or not seen_values:
    print(f"leaked: {leaks}", flush=True)
    sys.exit(1)
sys.exit(0)
