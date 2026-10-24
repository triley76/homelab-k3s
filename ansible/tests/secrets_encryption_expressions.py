"""Structure, expression and safety tests for the Stage 3 secrets-encryption role.

Contacts no cluster node, Kubernetes API, etcd or AWS, and downloads nothing.

1. Structure checks on the role, the phase playbooks, the validation playbook,
   k3s-server and site.yml: targeting, serial and fail-fast settings, the guard
   before facts and privilege escalation, no handlers, a single explicit K3s
   restart, the K3s subcommand each phase may use, the exact etcdctl query,
   the installer's check-before-install order, forbidden commands and paths,
   no_log on every task that can carry a canary value, raw etcd record or
   status output, the pins, and the safe default for fresh builds.
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
    "secrets-encryption-disable": ("disable", "first", "gate.yml", "disable.yml"),
    "secrets-encryption-reencrypt": ("reencrypt-after-disable", "first", "gate.yml", "reencrypt.yml"),
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
require("vars: no procedure path is rehearsal-approved yet", role_vars["secrets_encryption_rehearsal_approved_paths"] == [])
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
require("rotate, disable and reencrypt: snapshot must be newer than the last change",
        sorted(n for n, v in gate_vars.items() if v.get("secrets_encryption_snapshot_after_change") is True)
        == ["secrets-encryption-disable", "secrets-encryption-reencrypt", "secrets-encryption-rotate"])
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
        se_sub == {"status": {"gather", "restart", "rotate", "reencrypt"}, "enable": {"enable"}, "rotate-keys": {"rotate"},
                   "disable": {"disable"}, "reencrypt --force --skip": {"reencrypt"}})
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
        len([1 for _, t in all_role_tasks if needs_no_log(t)]) >= 10 and all(t.get("no_log") is True for _, t in all_role_tasks if needs_no_log(t)))
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
require("disable.yml and reencrypt.yml: preconditions before the command; marked not yet rehearsal-approved",
        order_ok("disable", ["Enforce the disable preconditions", "Run secrets-encrypt disable on the first server", "Record the disable change"])
        and order_ok("reencrypt", ["Enforce the rollback re-encryption preconditions",
                                   "Run secrets-encrypt reencrypt --force --skip on the first server", "Record the rollback re-encryption change"])
        and "Not yet rehearsal-approved" in task_text["disable"] and "Not yet rehearsal-approved" in task_text["reencrypt"])
require("gate.yml: every check before any write",
        order_ok("gate", ["Gather the cluster state", "Evaluate preservation and snapshot freshness", "Enforce the common health gate",
                          "Enforce snapshot and database preservation", "Enforce snapshot freshness", "Refuse a confirmation that was already used",
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
           status_results=None):
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
UNAV3 = [unavailable()] * 3
NOT_PARSED = "secrets-encrypt status not parsed"


def round_probes(started=(30000, 30000, 30000), verified=(None, None, None), dropin=(False, False, False), status=None,
                 ledger=LEDGER_OK, snaps=None, marker="40000 enable", change=None):
    return probes(svc=[{"rc": 0, "stdout": f"NRestarts=0\nActiveState=active\nActiveEnterTimestamp=@{s}"} for s in started],
                  verified=[{"content": b64(str(v))} if v else absent() for v in verified],
                  dropin=[{"stat": {"exists": d, "isreg": d, "islnk": False}} for d in dropin],
                  change=change, status_results=status or UNAV3, ledger=ledger, snaps=snaps or PRE_SNAP, marker=marker)


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
       ledger_malformed=False, pre_enable_snapshot=True):
    first = storage(stage3=[("stage3-p0-pre-enable-x", 89000)] if pre_enable_snapshot else [("stage3-p1-x", 95000)])
    return {"secrets_encryption_servers": {"k3s01": s1, "k3s02": s2 or s1, "k3s03": s3 or s1},
            "secrets_encryption_marker": {"present": phase is not None, "malformed": False, "epoch": epoch if phase else 0, "phase": phase or "none"},
            "secrets_encryption_report": {"encryption": "mocked"}, "secrets_encryption_now_epoch": NOW,
            "secrets_encryption_confirm_id": confirm_id, "secrets_encryption_ledger_events": list(events),
            "secrets_encryption_ledger_malformed": ledger_malformed,
            "secrets_encryption_storage": {"k3s01": first, "k3s02": storage(), "k3s03": storage()}}


NOCONF = srv()
IDENT = srv("disabled", "start", dropin=True)
IDENT_NODROP = srv("disabled", "start")
ENAB = srv("enabled", "reencrypt_finished", dropin=True, key_type="XSalsa20-POLY1305")
DISAB = srv("disabled", "reencrypt_finished", dropin=True)

enable_dec = picks("enable", "Decide whether enable is required", "Enforce the enable preconditions")
D = "secrets_encryption_enable_decision"
EE = "Enforce the enable preconditions"
plays.append(play("enable: fresh cluster runs", cl(NOCONF), enable_dec, False, [f"{D} == 'run'"]))
plays.append(play("enable: idempotent after enable (identity configuration on the first server)", cl(IDENT_NODROP, NOCONF, NOCONF, phase="enable"),
                  enable_dec, False, [f"{D} == 'done'"]))
plays.append(play("enable: idempotent after enable and restarts", cl(IDENT, phase="enable"), enable_dec, False, [f"{D} == 'done'"]))
plays.append(play("enable: refused when encryption is already enabled", cl(ENAB, phase="rotate-keys"), enable_dec, EE))
plays.append(play("enable: refused with a drop-in already present", cl(srv(dropin=True)), enable_dec, EE))
plays.append(play("enable: refused with an unexplained identity configuration", cl(IDENT_NODROP, NOCONF, NOCONF), enable_dec, EE))
plays.append(play("enable: refused after a recorded disable", cl(DISAB, phase="disable"), enable_dec, EE))

round_task = picks("summarize", "Summarize the enable restart round")
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
plays.append(play("restart: flag removal refused after disable until the rollback re-encryption", cl(DISAB, phase="disable"), restart_pre, RP_,
                  extra_vars={"secrets_encryption_flag_state": "absent"}))
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

decide = picks("restart", "Decide the restart")
R = "secrets_encryption_restart_required | bool"
plays.append(play("restart decision: idempotent when already restarted and the drop-in is unchanged",
                  dict(cl(IDENT, phase="enable"), secrets_encryption_dropin_changed=False), decide, False, [f"not {R}"]))
plays.append(play("restart decision: restart when the drop-in changed", dict(cl(IDENT, phase="enable"), secrets_encryption_dropin_changed=True),
                  decide, False, [R]))
plays.append(play("restart decision: restart when started before the change",
                  dict(cl(srv("disabled", "start", dropin=True, restarted=False), phase="enable"), secrets_encryption_dropin_changed=False),
                  decide, False, [R]))

rot_pre = picks("rotate", "Decide the rotation purpose", "Enforce the rotation preconditions")
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
plays.append(play("rotation: refused after disable", cl(DISAB, phase="disable"), rot_pre, ER))

dis = picks("disable", "Decide whether disable is required", "Enforce the disable preconditions")
ED = "Enforce the disable preconditions"
plays.append(play("disable: after a completed rotation and verified restarts", cl(ENAB, phase="rotate-keys"), dis, False,
                  ["secrets_encryption_disable_decision == 'run'"]))
plays.append(play("disable: idempotent after disable", cl(DISAB, ENAB, ENAB, phase="disable"), dis, False,
                  ["secrets_encryption_disable_decision == 'done'"]))
plays.append(play("disable: refused before the restarts after rotation",
                  cl(srv("enabled", "reencrypt_finished", dropin=True, restarted=False), phase="rotate-keys"), dis, ED))
plays.append(play("disable: refused when never enabled", cl(IDENT, phase="enable"), dis, ED))
reenc = picks("reencrypt", "Decide whether the rollback re-encryption is required", "Enforce the rollback re-encryption preconditions")
ERE = "Enforce the rollback re-encryption preconditions"
plays.append(play("rollback re-encryption: after disable and verified restarts", cl(DISAB, phase="disable"), reenc, False,
                  ["secrets_encryption_reencrypt_decision == 'run'"]))
plays.append(play("rollback re-encryption: idempotent afterwards", cl(DISAB, phase="reencrypt-after-disable"), reenc, False,
                  ["secrets_encryption_reencrypt_decision == 'done'"]))
plays.append(play("rollback re-encryption: refused before every server restarted",
                  cl(DISAB, srv("disabled", "reencrypt_finished", dropin=True, restarted=False), phase="disable"), reenc, ERE))
plays.append(play("rollback re-encryption: refused without disable", cl(ENAB, phase="rotate-keys"), reenc, ERE))

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


def enable_scenario(base, label, enable_mode, fail, status_mode="unavailable"):
    sv = stubs(f"enable-{len(plays)}")
    sd = pathlib.Path(sv["stub_state"]).parent / "statedir"
    sd.mkdir()
    tasks = unroot(absolutize(load(base / "enable.yml") if base else copy.deepcopy(task_files["enable"]), base))
    checks = [f"('{sd}/last-change' is exists) == {not fail}", f"{stub_log(sv)} is search('secrets-encrypt enable')",
              f"{stub_log(sv)} is not search('secrets-encrypt status')"]
    if not fail:
        checks.append(f"lookup('ansible.builtin.file', '{sd}/last-change') is match('^[0-9]+ enable$')")
    return dict(name=f"step 1: {label}", mocks=cl(NOCONF), tasks=tasks, expect_fail=fail, checks=checks,
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
    tasks = (picks("summarize", "Summarize the enable restart round", base=base)
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
for label, edits, scenario in mutants:
    add(scenario(mutant_dir(edits)), invert=True, prefix=f"mutant killed: {label}: ")

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
         "rotate-keys": "secrets-encryption-rotate", "canary": "secrets-encryption-canary", "disable": "secrets-encryption-disable",
         "reencrypt-after-disable": "secrets-encryption-reencrypt", "install-etcdctl": "install-etcdctl-rehearsal"}
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
    ("restart: flag removal is not yet rehearsal-approved for live", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_flag_state="absent", secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("restart: flag removal allowed in a rehearsal", "restart", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_flag_state="absent", secrets_encryption_confirm=C("restart", "s3r01")), True),
    ("restart: an injected enable restart round is refused", "restart", "live", "k3s01",
     dict(LIVE, secrets_encryption_enable_round={"tolerate_unavailable_status": True, "next": "k3s01", "ledger_ok": True, "checkpoint_ok": True,
                                                 "out_of_order": "", "complete": False}, secrets_encryption_confirm=C("restart", "k3s01")), False),
    ("restart: an injected enable restart round is refused in a rehearsal too", "restart", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_enable_round={"tolerate_unavailable_status": True}, secrets_encryption_confirm=C("restart", "s3r01")), False),
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
    ("disable: not yet rehearsal-approved for live", "disable", "live", "k3s01", dict(LIVE, secrets_encryption_confirm=C("disable", "k3s01")), False),
    ("disable: approval cannot be injected with extra vars", "disable", "live", "k3s01",
     dict(LIVE, secrets_encryption_rehearsal_approved_paths=["disable"], secrets_encryption_confirm=C("disable", "k3s01")), False),
    ("disable: allowed in a rehearsal", "disable", "rehearsal", "s3r01", dict(REH, secrets_encryption_confirm=C("disable", "s3r01")), True),
    ("reencrypt: not yet rehearsal-approved for live", "reencrypt-after-disable", "live", "k3s01",
     dict(LIVE, secrets_encryption_confirm=C("reencrypt-after-disable", "k3s01")), False),
    ("reencrypt: a disable confirmation is not accepted", "reencrypt-after-disable", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_confirm=C("disable", "s3r01")), False),
    ("reencrypt: allowed in a rehearsal with its own confirmation", "reencrypt-after-disable", "rehearsal", "s3r01",
     dict(REH, secrets_encryption_confirm=C("reencrypt-after-disable", "s3r01")), True),
]
TASK_RE = re.compile(r"^TASK \[(?:[^\]]+? : )?(.+?)\] \*+$", re.MULTILINE)
guard_failures = []
for label, key, inv_name, limit, extra, expect_pass in guard_cases:
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
              and "Gathering Facts" not in r.stdout and ("FAILED!" in r.stdout or re.search(r"^failed: \[", r.stdout, re.MULTILINE)))
    print(f"{'PASS' if ok else 'FAIL'}  guard: {label} ({'allowed' if expect_pass else 'refused in the guard'}; exit {r.returncode})", flush=True)
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
