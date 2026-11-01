"""Structure, unit, behavior and mutation tests for the Stage 4 etcd S3 upload role.

Contacts no cluster node, VM, Kubernetes API, etcd, AWS or home-cluster, and
downloads nothing. Credentials are runtime-built sentinels that match the
committed formats; no literal key-shaped string is in this file.

1. Structure: the committed D1/D4 values; each Stage 4 playbook's play name,
   phase, targeting and fail-fast settings, and the guard first without
   privilege escalation; the D5 Stage 3 gate before every change; credentials
   only from the two environment-named files, with no_log, diff off and no
   backup on every task that reads, validates, holds or writes them; the
   on-demand save always with --name on-demand-s4-<host> and no other
   etcd-snapshot subcommand; no ETag, object metadata, annotation or object
   dump; every name the role sets refused if injected; the fresh-build files
   unchanged; the Stage 3 retention pattern and its baseline filter; the
   documentation statements. Structural mutants must fail these predicates.
2. Unit: the probe's configuration, leak and snapshot logic and its output
   filter; the D6 byte counter and the equality-only comparator.
3. Behavior: the real playbooks run against three local stand-in servers
   (ansible_connection=local, temporary paths, fake k3s, systemctl and
   journalctl) for the success paths and every refusal: output modes,
   credential sources, limits, confirmations, environments, rehearsal
   endpoints, committed-value and reserved-name overrides, overlapping bases,
   the Stage 3 gate, existing Stage 4 names, unsafe drop-ins, other
   configuration sources, a failed save, leaks and integrity expectations.
   Every case checks that no credential or bucket sentinel appears in the
   output, on success and on failure, and that a refused case wrote nothing.

Usage (requires ansible-core and PyYAML, and a tmpfs at /dev/shm or
$XDG_RUNTIME_DIR):
    python3 ansible/tests/etcd_s3_expressions.py
"""
import base64
import copy
import datetime
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import contextlib

import yaml

repo = pathlib.Path(__file__).resolve().parents[2]
ans = repo / "ansible"
role = ans / "roles/etcd-s3"
se_role = ans / "roles/secrets-encryption"
BOOKS = ("configure-etcd-s3.yml", "restart-etcd-s3.yml", "snapshot-etcd-s3.yml", "validate-etcd-s3.yml", "preflight-etcd-s3.yml")
MUTATING = BOOKS[:3]

# Runtime-built sentinels in the committed formats.
KEY_ID = "AKIA" + "S4TESTSENTINEL00"
SECRET = "s4SecretSentinel" + "0" * 24
BUCKET = "home-cluster-backup-" + "s4sentinel01"
SENTINELS = (KEY_ID, SECRET, BUCKET)

failures = []


def check(kind, label, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {kind}: {label}", flush=True)
    if not ok:
        failures.append(f"{kind}: {label}")
        if detail:
            print("   " + detail.replace("\n", "\n   ")[:3000])


def load(p):
    return yaml.safe_load(pathlib.Path(p).read_text())


def tasks_of(name):
    return load(role / "tasks" / name)


role_vars = load(role / "vars/main.yml")
role_defaults = load(role / "defaults/main.yml")
role_task_files = {p.name: load(p) for p in sorted((role / "tasks").glob("*.yml"))}
role_task_texts = {p.name: p.read_text() for p in sorted((role / "tasks").glob("*.yml"))}
books = {b: load(ans / b) for b in BOOKS}
book_texts = {b: (ans / b).read_text() for b in BOOKS}
probe_text = (role / "files/etcd_s3_probe.py").read_text()
se_vars = load(se_role / "vars/main.yml")
se_checks_text = (se_role / "tasks/checks.yml").read_text()
se_gate_text = (se_role / "tasks/gate.yml").read_text()
DOC = (repo / "docs/etcd-s3-uploads.md").read_text()
SE_DOC = (repo / "docs/secrets-encryption.md").read_text()
README = (repo / "README.md").read_text()
FRESH_FILES = ["site.yml", "init-first-server.yml", "join-servers.yml", "group_vars/servers.yml"] + [
    str(p.relative_to(ans)) for p in sorted((ans / "roles/k3s-server").rglob("*")) if p.is_file()]
fresh_texts = {f: (ans / f).read_text() for f in FRESH_FILES}


def module_of(t):
    keys = [k for k in t if k.startswith("ansible.builtin.")]
    return keys[0] if keys else None


def walk(tasks):
    for t in tasks or []:
        yield t
        for k in ("block", "rescue", "always"):
            yield from walk(t.get(k))


def all_role_tasks(files):
    for name, tasks in files.items():
        for t in walk(tasks):
            yield name, t


# ====================================================================== structure predicates
D1_D4 = {
    "etcd_s3_supported_k3s_version": "v1.36.4+k3s1",
    "etcd_s3_dropin_path": "/etc/rancher/k3s/config.yaml.d/30-etcd-s3.yaml",
    "etcd_s3_scheduled_base_prefix": "etcd-snapshot-s4-",
    "etcd_s3_ondemand_base_prefix": "on-demand-s4-",
    "etcd_s3_snapshot_retention": 5,
    "etcd_s3_s3_retention": 5,
    "etcd_s3_folder": "etcd",
    "etcd_s3_schedule_cron": "0 */12 * * *",
    "etcd_s3_compress": False,
    "etcd_s3_region": "us-east-1",
    "etcd_s3_endpoint": "s3.amazonaws.com",
    "etcd_s3_bucket_lookup_type": "auto",
    "etcd_s3_timeout": "5m0s",
    "etcd_s3_live_hosts": ["k3s01", "k3s02", "k3s03"],
    "etcd_s3_integrity_approved_methods": [],
    "etcd_s3_owner_uid": 0,
}


def committed_values_ok(v):
    return all(k in v and v[k] == val and type(v[k]) is type(val) for k, val in D1_D4.items())


def play_phase_ok(bks, v):
    for b in BOOKS:
        plays = bks[b]
        if len(plays) != 1:
            return False
        p = plays[0]
        phase = v["etcd_s3_play_phases"].get(p.get("name"))
        if phase is None or p.get("vars", {}).get("etcd_s3_phase") != phase or p.get("hosts") != "servers":
            return False
        if p.get("gather_facts") is not False or p.get("become") is not True:
            return False
        pre = p.get("pre_tasks") or []
        g = pre[0] if pre else {}
        if module_of(g) != "ansible.builtin.import_role" or g[module_of(g)] != {"name": "etcd-s3", "tasks_from": "guard.yml"} or g.get("become") is not False:
            return False
        mutating = phase in v["etcd_s3_mutating_phases"]
        if mutating != (b in MUTATING):
            return False
        if mutating and (p.get("serial") != 1 or p.get("any_errors_fatal") is not True or p.get("max_fail_percentage") != 0):
            return False
        froms = [t[module_of(t)].get("tasks_from") for t in pre + (p.get("tasks") or []) if module_of(t) in ("ansible.builtin.import_role", "ansible.builtin.include_role")]
        if mutating:
            # D5 directly after the guard; credentials only in configure, right after D5.
            if len(pre) < 2 or pre[1][module_of(pre[1])].get("tasks_from") != "stage3.yml" or pre[1].get("become") is not False:
                return False
            if ("credentials.yml" in froms) != (phase == "configure"):
                return False
            if froms.count("ledger.yml") != 1:
                return False
            # The ledger is consumed after every check and before any change.
            change = {"configure": "dropin.yml", "restart": "restart.yml", "snapshot": "ondemand.yml"}[phase]
            if not (froms.index("config_check.yml") < froms.index("ledger.yml") < froms.index(change)) or "leaks.yml" not in froms[froms.index(change):]:
                return False
            if phase == "configure" and froms.index("credentials.yml") != 2:
                return False
        else:
            if set(froms) & {"stage3.yml", "credentials.yml", "ledger.yml", "dropin.yml", "ondemand.yml", "restart.yml"}:
                return False
        if any(module_of(t) not in ("ansible.builtin.import_role", "ansible.builtin.include_role", "ansible.builtin.debug", "ansible.builtin.assert") for t in p.get("tasks") or []):
            return False
    return True


# Names that hold a credential, the bucket or raw output that may contain them.
CRED_VALUE_REFS = ("etcd_s3_credentials", "etcd_s3_source_content", "etcd_s3_sources", "etcd_s3_probe_raw")
OUTPUT_REGISTERS = ("etcd_s3_source_content", "etcd_s3_probe_raw", "etcd_s3_save", "etcd_s3_restart", "etcd_s3_dropin_write",
                    "etcd_s3_dropin_after")


def task_text(t):
    return json.dumps(t, sort_keys=True)


def credential_hygiene_ok(files):
    """Every task that reads, validates, holds or writes a credential (all of credentials.yml, the probe, the drop-in
    write, the save and the restart, and anything referring to their values) has no_log, diff off and no backup."""
    for name, t in all_role_tasks(files):
        text = task_text(t)
        mod = module_of(t)
        if mod in ("ansible.builtin.template", "ansible.builtin.blockinfile", "ansible.builtin.replace"):
            return False
        if mod in ("ansible.builtin.copy", "ansible.builtin.lineinfile") and t[mod].get("backup") is not False:
            return False
        if mod == "ansible.builtin.debug" and any(r in text for r in CRED_VALUE_REFS + OUTPUT_REGISTERS):
            return False
        sensitive = (name == "credentials.yml" or mod == "ansible.builtin.script" or t.get("register") in OUTPUT_REGISTERS
                     or any(r in text for r in CRED_VALUE_REFS))
        if sensitive and (t.get("no_log") is not True or t.get("diff") is not False):
            return False
    return True


ENV_ALLOWED = {"etcd_s3_key_file_env", "etcd_s3_bucket_file_env", "'ANSIBLE_DEBUG'", "'ANSIBLE_KEEP_REMOTE_FILES'", "'ANSIBLE_LOG_PATH'"}


def sources_ok(texts, bks_texts):
    allt = "\n".join(list(texts.values()) + list(bks_texts.values()))
    envs = set(re.findall(r"lookup\('ansible\.builtin\.env', ([^)]+)\)", allt))
    files = set(re.findall(r"lookup\('ansible\.builtin\.file', ([^)]+)\)", allt))
    other = re.findall(r"lookup\('(?!ansible\.builtin\.(?:env|file|vars)')", allt) + re.findall(r"query\('(?!ansible\.builtin\.(?:varnames|config)')", allt)
    slurps = [t for n, t in all_role_tasks({k: yaml.safe_load(v) for k, v in texts.items()}) if module_of(t) == "ansible.builtin.slurp"]
    cred_slurps = [t for t in slurps if "etcd_s3_sources" in task_text(t)]
    return (envs == ENV_ALLOWED and files <= {"role_path ~ '/vars/main.yml'", "role_path ~ '/defaults/main.yml'"} and not other
            and len(cred_slurps) == 1 and cred_slurps[0].get("delegate_to") == "localhost" and cred_slurps[0].get("become") is False
            and "lookup('ansible.builtin.pipe'" not in allt and "etcd_s3_access_key:" not in allt and "etcd_s3_secret_key:" not in allt)


def save_argv_ok(files, bks_texts, v_text):
    saves = [t for n, t in all_role_tasks(files) if "etcd-snapshot" in task_text(t) and module_of(t) == "ansible.builtin.command"]
    ok = (len(saves) == 1 and saves[0]["ansible.builtin.command"].get("argv") == ["{{ etcd_s3_k3s_bin }}", "etcd-snapshot", "save", "--name", "{{ etcd_s3_ondemand_name }}"]
          and saves[0].get("no_log") is True)
    values = files["values.yml"][0]["ansible.builtin.set_fact"]
    ok = ok and values.get("etcd_s3_ondemand_name") == "{{ etcd_s3_ondemand_base_prefix ~ inventory_hostname }}"
    allt = "\n".join([json.dumps(v) for v in files.values()] + list(bks_texts.values()))
    return ok and not re.search(r"etcd-snapshot[\s,'\"\]]*(delete|prune)", allt)


FORBIDDEN_OUTPUT = (r"(?i)etag", r"x-amz-meta", r"head-object", r"-o yaml\b", r"-o json\b", r"--output=json\b", r"--output=yaml\b",
                    r"(?i)annotations", r"get-object")


def output_safety_ok(texts, bks_texts, probe):
    allt = "\n".join(list(texts.values()) + list(bks_texts.values()))
    # Comments may explain what is never read; the refusal and report texts may name the ETag rule.
    allt = re.sub(r"(?m)^\s*#.*$", "", allt)
    allt = re.sub(r"(?i)an ETag is not an integrity check", "", allt)
    if any(re.search(p, allt) for p in FORBIDDEN_OUTPUT):
        return False
    prints = re.findall(r"print\((.*)\)", probe)
    return (prints == ['json.dumps({"probe_error": True})', "json.dumps(result, sort_keys=True)"]
            and "result = checked(modes[a.mode](a, exp))" in probe and not re.search(r"(?i)etag|x-amz|annotation", probe))


def reserved_ok(files, v, defaults):
    names = set()
    for _, t in all_role_tasks(files):
        if t.get("register"):
            names.add(t["register"])
        sf = t.get("ansible.builtin.set_fact")
        if sf:
            names |= set(sf)
        names |= {k for k in (t.get("vars") or {})}
    known = set(v) | set(defaults) | {"etcd_s3_phase", "etcd_s3_environment", "etcd_s3_confirm"}
    guard = files["guard.yml"]
    unknown = next((t for t in guard if t.get("name") == "Refuse unknown Stage 4 variables"), None)
    reserved = next((t for t in guard if t.get("name") == "Refuse reserved variables from the command line or inventory"), None)
    names_ok = all((n.startswith("etcd_s3_") and n not in known) or n.startswith("es_") for n in names)
    if unknown is None or reserved is None or not names_ok:
        return False
    that = " ".join(unknown["ansible.builtin.assert"]["that"])
    order = [t.get("name") for t in guard]
    return ("query('ansible.builtin.varnames', '^etcd_s3_')" in that and "query('ansible.builtin.varnames', '^es_') | length == 0" in that
            and order[0] == "Bind the phase to the running play" and order.index("Refuse unknown Stage 4 variables") < order.index("Evaluate the phase confirmation")
            and order.index("Refuse reserved variables from the command line or inventory") < order.index("Evaluate the phase confirmation")
            and {"etcd_s3_access_key", "etcd_s3_secret_key", "etcd_s3_bucket", "etcd_s3_credentials", "etcd_s3_ondemand_name"} <= set(v["etcd_s3_reserved_vars"]))


def guard_modes_ok(files, v):
    g = files["guard.yml"]
    modes = next((t for t in g if t.get("name") == "Refuse output modes that could expose credentials"), None)
    cfg = next((t for t in g if t.get("name") == "Refuse configuration that displays or keeps task data"), None)
    if modes is None or cfg is None:
        return False
    that = modes["ansible.builtin.assert"]["that"]
    need = ["ansible_verbosity | int == 0", "not ansible_check_mode", "not ansible_diff_mode", "lookup('ansible.builtin.env', 'ANSIBLE_DEBUG') == ''",
            "lookup('ansible.builtin.env', 'ANSIBLE_KEEP_REMOTE_FILES') == ''", "lookup('ansible.builtin.env', 'ANSIBLE_LOG_PATH') == ''",
            "query('ansible.builtin.config', 'DEFAULT_LOG_PATH') | first in [none, '']",
            "query('ansible.builtin.config', 'DEFAULT_STDOUT_CALLBACK') | first == 'default'",
            "query('ansible.builtin.config', 'CALLBACKS_ENABLED') | first | length == 0"]
    return (all(n in that for n in need) and v["etcd_s3_refused_config"] == ["DEFAULT_DEBUG", "DEFAULT_KEEP_REMOTE_FILES", "DISPLAY_ARGS_TO_STDOUT"]
            and cfg["ansible.builtin.assert"]["that"] == ["not (query('ansible.builtin.config', item) | first | bool)"]
            and cfg.get("loop") == "{{ etcd_s3_refused_config }}")


def fresh_unchanged_ok(texts):
    return not any(re.search(r"etcd-s3|etcd_s3|30-etcd-s3|etcd-snapshot|on-demand-s4", t) for t in texts.values())


STAGE3_PATTERN = "^(etcd-snapshot-|on-demand-s4-)"


def stage3_pattern_ok(sev, checks_text, gate_text, ondemand_tasks):
    cmp_task = next(t for t in ondemand_tasks if t.get("name") == "Compare the local snapshot files")
    return (sev["secrets_encryption_scheduled_snapshot_pattern"] == STAGE3_PATTERN
            and "if f not in st.snapshot_names and f is not match(secrets_encryption_scheduled_snapshot_pattern)" in checks_text
            and "| reject('match', secrets_encryption_scheduled_snapshot_pattern) | list)) | unique | sort," in gate_text
            and cmp_task["vars"]["es_retained"] == STAGE3_PATTERN)


def integrity_ok(v, files):
    g = next(t for t in files["guard.yml"] if t.get("name") == "Refuse an integrity expectation without an approved method")
    return (v["etcd_s3_integrity_approved_methods"] == []
            and g["ansible.builtin.assert"]["that"] == ["not etcd_s3_expect_integrity or etcd_s3_integrity_approved_methods | length > 0"])


def overlap_check_ok(files):
    g = next((t for t in files["guard.yml"] if t.get("name") == "Require non-overlapping per-server snapshot bases"), None)
    return g is not None and "b.startswith(a)" in g["vars"]["es_overlaps"] and "es_overlaps | int == 0" in g["ansible.builtin.assert"]["that"]


DOC_REQUIRED = (
    "**The drop-in holds the access key persistently.**",
    "readable only by root",
    "An ETag is never an integrity check",
    "fails closed",
    "`site.yml`, the build playbooks and the fresh-build setting are unchanged",
    "`^(etcd-snapshot-|on-demand-s4-)`",
    "`--name on-demand-s4-<host>`",
    "`no_log: true`, `diff: false` and no backup",
    "never from extra vars",
    "**Status: S4-1, static tests only.**",
)


def docs_ok(doc, se_doc, readme):
    return (all(s in doc for s in DOC_REQUIRED)
            and "`^(etcd-snapshot-|on-demand-s4-)`" in se_doc
            and "| etcd snapshot uploads to S3 (Stage 4) | Implemented with static tests (S4-1); not rehearsed, not deployed |" in readme)


STRUCTURE = [
    ("committed D1 and D4 values", lambda d: committed_values_ok(d["vars"])),
    ("play names, phases, targeting, guard first and the D5 gate", lambda d: play_phase_ok(d["books"], d["vars"])),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", lambda d: credential_hygiene_ok(d["files"])),
    ("credentials only from the two environment-named files", lambda d: sources_ok(d["texts"], d["book_texts"])),
    ("the on-demand save always names on-demand-s4-<host>; no other etcd-snapshot use", lambda d: save_argv_ok(d["files"], d["book_texts"], None)),
    ("no ETag, object metadata, annotation or object dump; probe prints only its filtered result",
     lambda d: output_safety_ok(d["texts"], d["book_texts"], d["probe"])),
    ("every name the role sets is refused if injected", lambda d: reserved_ok(d["files"], d["vars"], d["defaults"])),
    ("the guard refuses verbose, check, diff, debug, kept files, log path and callbacks", lambda d: guard_modes_ok(d["files"], d["vars"])),
    ("the fresh-build files do not configure uploads", lambda d: fresh_unchanged_ok(d["fresh"])),
    ("Stage 3 retention pattern and baseline filter", lambda d: stage3_pattern_ok(d["se_vars"], d["se_checks"], d["se_gate"], d["files"]["ondemand.yml"])),
    ("integrity fails closed with no approved method", lambda d: integrity_ok(d["vars"], d["files"])),
    ("the guard checks base overlap across the inventory", lambda d: overlap_check_ok(d["files"])),
    ("documentation statements", lambda d: docs_ok(d["doc"], d["se_doc"], d["readme"])),
]


def base_data():
    return {"vars": copy.deepcopy(role_vars), "defaults": copy.deepcopy(role_defaults), "files": copy.deepcopy(role_task_files),
            "texts": dict(role_task_texts), "books": copy.deepcopy(books), "book_texts": dict(book_texts), "probe": probe_text,
            "fresh": dict(fresh_texts), "se_vars": copy.deepcopy(se_vars), "se_checks": se_checks_text, "se_gate": se_gate_text,
            "doc": DOC, "se_doc": SE_DOC, "readme": README}


print("== structure")
for label, pred in STRUCTURE:
    check("structure", label, pred(base_data()))


def named(tasks, name):
    return next(t for t in walk(tasks) if t.get("name") == name)


def mut_file(fname, name, fn):
    """Mutate one task; the file's text predicates then see it as JSON (valid YAML, quotes preserved)."""
    def m(d):
        fn(named(d["files"][fname], name))
        d["texts"][fname] = json.dumps(d["files"][fname], indent=1)
    return m


def mut_book_text(book, old, new):
    def m(d):
        assert old in d["book_texts"][book], (book, old)
        d["book_texts"][book] = d["book_texts"][book].replace(old, new, 1)
    return m


def setv(key, val):
    def m(d):
        d["vars"][key] = val
    return m


def book_play(book, fn):
    def m(d):
        fn(d["books"][book][0])
    return m


def drop_pre(book, idx):
    return book_play(book, lambda p: p["pre_tasks"].pop(idx))


MUTANTS = [
    ("committed D1 and D4 values", "default base name", setv("etcd_s3_scheduled_base_prefix", "etcd-snapshot-")),
    ("committed D1 and D4 values", "retention 15", setv("etcd_s3_s3_retention", 15)),
    ("committed D1 and D4 values", "compression on", setv("etcd_s3_compress", True)),
    ("committed D1 and D4 values", "per-node folder", setv("etcd_s3_folder", "etcd/{{ inventory_hostname }}")),
    ("committed D1 and D4 values", "an integrity method approved", setv("etcd_s3_integrity_approved_methods", ["etag"])),
    ("committed D1 and D4 values", "string retention", setv("etcd_s3_snapshot_retention", "5")),
    ("play names, phases, targeting, guard first and the D5 gate", "guard not first", book_play("configure-etcd-s3.yml", lambda p: p["pre_tasks"].reverse())),
    ("play names, phases, targeting, guard first and the D5 gate", "guard with privilege escalation",
     book_play("restart-etcd-s3.yml", lambda p: p["pre_tasks"][0].__setitem__("become", True))),
    ("play names, phases, targeting, guard first and the D5 gate", "no Stage 3 gate before a restart", drop_pre("restart-etcd-s3.yml", 1)),
    ("play names, phases, targeting, guard first and the D5 gate", "no Stage 3 gate before a save", drop_pre("snapshot-etcd-s3.yml", 1)),
    ("play names, phases, targeting, guard first and the D5 gate", "serial removed", book_play("configure-etcd-s3.yml", lambda p: p.pop("serial"))),
    ("play names, phases, targeting, guard first and the D5 gate", "any_errors_fatal removed", book_play("snapshot-etcd-s3.yml", lambda p: p.pop("any_errors_fatal"))),
    ("play names, phases, targeting, guard first and the D5 gate", "facts gathered", book_play("validate-etcd-s3.yml", lambda p: p.__setitem__("gather_facts", True))),
    ("play names, phases, targeting, guard first and the D5 gate", "phase name swapped",
     book_play("snapshot-etcd-s3.yml", lambda p: p["vars"].__setitem__("etcd_s3_phase", "configure"))),
    ("play names, phases, targeting, guard first and the D5 gate", "credentials loaded by a read-only report",
     book_play("validate-etcd-s3.yml", lambda p: p["pre_tasks"].append({"name": "x", "ansible.builtin.import_role": {"name": "etcd-s3", "tasks_from": "credentials.yml"}}))),
    ("play names, phases, targeting, guard first and the D5 gate", "ledger after the change",
     book_play("configure-etcd-s3.yml", lambda p: p["tasks"].append(p["tasks"].pop(next(i for i, t in enumerate(p["tasks"]) if t.get("name") == "Consume the confirmation"))))),
    ("play names, phases, targeting, guard first and the D5 gate", "no leak check after the restart",
     book_play("restart-etcd-s3.yml", lambda p: p["tasks"].pop(next(i for i, t in enumerate(p["tasks"]) if t.get("name") == "Check for credential leaks")))),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", "credential read without no_log",
     mut_file("credentials.yml", "Read the key file and the bucket file", lambda t: t.pop("no_log"))),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", "credential check with diff",
     mut_file("credentials.yml", "Require an active key for the etcd identity and a well-formed bucket name", lambda t: t.__setitem__("diff", True))),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", "drop-in write with a backup",
     mut_file("dropin.yml", "Write the Stage 4 drop-in", lambda t: t["ansible.builtin.copy"].__setitem__("backup", True))),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", "drop-in write displayed",
     mut_file("dropin.yml", "Write the Stage 4 drop-in", lambda t: t.pop("no_log"))),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", "drop-in by template",
     mut_file("dropin.yml", "Write the Stage 4 drop-in", lambda t: t.__setitem__("ansible.builtin.template", t.pop("ansible.builtin.copy")))),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", "probe output displayed",
     mut_file("probe.yml", "Run the Stage 4 probe", lambda t: t.pop("no_log"))),
    ("credential hygiene: no_log, diff off, no backup, no template or debug", "save output displayed",
     mut_file("ondemand.yml", "Take the on-demand snapshot", lambda t: t.pop("no_log"))),
    ("credentials only from the two environment-named files", "key from an extra var",
     mut_file("credentials.yml", "Resolve the credential source paths from the environment",
              lambda t: t["ansible.builtin.set_fact"]["etcd_s3_sources"].__setitem__("key", "{{ etcd_s3_key_path }}"))),
    ("credentials only from the two environment-named files", "key from another environment variable",
     mut_file("credentials.yml", "Resolve the credential source paths from the environment",
              lambda t: t["ansible.builtin.set_fact"]["etcd_s3_sources"].__setitem__("key", "{{ lookup('ansible.builtin.env', 'AWS_SECRET_ACCESS_KEY') }}"))),
    ("credentials only from the two environment-named files", "credential read on the node",
     mut_file("credentials.yml", "Read the key file and the bucket file", lambda t: t.pop("delegate_to"))),
    ("the on-demand save always names on-demand-s4-<host>; no other etcd-snapshot use", "save without --name",
     mut_file("ondemand.yml", "Take the on-demand snapshot", lambda t: t["ansible.builtin.command"].__setitem__("argv", t["ansible.builtin.command"]["argv"][:3]))),
    ("the on-demand save always names on-demand-s4-<host>; no other etcd-snapshot use", "default on-demand name",
     mut_file("values.yml", "Compute this server's Stage 4 settings", lambda t: t["ansible.builtin.set_fact"].__setitem__("etcd_s3_ondemand_name", "on-demand"))),
    ("the on-demand save always names on-demand-s4-<host>; no other etcd-snapshot use", "a snapshot delete",
     mut_book_text("validate-etcd-s3.yml", "  tasks:\n", "  tasks:\n    # k3s etcd-snapshot delete\n")),
    ("no ETag, object metadata, annotation or object dump; probe prints only its filtered result", "an ETag comparison",
     lambda d: d["texts"].__setitem__("report.yml", d["texts"]["report.yml"] + "\n# compare the object ETag with the local MD5\n- x: '{{ etag }}'\n")),
    ("no ETag, object metadata, annotation or object dump; probe prints only its filtered result", "a record dump",
     lambda d: d["texts"].__setitem__("report.yml", d["texts"]["report.yml"] + "\n- argv: [k3s, kubectl, get, etcdsnapshotfiles, -o yaml]\n")),
    ("no ETag, object metadata, annotation or object dump; probe prints only its filtered result", "probe prints a record",
     lambda d: d.__setitem__("probe", d["probe"].replace("    print(json.dumps(result, sort_keys=True))", "    print(json.dumps(result, sort_keys=True))\n    print(records)"))),
    ("no ETag, object metadata, annotation or object dump; probe prints only its filtered result", "probe output unfiltered",
     lambda d: d.__setitem__("probe", d["probe"].replace("result = checked(modes[a.mode](a, exp))", "result = modes[a.mode](a, exp)"))),
    ("every name the role sets is refused if injected", "unknown-variable check removed",
     lambda d: d["files"]["guard.yml"].remove(named(d["files"]["guard.yml"], "Refuse unknown Stage 4 variables"))),
    ("every name the role sets is refused if injected", "a role fact outside the protected namespace",
     mut_file("values.yml", "Compute this server's Stage 4 settings", lambda t: t["ansible.builtin.set_fact"].__setitem__("s4_dropin", "x"))),
    ("every name the role sets is refused if injected", "confirmation evaluated before the reserved check",
     lambda d: d["files"]["guard.yml"].insert(1, d["files"]["guard.yml"].pop(next(i for i, t in enumerate(d["files"]["guard.yml"]) if t.get("name") == "Evaluate the phase confirmation")))),
    ("the guard refuses verbose, check, diff, debug, kept files, log path and callbacks", "verbosity allowed",
     mut_file("guard.yml", "Refuse output modes that could expose credentials", lambda t: t["ansible.builtin.assert"]["that"].remove("ansible_verbosity | int == 0"))),
    ("the guard refuses verbose, check, diff, debug, kept files, log path and callbacks", "diff allowed",
     mut_file("guard.yml", "Refuse output modes that could expose credentials", lambda t: t["ansible.builtin.assert"]["that"].remove("not ansible_diff_mode"))),
    ("the guard refuses verbose, check, diff, debug, kept files, log path and callbacks", "kept remote files allowed",
     setv("etcd_s3_refused_config", ["DEFAULT_DEBUG", "DISPLAY_ARGS_TO_STDOUT"])),
    ("the fresh-build files do not configure uploads", "site.yml configures uploads",
     lambda d: d["fresh"].__setitem__("site.yml", d["fresh"]["site.yml"] + "\n- import_playbook: configure-etcd-s3.yml\n")),
    ("the fresh-build files do not configure uploads", "k3s-server writes the drop-in",
     lambda d: d["fresh"].__setitem__("roles/k3s-server/tasks/main.yml", d["fresh"]["roles/k3s-server/tasks/main.yml"] + "\n# 30-etcd-s3.yaml\n")),
    ("Stage 3 retention pattern and baseline filter", "Stage 3 pattern reverted",
     lambda d: d["se_vars"].__setitem__("secrets_encryption_scheduled_snapshot_pattern", "^etcd-snapshot-")),
    ("Stage 3 retention pattern and baseline filter", "Stage 3 pattern covers default on-demand",
     lambda d: d["se_vars"].__setitem__("secrets_encryption_scheduled_snapshot_pattern", "^(etcd-snapshot-|on-demand-)")),
    ("Stage 3 retention pattern and baseline filter", "baseline filter removed",
     lambda d: d.__setitem__("se_checks", d["se_checks"].replace(" and f is not match(secrets_encryption_scheduled_snapshot_pattern)", ""))),
    ("Stage 3 retention pattern and baseline filter", "Stage 4 comparison pattern differs",
     mut_file("ondemand.yml", "Compare the local snapshot files", lambda t: t["vars"].__setitem__("es_retained", "^etcd-snapshot-"))),
    ("integrity fails closed with no approved method", "integrity refusal removed",
     mut_file("guard.yml", "Refuse an integrity expectation without an approved method", lambda t: t["ansible.builtin.assert"].__setitem__("that", ["true"]))),
    ("the guard checks base overlap across the inventory", "overlap check weakened",
     mut_file("guard.yml", "Require non-overlapping per-server snapshot bases", lambda t: t["ansible.builtin.assert"]["that"].remove("es_overlaps | int == 0"))),
    ("documentation statements", "persistent credential statement removed",
     lambda d: d.__setitem__("doc", d["doc"].replace("**The drop-in holds the access key persistently.**", "The drop-in is written."))),
    ("documentation statements", "ETag claimed as integrity",
     lambda d: d.__setitem__("doc", d["doc"].replace("An ETag is never an integrity check", "The ETag proves integrity"))),
    ("documentation statements", "README claims deployment",
     lambda d: d.__setitem__("readme", d["readme"].replace("Implemented with static tests (S4-1); not rehearsed, not deployed", "Deployed"))),
]

print("== structural mutants")
preds = dict(STRUCTURE)
for target, label, fn in MUTANTS:
    d = base_data()
    try:
        fn(d)
        survived = preds[target](d)
    except (KeyError, StopIteration, IndexError, ValueError, AssertionError, TypeError) as exc:
        check("mutant", f"{label} (mutation could not be applied: {type(exc).__name__})", False)
        continue
    check("mutant", f"{label} is caught by: {target}", not survived)


# ====================================================================== unit tests
print("== unit")
spec = importlib.util.spec_from_file_location("etcd_s3_probe", role / "files/etcd_s3_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="s4-tests-"))
EXP_VALUES = {
    "etcd-snapshot-name": "etcd-snapshot-s4-s4t01", "etcd-snapshot-retention": 5, "etcd-snapshot-schedule-cron": "0 */12 * * *",
    "etcd-snapshot-compress": False, "etcd-s3": True, "etcd-s3-endpoint": "s3.amazonaws.com", "etcd-s3-region": "us-east-1",
    "etcd-s3-folder": "etcd", "etcd-s3-retention": 5, "etcd-s3-bucket-lookup-type": "auto", "etcd-s3-timeout": "5m0s"}
EXP = {"version": "v1.36.4+k3s1", "owner_uid": os.getuid(), "scheduled_base": "etcd-snapshot-s4-s4t01", "ondemand_base": "on-demand-s4-s4t01",
       "scheduled_base_prefix": "etcd-snapshot-s4-", "ondemand_base_prefix": "on-demand-s4-", "scheduled_name": "etcd-snapshot-s4-s4t01",
       "approved_bases": role_vars["etcd_s3_approved_bases"], "keys": role_vars["etcd_s3_dropin_keys"], "values": EXP_VALUES,
       "access_key_pattern": role_vars["etcd_s3_access_key_pattern"], "secret_key_pattern": role_vars["etcd_s3_secret_key_pattern"],
       "bucket_pattern": role_vars["etcd_s3_bucket_pattern"], "wait": {}}


def dropin_doc(**over):
    d = dict(EXP_VALUES, **{"etcd-s3-bucket": BUCKET, "etcd-s3-access-key": KEY_ID, "etcd-s3-secret-key": SECRET})
    d.update(over)
    return {k: v for k, v in d.items() if v is not None}


class A:
    pass


def probe_args(d, host="s4t01"):
    a = A()
    a.host, a.config_file, a.config_dir = host, str(d / "config.yaml"), str(d / "config.yaml.d")
    a.dropin, a.unit, a.root_aws = str(d / "config.yaml.d/30-etcd-s3.yaml"), str(d / "k3s.service"), str(d / "root-aws")
    return a


def unit_config(label, files, expect):
    d = tmp_root / f"unit-config-{len(list(tmp_root.glob('unit-config-*')))}"
    (d / "config.yaml.d").mkdir(parents=True)
    (d / "k3s.service").write_text("[Service]\nExecStart=/usr/local/bin/k3s server\n")
    for name, content in files.items():
        p = d / name
        p.write_text(content if isinstance(content, str) else yaml.safe_dump(content))
        os.chmod(p, 0o600)
    out = probe.checked(probe.mode_config(probe_args(d), EXP))
    ok = all(out.get(k) == v for k, v in expect.items()) and not any(s in json.dumps(out) for s in SENTINELS)
    check("unit", f"probe config: {label}", ok, json.dumps(out))


DI = "config.yaml.d/30-etcd-s3.yaml"
unit_config("the approved drop-in", {"config.yaml": {"cluster-init": True}, DI: dropin_doc()},
            {"values_match": True, "name_ok": True, "name_definitions": 1, "dropin_unknown_keys": 0, "dropin_missing_keys": 0,
             "stage4_keys_elsewhere": 0, "access_key_format_ok": True, "secret_key_format_ok": True, "bucket_format_ok": True,
             "dropin_mode_ok": True, "unit_stage4_flags": 0})
unit_config("a default base name", {DI: dropin_doc(**{"etcd-snapshot-name": "etcd-snapshot"})}, {"values_match": False, "name_ok": False})
unit_config("a prefix-matching pre-Stage-4 name", {DI: dropin_doc(**{"etcd-snapshot-name": "etcd-snapshot-s4t01"})}, {"name_ok": False})
unit_config("a missing name", {DI: dropin_doc(**{"etcd-snapshot-name": None})}, {"name_ok": False, "name_definitions": 0})
unit_config("a second name in config.yaml", {"config.yaml": {"etcd-snapshot-name": "etcd-snapshot"}, DI: dropin_doc()},
            {"name_definitions": 2, "stage4_keys_elsewhere": 1})
unit_config("an appended name in another drop-in", {"config.yaml.d/40-x.yaml": {"etcd-snapshot-name+": "x"}, DI: dropin_doc()},
            {"name_definitions": 2, "stage4_keys_elsewhere": 1})
unit_config("an S3 key in config.yaml", {"config.yaml": {"etcd-s3": True}, DI: dropin_doc()}, {"stage4_keys_elsewhere": 1})
unit_config("compression on", {DI: dropin_doc(**{"etcd-snapshot-compress": True})}, {"values_match": False})
unit_config("a per-node folder", {DI: dropin_doc(**{"etcd-s3-folder": "etcd/s4t01"})}, {"values_match": False})
unit_config("retention as a string", {DI: dropin_doc(**{"etcd-s3-retention": "5"})}, {"values_match": False})
unit_config("an unknown key", {DI: dropin_doc(**{"etcd-s3-config-secret": "x"})}, {"dropin_unknown_keys": 1})
unit_config("an unexpected allowlisted key", {DI: dropin_doc(**{"etcd-s3-proxy": "none"})}, {"values_match": False})
unit_config("a missing secret", {DI: dropin_doc(**{"etcd-s3-secret-key": None})}, {"dropin_missing_keys": 1, "secret_key_format_ok": False})
unit_config("a malformed key ID", {DI: dropin_doc(**{"etcd-s3-access-key": "AKIA-short"})}, {"access_key_format_ok": False})
unit_config("an unparsable source", {"config.yaml.d/10-bad.yaml": "a: [\n", DI: dropin_doc()}, {"unparsable": 1})
unit_config("no drop-in", {}, {"dropin_exists": False, "name_definitions": 0})

# Leak counting: exact secrets and key-shaped strings, counts only.
secrets_b = [KEY_ID.encode(), SECRET.encode()]
for label, data, n in (("none", b"Checking if S3 bucket exists\n", 0), ("the secret", b"x " + SECRET.encode() + b" y", 1),
                       ("the key ID (exact and key-shaped)", b"id=" + KEY_ID.encode(), 2),
                       ("another key-shaped string", b"ASIA" + b"Z" * 16, 1), ("both", SECRET.encode() + KEY_ID.encode(), 3)):
    check("unit", f"leak count: {label}", probe.count_in(data, secrets_b) == n)
for label, obj, ok in (("booleans and integers", {"a": True, "b": {"c": 1}}, True), ("a string value", {"a": SECRET}, False),
                       ("a list", {"a": [1]}, False), ("a float", {"a": 1.5}, False)):
    try:
        probe.checked(obj)
        got = True
    except ValueError:
        got = False
    check("unit", f"probe output filter: {label} {'accepted' if ok else 'refused'}", got == ok)


def snap_unit(label, files, records, expect):
    d = tmp_root / f"unit-snap-{len(list(tmp_root.glob('unit-snap-*')))}"
    (d / "snaps").mkdir(parents=True)
    for n in files:
        (d / "snaps" / n).write_text("x")
    a = probe_args(d)
    a.snapshot_dir, a.k3s = str(d / "snaps"), "unused"
    saved = probe.snapshot_records
    probe.snapshot_records = lambda k3s: (records, b"")
    try:
        out = probe.checked(probe.mode_snapshots(a, EXP))
    finally:
        probe.snapshot_records = saved
    ok = all((out[k] if not isinstance(v, dict) else {kk: out[k][kk] for kk in v}) == v for k, v in expect.items())
    check("unit", f"probe snapshots: {label}", ok, json.dumps(out))


def rec(name, node="s4t01", s3=True, ready=True, when="2026-10-31T12:00:00Z"):
    return {"spec": {"snapshotName": name, "nodeName": node, "s3": {"bucket": BUCKET} if s3 else None},
            "status": {"readyToUse": ready, "creationTime": when}, "metadata": {"annotations": {"etcd.k3s.cattle.io/token-hash": "0" * 12}}}


snap_unit("classification by base and node", ["etcd-snapshot-s4-s4t01-s4t01-1", "on-demand-s4-s4t01-s4t01-2", "stage3-p2-x-s4t01-3",
                                              "etcd-snapshot-s4t01-4", "on-demand-s4t01-5", "etcd-snapshot-s4-s4t02-s4t02-6"],
          [rec("etcd-snapshot-s4-s4t01-s4t01-1"), rec("on-demand-s4-s4t01-s4t01-2"), rec("etcd-snapshot-s4-s4t02-s4t02-6", node="s4t02"),
           rec("etcd-snapshot-s4t01-4", s3=False), rec("on-demand-s4-s4t01-s4t01-7", ready=False)],
          {"local": {"scheduled_s4": 1, "ondemand_s4": 1, "stage3": 1, "legacy_scheduled": 1, "other": 1, "other_server_s4": 1},
           "s3": {"scheduled_s4": 1, "ondemand_s4": 1, "ready": 2, "not_ready": 1, "unapproved_base": 0}})
snap_unit("an S3 record with an unapproved base", [], [rec("etcd-snapshot-s4t01-9"), rec("on-demand-s4t01-1", node="s4t02")],
          {"s3": {"unapproved_base": 2}})

# The D6 byte counter and the comparator, as the rehearsal runs them.
tools = role / "files"


def tool(name, *args):
    return subprocess.run([sys.executable, "-I", str(tools / name), *map(str, args)], capture_output=True)


marker = bytes(range(7, 39))
mk = tmp_root / "marker.bin"
mk.write_bytes(marker)
for label, data, n in (("no occurrence", b"\0" * 5000, 0), ("two occurrences", b"a" + marker + b"b" * 100 + marker, 2),
                       ("base64 and hex renderings", base64.b64encode(marker) + marker.hex().encode(), 0),
                       ("across a chunk boundary", b"z" * ((1 << 20) - 10) + marker + b"z", 1),
                       ("a truncated marker", marker[:-1], 0)):
    t = tmp_root / f"target-{label.replace(' ', '-')}.bin"
    t.write_bytes(data)
    r = tool("byte_count.py", mk, t)
    check("unit", f"byte counter: {label}", r.returncode == 0 and r.stdout == f"{n}\n".encode() and marker not in r.stdout + r.stderr
          and marker.hex().encode() not in r.stdout)
short = tmp_root / "short.bin"
short.write_bytes(b"x" * 8)
for label, args in (("a marker under 16 bytes", (short, mk)), ("a missing target", (mk, tmp_root / "absent")), ("no arguments", ())):
    r = tool("byte_count.py", *args)
    check("unit", f"byte counter refuses {label}", r.returncode == 2 and r.stdout == b"FAIL-USAGE\n")
a_f, b_f, c_f = tmp_root / "a.snap", tmp_root / "b.snap", tmp_root / "c.snap"
a_f.write_bytes(b"\1" * 3000)
b_f.write_bytes(b"\1" * 3000)
c_f.write_bytes(b"\1" * 2999 + b"\2")
for label, args, rc, out in (("identical files", (a_f, b_f), 0, b"MATCH\n"), ("one byte differs", (a_f, c_f), 1, b"MISMATCH\n"),
                             ("a shorter file", (a_f, mk), 1, b"MISMATCH\n"), ("the same file twice", (a_f, a_f), 2, b"FAIL-USAGE\n")):
    r = tool("snapshot_compare.py", *args)
    check("unit", f"comparator: {label}", r.returncode == rc and r.stdout == out and b"3000" not in r.stdout + r.stderr)


# ====================================================================== behavior
print("== behavior")


def find_tmpfs():
    for c in ("/dev/shm", os.environ.get("XDG_RUNTIME_DIR", "")):
        if c and os.path.isdir(c):
            r = subprocess.run(["stat", "-f", "-c", "%T", c], capture_output=True, text=True)
            if r.stdout.strip() == "tmpfs" and os.access(c, os.W_OK):
                return c
    return None


TMPFS = find_tmpfs()
check("behavior", "a writable tmpfs exists for the operator key file", TMPFS is not None)
# A key directory on a disk file system, for the not-on-tmpfs refusal.
NON_TMPFS = tempfile.mkdtemp(prefix="s4-nontmpfs-", dir=os.path.expanduser("~"))
check("behavior", "the not-on-tmpfs case uses a disk file system",
      subprocess.run(["stat", "-f", "-c", "%T", NON_TMPFS], capture_output=True, text=True).stdout.strip() not in ("tmpfs", "ramfs", ""))
UID = os.getuid()
import grp  # noqa: E402
import pwd  # noqa: E402
USER = pwd.getpwuid(UID).pw_name
check("behavior", "the test user's primary group has the user's name (the role uses one owner name)",
      grp.getgrgid(os.getgid()).gr_name == USER and os.getgid() == UID)
SERVERS = ("s4t01", "s4t02", "s4t03")
TASK_RE = re.compile(r"^TASK \[(.+?)\] \*+$")
children = []

FAKE_K3S = r'''#!PYTHON
import json, os, pathlib, sys, time
D = pathlib.Path(__file__).resolve().parents[1]
a = sys.argv[1:]
host = (D / "etc/hostname").read_text().strip()
if a[:1] == ["--version"]:
    print("k3s version v1.36.4+k3s1 (4dedb15b)"); sys.exit(0)
if a[:2] == ["etcd-snapshot", "save"]:
    if len(a) != 4 or a[2] != "--name":
        sys.exit(9)
    with open(D / "save-calls", "a") as f:
        f.write(a[3] + "\n")
    print("Uploading snapshot to bucket " + (D / "bucket-echo").read_text())
    if (D / "save-fail").exists():
        print("S3 upload failed for bucket " + (D / "bucket-echo").read_text(), file=sys.stderr); sys.exit(1)
    ts = int(time.time())
    name = f"{a[3]}-{host}-{ts}"
    (D / "snapshots" / name).write_text("snapshot")
    if not (D / "no-record").exists():
        recs = json.loads((D / "records.json").read_text())
        recs.append({"metadata": {"name": "s3-" + name, "annotations": {"etcd.k3s.cattle.io/token-hash": "0" * 12}},
                     "spec": {"snapshotName": name, "nodeName": host, "location": "s3://" + (D / "bucket-echo").read_text() + "/etcd/" + name,
                              "s3": {"bucket": (D / "bucket-echo").read_text(), "folder": "etcd"}},
                     "status": {"readyToUse": True, "creationTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))}})
        (D / "records.json").write_text(json.dumps(recs))
    sys.exit(0)
if a[:1] == ["kubectl"]:
    k = a[1:]
    if k == ["get", "etcdsnapshotfiles.k3s.cattle.io", "-o", "json"]:
        print(json.dumps({"items": json.loads((D / "records.json").read_text())})); sys.exit(0)
    if k == ["get", "configmap", "-n", "kube-system", "k3s-etcd-snapshots", "-o", "json"]:
        p = D / "configmap.json"
        if p.exists():
            print(p.read_text()); sys.exit(0)
        sys.exit(1)
    if k[:4] == ["get", "configmap", "-n", "kube-system"]:
        sys.exit(1)
    if k == ["get", "--raw", "/readyz"]:
        print("ok"); sys.exit(0)
    if k[:2] == ["get", "node"]:
        print("True"); sys.exit(0)
sys.exit(7)
'''

FAKE_SYSTEMCTL = r'''#!PYTHON
import os, pathlib, subprocess, sys
D = pathlib.Path(__file__).resolve().parents[1]
a = sys.argv[1:]
if a == ["show", "--property", "MainPID", "--value", "k3s"]:
    print((D / "pid").read_text().strip()); sys.exit(0)
if a == ["restart", "k3s"]:
    with open(D / "restart-calls", "a") as f:
        f.write("restart\n")
    p = subprocess.Popen(["sleep", "300"], env={"PATH": "/usr/bin:/bin"}, start_new_session=True)
    (D / "pid").write_text(str(p.pid))
    with open(D / "children", "a") as f:
        f.write(str(p.pid) + "\n")
    sys.exit(0)
sys.exit(5)
'''

FAKE_JOURNALCTL = r'''#!PYTHON
import pathlib, sys
D = pathlib.Path(__file__).resolve().parents[1]
sys.stdout.write((D / "journal.txt").read_text()); sys.exit(0)
'''

STAGE3_STUB = [{"name": "Stub of the Stage 3 validation", "hosts": "localhost", "gather_facts": False, "tasks": [
    {"name": "Record the Stage 3 stub run", "ansible.builtin.copy": {
        "content": "{{ secrets_encryption_enforce }} {{ secrets_encryption_expect }}\n", "dest": "{{ lookup('ansible.builtin.env', 'S4T_STAGE3_MARK') }}"}},
    {"name": "Stub the Stage 3 result", "ansible.builtin.assert": {"that": [
        "lookup('ansible.builtin.env', 'S4T_STAGE3_FAIL') == ''", "secrets_encryption_enforce | bool", "secrets_encryption_expect == 'enabled'"]}}]}]


def now_id(minutes=0):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutes)).strftime("%Y%m%dT%H%M%SZ")


def new_case(hosts=SERVERS, key_doc=None, key_mode=0o600, key_dir_mode=0o700, key_on_tmpfs=True, key_link=False, bucket_text=None,
             bucket_mode=0o600, preexisting=(), config=None, dropin=None, dropin_link=False, journal="Started k3s\n", configmap=None,
             records=None, env_proc=None, save_fail=False, no_record=False):
    d = tmp_root / f"case-{len(list(tmp_root.glob('case-*')))}"
    tree = d / "tree"
    shutil.copytree(ans, tree, ignore=shutil.ignore_patterns("tests", "inventory", "__pycache__", "ansible.cfg"))
    (tree / "validate-secrets-encryption.yml").write_text(yaml.safe_dump(STAGE3_STUB, sort_keys=False))
    for sub in ("bin", "etc/config.yaml.d", "snapshots", "zoneinfo/Etc"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    (d / "zoneinfo/Etc/UTC").write_text("TZif")
    os.symlink(d / "zoneinfo/Etc/UTC", d / "etc/localtime")
    (d / "etc/hostname").write_text(hosts[0] + "\n")
    (d / "etc/k3s.service").write_text("[Service]\nExecStart=/usr/local/bin/k3s server\n")
    (d / "etc/k3s.service.env").write_text("K3S_EXAMPLE=1\n")
    (d / "metrics.txt").write_text("etcd_mvcc_db_total_size_in_bytes 4e+06\netcd_mvcc_db_total_size_in_use_in_bytes 3e+06\n")
    (d / "journal.txt").write_text(journal)
    (d / "records.json").write_text(json.dumps(records or []))
    (d / "bucket-echo").write_text(BUCKET)
    if configmap is not None:
        (d / "configmap.json").write_text(configmap)
    if save_fail:
        (d / "save-fail").write_text("1")
    if no_record:
        (d / "no-record").write_text("1")
    for n in preexisting:
        (d / "snapshots" / n).write_text("old")
    os.chmod(d / "etc", 0o755)
    os.chmod(d / "etc/config.yaml.d", 0o755)
    if config is not None:
        (d / "etc/config.yaml").write_text(yaml.safe_dump(config))
    dp = d / "etc/config.yaml.d/30-etcd-s3.yaml"
    if dropin_link:
        (d / "elsewhere.yaml").write_text("x: 1\n")
        os.symlink(d / "elsewhere.yaml", dp)
    elif dropin is not None:
        dp.write_text(yaml.safe_dump(dropin))
        os.chmod(dp, 0o600)
    for name, src in (("k3s", FAKE_K3S), ("systemctl", FAKE_SYSTEMCTL), ("journalctl", FAKE_JOURNALCTL)):
        p = d / "bin" / name
        p.write_text(src.replace("#!PYTHON", "#!" + sys.executable))
        os.chmod(p, 0o755)
    proc = subprocess.Popen(["sleep", "300"], env=dict({"PATH": "/usr/bin:/bin"}, **(env_proc or {})), start_new_session=True)
    children.append(proc.pid)
    (d / "pid").write_text(str(proc.pid))
    v = copy.deepcopy(role_vars)
    v.update({"etcd_s3_k3s_bin": str(d / "bin/k3s"), "etcd_s3_systemctl": str(d / "bin/systemctl"), "etcd_s3_journalctl": str(d / "bin/journalctl"),
              "etcd_s3_config_file": str(d / "etc/config.yaml"), "etcd_s3_config_dir": str(d / "etc/config.yaml.d"), "etcd_s3_dropin_path": str(dp),
              "etcd_s3_unit_file": str(d / "etc/k3s.service"), "etcd_s3_unit_env_file": str(d / "etc/k3s.service.env"),
              "etcd_s3_root_aws_dir": str(d / "root-aws"), "etcd_s3_snapshot_dir": str(d / "snapshots"), "etcd_s3_hostname_file": str(d / "etc/hostname"),
              "etcd_s3_localtime": str(d / "etc/localtime"), "etcd_s3_etcd_metrics_url": "file://" + str(d / "metrics.txt"),
              "etcd_s3_owner": USER, "etcd_s3_owner_uid": UID, "etcd_s3_state_dir": str(d / "state")})
    (tree / "roles/etcd-s3/vars/main.yml").write_text(yaml.safe_dump(v, sort_keys=False, width=200))
    # The operator's files.
    kd = pathlib.Path(tempfile.mkdtemp(prefix="s4key-", dir=TMPFS if key_on_tmpfs else NON_TMPFS))
    os.chmod(kd, key_dir_mode)
    kf = kd / "etcd-key.json"
    doc = key_doc if key_doc is not None else {"AccessKey": {"UserName": "home-cluster-etcd-backup", "AccessKeyId": KEY_ID, "Status": "Active",
                                                             "SecretAccessKey": SECRET, "CreateDate": "2026-10-31T00:00:00Z"}}
    real = kd / "real-key.json" if key_link else kf
    real.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    os.chmod(real, key_mode)
    if key_link:
        os.symlink(real, kf)
    bf = d / "backup-bucket"
    bf.write_text((bucket_text if bucket_text is not None else BUCKET) + "\n")
    os.chmod(bf, bucket_mode)
    inv = {"all": {"vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable},
                   "children": {"servers": {"hosts": {h: {} for h in hosts}}}}}
    (d / "inventory.yml").write_text(yaml.safe_dump(inv))
    return {"dir": d, "tree": tree, "dropin": dp, "key": kf, "key_dir": kd, "bucket": bf, "hosts": hosts}


def failed_task(stdout):
    current = None
    for line in stdout.splitlines():
        m = TASK_RE.match(line)
        if m:
            current = m.group(1)
        elif line.startswith(("fatal: [", "failed: [")):
            return current
    return None


def run_book(case, book, limit="s4t01", phase=None, confirm=None, extra=None, args=(), env_over=None, env_drop=(), environment="rehearsal"):
    d = case["dir"]
    ev = {"etcd_s3_environment": environment, "ansible_become": False}
    phase = phase or {"configure-etcd-s3.yml": "configure", "restart-etcd-s3.yml": "restart", "snapshot-etcd-s3.yml": "snapshot"}.get(book)
    if phase and confirm is not False:
        ev["etcd_s3_confirm"] = confirm or f"{phase}:{limit}:{now_id()}"
    ev.update(extra or {})
    cmd = ["ansible-playbook", "-i", str(d / "inventory.yml"), str(case["tree"] / book), "-e", json.dumps(ev), *args]
    if limit:
        cmd += ["--limit", limit]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANSIBLE_", "HOMELAB_", "S4T_"))}
    env.update({"HOMELAB_ETCD_S3_KEY_FILE": str(case["key"]), "HOMELAB_ETCD_S3_BUCKET_FILE": str(case["bucket"]),
                "S4T_STAGE3_MARK": str(d / "stage3-ran"), "ANSIBLE_HOST_KEY_CHECKING": "False", "ANSIBLE_NOCOLOR": "1",
                "ANSIBLE_LOCAL_TEMP": str(d / "ansible-local"), "ANSIBLE_REMOTE_TEMP": str(d / "ansible-remote")})
    for k in env_drop:
        env.pop(k, None)
    env.update(env_over or {})
    for p in ("stage3-ran",):
        (d / p).unlink(missing_ok=True)
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=str(d))
    return r


def leaked(r, case):
    out = r.stdout + r.stderr
    log = case["dir"] / "ansible.log"
    if log.exists():
        out += log.read_text()
    return [s for s in SENTINELS if s in out]


def new_snapshots(case, prefix="on-demand-s4-"):
    return sorted(n.name for n in (case["dir"] / "snapshots").iterdir() if n.name.startswith(prefix))


def behave(label, case, book, expect_fail, written=False, saved=None, stage3=None, **kw):
    r = run_book(case, book, **kw)
    got = failed_task(r.stdout) if r.returncode != 0 else None
    leaks = leaked(r, case)
    dropin = case["dropin"].exists() and not case["dropin"].is_symlink()
    saves = (case["dir"] / "save-calls").read_text().splitlines() if (case["dir"] / "save-calls").exists() else []
    stage3_ran = (case["dir"] / "stage3-ran").exists()
    if expect_fail is True:
        fail_ok = r.returncode != 0
    elif expect_fail:
        # With displayed task arguments, the header carries the arguments after the name.
        fail_ok = r.returncode != 0 and got is not None and (got.endswith(expect_fail) or got.startswith("etcd-s3 : " + expect_fail + " "))
    else:
        fail_ok = r.returncode == 0
    ok = (fail_ok and not leaks and dropin == written and (saved is None or len(saves) == saved)
          and (stage3 is None or stage3_ran == stage3))
    check("behavior", label, ok, f"rc={r.returncode} failed={got!r} leaked={len(leaks)} dropin={dropin} saves={len(saves)} stage3={stage3_ran}\n"
          + "\n".join(l for l in r.stdout.splitlines() if l.startswith(("fatal", "TASK", "ERROR", "[ERROR")) or "msg" in l)[-2500:]
          + r.stderr[-800:])
    return r


if TMPFS is not None:
    G_BIND = "Bind the phase to the running play"
    G_RES = "Refuse reserved variables from the command line or inventory"
    G_UNK = "Refuse unknown Stage 4 variables"
    G_MODE = "Refuse output modes that could expose credentials"
    G_CFG = "Refuse configuration that displays or keeps task data"
    G_LIM = "Require an exact single-host limit for a mutating phase"
    G_CONF = "Require a fresh confirmation for this phase and host"
    G_ENV = "Require a declared environment that matches the inventory"
    G_REH = "Refuse rehearsal endpoints near the live cluster"
    G_FIX = "Require the committed fixed values"
    G_OVL = "Require non-overlapping per-server snapshot bases"
    G_INT = "Refuse an integrity expectation without an approved method"
    S3G = "Require the Stage 3 enabled state on every server"
    C_PATH = "Require absolute credential source paths"
    C_FILE = "Require a private key file on tmpfs and a private bucket file"
    C_KEY = "Require an active key for the etcd identity and a well-formed bucket name"
    C_EXT = "Extract the access key and the bucket name"
    CONF = "configure-etcd-s3.yml"

    # ---- success paths, in rollout order, with sentinel checks on every output
    ok_case = new_case(preexisting=("etcd-snapshot-s4t01-1700000000", "on-demand-s4t01-1700000001", "stage3-p2-20261029t000000z-s4t01-1"))
    r = behave("configure: success on a rehearsal server (drop-in, on-demand upload, no leak)", ok_case, CONF, False, written=True, saved=1, stage3=True)
    if ok_case["dropin"].exists():
        st = ok_case["dropin"].stat()
        doc = yaml.safe_load(ok_case["dropin"].read_text())
        want = dict(EXP_VALUES, **{"etcd-s3-bucket": BUCKET, "etcd-s3-access-key": KEY_ID, "etcd-s3-secret-key": SECRET})
        differ = sorted(k for k in set(doc) | set(want) if doc.get(k) != want.get(k) or type(doc.get(k)) is not type(want.get(k)))
        check("behavior", "configure: the drop-in is 0600, owned by the configured owner, with exactly the approved keys and values",
              oct(st.st_mode & 0o7777) == "0o600" and st.st_uid == UID and not differ,
              f"mode={oct(st.st_mode & 0o7777)} differing keys (names only)={differ}")
    check("behavior", "configure: the save used --name on-demand-s4-<host>",
          (ok_case["dir"] / "save-calls").exists() and (ok_case["dir"] / "save-calls").read_text() == "on-demand-s4-s4t01\n")
    check("behavior", "configure: pre-existing default-named and Stage 3 files are untouched",
          {"etcd-snapshot-s4t01-1700000000", "on-demand-s4t01-1700000001", "stage3-p2-20261029t000000z-s4t01-1"}
          <= {p.name for p in (ok_case["dir"] / "snapshots").iterdir()})
    check("behavior", "configure: the success output has no credential and no bucket", not leaked(r, ok_case))
    behave("snapshot: success after configuration", ok_case, "snapshot-etcd-s3.yml", False, written=True, saved=2, stage3=True)
    reuse = f"snapshot:s4t01:{now_id(-1)}"
    behave("snapshot: a fresh confirmation is accepted once", ok_case, "snapshot-etcd-s3.yml", False, written=True, saved=3, confirm=reuse)
    behave("snapshot: the same confirmation is refused the second time", ok_case, "snapshot-etcd-s3.yml",
           "Refuse a reused confirmation or an unsafe ledger", written=True, saved=3, confirm=reuse)
    r = behave("restart: success after configuration", ok_case, "restart-etcd-s3.yml", False, written=True, stage3=True)
    check("behavior", "restart: exactly one restart", (ok_case["dir"] / "restart-calls").exists()
          and (ok_case["dir"] / "restart-calls").read_text() == "restart\n")
    behave("validate: configured state passes, enforced", ok_case, "validate-etcd-s3.yml", False, written=True,
           extra={"etcd_s3_enforce": True}, stage3=False)
    behave("validate: integrity expectation fails closed", ok_case, "validate-etcd-s3.yml", G_INT, written=True,
           extra={"etcd_s3_expect_integrity": True})
    behave("validate: uploading expected without a scheduled upload fails", ok_case, "validate-etcd-s3.yml", "Require the expected Stage 4 state",
           written=True, extra={"etcd_s3_enforce": True, "etcd_s3_expect": "uploading"})
    fresh = new_case()
    behave("preflight: a server ready for its first configuration passes, enforced", fresh, "preflight-etcd-s3.yml", False,
           extra={"etcd_s3_enforce": True})
    behave("preflight: a configured server is not ready for a first configuration", ok_case, "preflight-etcd-s3.yml",
           "Require a server ready for its first configuration", written=True, extra={"etcd_s3_enforce": True})

    # ---- output modes (refused by the guard before any credential is read)
    c = new_case()
    behave("refused: -v", c, CONF, G_MODE, args=("-v",), saved=0, stage3=False)
    behave("refused: --check", c, CONF, G_MODE, args=("--check",), saved=0, stage3=False)
    behave("refused: --diff", c, CONF, G_MODE, args=("--diff",), saved=0, stage3=False)
    behave("refused: ANSIBLE_DEBUG", c, CONF, True, env_over={"ANSIBLE_DEBUG": "1"}, saved=0, stage3=False)
    behave("refused: ANSIBLE_KEEP_REMOTE_FILES", c, CONF, G_MODE, env_over={"ANSIBLE_KEEP_REMOTE_FILES": "1"}, saved=0, stage3=False)
    behave("refused: a log path", c, CONF, G_MODE, env_over={"ANSIBLE_LOG_PATH": str(c["dir"] / "ansible.log")}, saved=0, stage3=False)
    behave("refused: displayed task arguments", c, CONF, G_CFG, env_over={"ANSIBLE_DISPLAY_ARGS_TO_STDOUT": "True"}, saved=0, stage3=False)
    behave("refused: an extra callback", c, CONF, G_MODE, env_over={"ANSIBLE_CALLBACKS_ENABLED": "ansible.builtin.junit",
                                                                    "JUNIT_OUTPUT_DIR": str(c["dir"] / "junit")}, saved=0, stage3=False)
    behave("refused: another stdout callback", c, CONF, True, env_over={"ANSIBLE_STDOUT_CALLBACK": "minimal"}, saved=0, stage3=False)

    # ---- targeting, confirmation, environment
    behave("refused: no limit", c, CONF, G_LIM, limit=None, confirm="configure:s4t01:" + now_id(), saved=0, stage3=False)
    behave("refused: a group limit", c, CONF, G_LIM, limit="servers", confirm="configure:s4t01:" + now_id(), saved=0, stage3=False)
    behave("refused: two hosts", c, CONF, G_LIM, limit="s4t01,s4t02", confirm="configure:s4t01:" + now_id(), saved=0, stage3=False)
    behave("refused: a regex resolving to one host", c, CONF, G_LIM, limit="~s4t01$", confirm="configure:s4t01:" + now_id(), saved=0, stage3=False)
    behave("refused: an exclusion resolving to one host", c, CONF, G_LIM, limit="servers:!s4t02:!s4t03", confirm="configure:s4t01:" + now_id(),
           saved=0, stage3=False)
    behave("refused: no confirmation", c, CONF, G_CONF, confirm=False, saved=0, stage3=False)
    behave("refused: a stale confirmation", c, CONF, G_CONF, confirm="configure:s4t01:" + now_id(-45), saved=0, stage3=False)
    behave("refused: a confirmation for another phase", c, CONF, G_CONF, confirm="restart:s4t01:" + now_id(), saved=0, stage3=False)
    behave("refused: a confirmation for another host", c, CONF, G_CONF, confirm="configure:s4t02:" + now_id(), saved=0, stage3=False)
    behave("refused: no environment", c, CONF, G_ENV, extra={"etcd_s3_environment": None}, saved=0, stage3=False)
    behave("refused: live declared for a rehearsal inventory", c, CONF, G_ENV, environment="live", saved=0, stage3=False)
    live = new_case(hosts=("k3s01", "k3s02", "k3s03"))
    behave("refused: rehearsal declared for the live host names", live, CONF, G_ENV, limit="k3s01", saved=0, stage3=False)
    behave("refused: a rehearsal endpoint with the live host names", live, CONF, G_REH, limit="k3s01", environment="live",
           extra={"etcd_s3_rehearsal_endpoint": "minio.rehearsal.test:9000"}, saved=0, stage3=False)
    mixed = new_case(hosts=("s4t01", "s4t02", "k3s03"))
    behave("refused: a rehearsal inventory containing a live host name", mixed, CONF, G_ENV, saved=0, stage3=False)
    behave("refused: a malformed rehearsal endpoint", c, CONF, G_REH, extra={"etcd_s3_rehearsal_endpoint": "http://x/"}, saved=0, stage3=False)

    # ---- committed values, reserved and unknown names, phase injection
    for label, ev in (("a per-node folder", {"etcd_s3_folder": "etcd/s4t01"}), ("compression on", {"etcd_s3_compress": True}),
                      ("S3 retention 15", {"etcd_s3_s3_retention": 15}), ("the default base", {"etcd_s3_scheduled_base_prefix": "etcd-snapshot-"}),
                      ("an approved integrity method", {"etcd_s3_integrity_approved_methods": ["etag"]})):
        behave(f"refused: override of {label}", c, CONF, G_FIX, extra=ev, saved=0, stage3=False)
    for label, ev in (("the secret key as an extra var", {"etcd_s3_secret_key": SECRET}),
                      ("the access key as an extra var", {"etcd_s3_access_key": KEY_ID}),
                      ("the bucket as an extra var", {"etcd_s3_bucket": BUCKET}),
                      ("injected credentials", {"etcd_s3_credentials": {"secret_key": SECRET}}),
                      ("a default on-demand name", {"etcd_s3_ondemand_name": "on-demand"}),
                      ("the Stage 3 expectation", {"secrets_encryption_expect": "fresh-enabled"})):
        behave(f"refused: {label}", c, CONF, G_RES, extra=ev, saved=0, stage3=False)
    behave("refused: an unknown etcd_s3_ variable (an injected check result)", c, CONF, G_UNK, extra={"etcd_s3_confirm_ok": True}, saved=0, stage3=False)
    behave("refused: an injected task variable", c, CONF, G_UNK, extra={"es_safe": True}, saved=0, stage3=False)
    behave("refused: phase injection", c, CONF, G_BIND, extra={"etcd_s3_phase": "validate"}, saved=0, stage3=False)
    overlap = new_case(hosts=("node1", "node10", "node2"))
    behave("refused: host names whose bases overlap", overlap, CONF, G_OVL, limit="node1", saved=0, stage3=False)

    # ---- the D5 Stage 3 gate
    behave("refused: the Stage 3 enabled validation fails", c, CONF, S3G, env_over={"S4T_STAGE3_FAIL": "1"}, saved=0, stage3=True)

    # ---- credential sources (each refusal displays nothing)
    for label, kw, task in (
            ("a key file readable by others", {"key_mode": 0o644}, C_FILE),
            ("a key file not on tmpfs", {"key_on_tmpfs": False}, C_FILE),
            ("a key file that is a link", {"key_link": True}, C_FILE),
            ("a key directory open to others", {"key_dir_mode": 0o755}, C_FILE),
            ("a bucket file readable by others", {"bucket_mode": 0o644}, C_FILE),
            ("a malformed key file holding the sentinels", {"key_doc": "{not json " + SECRET + " " + KEY_ID + "}"}, C_EXT),
            ("a key file without the JSON shape", {"key_doc": "AccessKeyId=" + KEY_ID + "\nSecret=" + SECRET}, C_KEY),
            ("an inactive key", {"key_doc": {"AccessKey": {"UserName": "home-cluster-etcd-backup", "AccessKeyId": KEY_ID, "Status": "Inactive",
                                                           "SecretAccessKey": SECRET}}}, C_KEY),
            ("a key for another identity", {"key_doc": {"AccessKey": {"UserName": "home-cluster-velero", "AccessKeyId": KEY_ID, "Status": "Active",
                                                                      "SecretAccessKey": SECRET}}}, C_KEY),
            ("a malformed secret", {"key_doc": {"AccessKey": {"UserName": "home-cluster-etcd-backup", "AccessKeyId": KEY_ID, "Status": "Active",
                                                              "SecretAccessKey": SECRET[:20]}}}, C_KEY),
            ("a bucket outside the pattern", {"bucket_text": "my-bucket"}, C_KEY)):
        behave(f"refused: {label}", new_case(**kw), CONF, task, saved=0, stage3=True)
    behave("refused: the key file variable unset", c, CONF, C_PATH, env_drop=("HOMELAB_ETCD_S3_KEY_FILE",), saved=0, stage3=True)
    behave("refused: a relative key file path", c, CONF, C_PATH, env_over={"HOMELAB_ETCD_S3_KEY_FILE": "etcd-key.json"}, saved=0, stage3=True)

    # ---- node state before the write
    behave("refused: an existing local file with a new base before the first configuration",
           new_case(preexisting=("on-demand-s4-s4t01-s4t01-1",)), CONF, "Require no file with a new base before the first configuration", saved=0)
    behave("refused: a drop-in that is a link", new_case(dropin_link=True), CONF, "Require no Stage 4 setting outside the drop-in", saved=0)
    behave("refused: an S3 setting in config.yaml", new_case(config={"etcd-s3": True}), CONF, "Require no Stage 4 setting outside the drop-in", saved=0)
    behave("refused: a snapshot name in config.yaml", new_case(config={"etcd-snapshot-name": "etcd-snapshot"}), CONF,
           "Require no Stage 4 setting outside the drop-in", saved=0)
    behave("refused: AWS variables in the K3s environment", new_case(env_proc={"AWS_ACCESS_KEY_ID": "x"}), CONF,
           "Require the Stage 4 preconditions on this server", saved=0)
    behave("refused: a node name that is not the inventory host name", new_case(hosts=("s4t01", "s4t02", "s4t03")), CONF,
           "Require the Stage 4 preconditions on this server", limit="s4t02", saved=0)

    # ---- failures after the write: nothing displayed
    behave("failure: a failed save displays no bucket", new_case(save_fail=True), CONF, "Require a successful save", written=True, saved=1)
    behave("failure: a save without a ready record", new_case(no_record=True), CONF, "Require the uploaded on-demand snapshot", written=True, saved=1,
           extra={"etcd_s3_record_retries": 1, "etcd_s3_record_delay_seconds": 1})
    behave("failure: the secret in the K3s journal is counted, not displayed", new_case(journal="error " + SECRET + "\n"), CONF,
           "Require no credential outside the drop-in", written=True, saved=1)
    behave("failure: a key-shaped string in the records is counted, not displayed",
           new_case(records=[{"spec": {"snapshotName": "x", "nodeName": "s4t01"}, "status": {}, "metadata": {"labels": {"k": KEY_ID}}}]), CONF,
           "Require no credential outside the drop-in", written=True, saved=1)
    behave("failure: the secret in the K3s process environment is counted, not displayed",
           new_case(env_proc={"K3S_LEAK": SECRET}), CONF, "Require no credential outside the drop-in", written=True, saved=1)

    # ---- the restart and snapshot playbooks refuse an unapproved drop-in before acting
    bad = new_case(dropin=dict(dropin_doc(), **{"etcd-snapshot-name": "etcd-snapshot"}))
    behave("refused: a restart with a default snapshot name, before the restart", bad, "restart-etcd-s3.yml",
           "Require the approved Stage 4 configuration", written=True, stage3=True)
    check("behavior", "refused restart: no restart happened", not (bad["dir"] / "restart-calls").exists())
    behave("refused: a save with a default snapshot name, before the save", bad, "snapshot-etcd-s3.yml",
           "Require the approved Stage 4 configuration", written=True, saved=0)
    behave("refused: a restart without a drop-in", new_case(), "restart-etcd-s3.yml", "Require the approved Stage 4 configuration", saved=0)

for pid in children + [int(x) for p in tmp_root.glob("case-*/children") for x in p.read_text().split()]:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGTERM)
shutil.rmtree(tmp_root, ignore_errors=True)
shutil.rmtree(NON_TMPFS, ignore_errors=True)
for p in pathlib.Path(TMPFS or "/nonexistent").glob("s4key-*"):
    shutil.rmtree(p, ignore_errors=True)

n_struct, n_mut = len(STRUCTURE), len(MUTANTS)
print(f"Stage 4 checks: {n_struct} structure, {n_mut} structural mutants; {len(failures)} failed")
sys.exit(1 if failures else 0)
