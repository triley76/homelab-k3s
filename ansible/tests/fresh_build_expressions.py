"""Structure, behavior and mutation tests for the fresh-build secrets-encryption setting.

Contacts no cluster node, VM, Kubernetes API, etcd or AWS, and downloads nothing.

1. Structure: the setting is committed once, as a real boolean, in
   group_vars/servers.yml, and the k3s-server role has no default for it; the
   role's guards run before any filesystem or installation task; the fresh-join
   check reads the first server's drop-in by metadata only; installed servers
   keep their protections (no drop-in write or removal, restart or handler); the
   K3s initialization and join plays set any_errors_fatal; no live-cluster
   playbook or secrets-encryption role file reads the setting.
2. Behavior: the real k3s-server tasks, up to and including the drop-in, run on
   three local stand-in servers (ansible_connection=local, temporary paths),
   for every case: missing, non-boolean, one-host overrides, false with and
   without the acknowledgement, false in init mode, a first-server drop-in that
   does not match, installed binary or data, and refusals that stop the play
   sequence. A refused case must name the refusing task and change nothing.
3. Mutation: role mutants (each guard weakened in a copy of the task list) must
   change the outcome of the case that targets them, and structural mutants
   (committed value, defaults, plays, live playbooks, documentation) must fail
   the structure predicates. A surviving mutant fails the suite.
4. Documentation: the Fresh Builds section, the restore steps and their drop-in
   states, the failed-reset rule, the install-without-start prerequisite and
   the README status.

Usage (requires ansible-core and PyYAML):
    python3 ansible/tests/fresh_build_expressions.py
"""
import copy
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

import yaml

repo = pathlib.Path(__file__).resolve().parents[2]
ans = repo / "ansible"
ks_role = ans / "roles/k3s-server"
se_role = ans / "roles/secrets-encryption"


def load(p):
    return yaml.safe_load(pathlib.Path(p).read_text())


group_vars_text = (ans / "group_vars/servers.yml").read_text()
group_vars = yaml.safe_load(group_vars_text)
ks_defaults = load(ks_role / "defaults/main.yml")
ks_vars = load(ks_role / "vars/main.yml")
ks_tasks_text = (ks_role / "tasks/main.yml").read_text()
ks_tasks = yaml.safe_load(ks_tasks_text)
se_vars = load(se_role / "vars/main.yml")
se_dropin = load(se_role / "tasks/dropin.yml")
BUILD_BOOKS = ("site.yml", "init-first-server.yml", "join-servers.yml")
books = {name: load(ans / name) for name in BUILD_BOOKS}
other_texts = {p.name: p.read_text() for p in sorted(ans.glob("*.yml")) if p.name not in BUILD_BOOKS}
other_texts.update({f"secrets-encryption/{p.relative_to(se_role)}": p.read_text() for p in sorted(se_role.rglob("*.yml"))})
DOC = (repo / "docs/secrets-encryption.md").read_text()
README = (repo / "README.md").read_text()

G1 = "Require a boolean encryption setting, identical on all servers"
G2 = "Permit no encryption only for a pre-encryption restore rebuild"
JSTAT = "Check the first server's encryption drop-in before a fresh join"
JREQ = "Require the first server's drop-in to match this fresh join"
CONFDIR = "Ensure k3s configuration directory exists"
DROPIN = "Install the secrets-encryption drop-in before K3s first starts"
FRESH = ["not k3s_server_binary.stat.exists", "not k3s_server_data.stat.exists"]
ACK = "pre-encryption-restore"

failures = []


def check(kind, label, ok):
    print(f"{'PASS' if ok else 'FAIL'}  {kind}: {label}", flush=True)
    if not ok:
        failures.append(f"{kind}: {label}")


def module_of(t):
    keys = [k for k in t if k.startswith("ansible.builtin.")]
    return keys[0] if keys else None


def named(tasks, name):
    return next((t for t in tasks if t.get("name") == name), None)


def index_of(tasks, name):
    return next((i for i, t in enumerate(tasks) if t.get("name") == name), None)


# ====================================================================== structure predicates
def committed_setting_ok(gv, gv_text, defaults):
    """Exactly one committed value, a real boolean true, and no role default."""
    return (gv == {"k3s_secrets_encryption_enabled": True} and gv["k3s_secrets_encryption_enabled"] is True
            and len(re.findall(r"^k3s_secrets_encryption_enabled:", gv_text, re.MULTILINE)) == 1
            and not defaults)


def guards_first(tasks):
    """The mode check and both setting guards precede every other task; their conditions are complete."""
    g1, g2 = named(tasks, G1), named(tasks, G2)
    if g1 is None or g2 is None:
        return False
    first_other = min(i for i, t in enumerate(tasks) if t.get("name") not in ("Validate k3s role mode", G1, G2))
    g1_that = " ".join(" ".join(g1["ansible.builtin.assert"]["that"]).split())
    values = " ".join(str(g1.get("vars", {}).get("k3s_server_secrets_encryption_values", "")).split())
    g2_that = " ".join(" ".join(g2["ansible.builtin.assert"]["that"]).split())
    return (max(index_of(tasks, G1), index_of(tasks, G2), index_of(tasks, "Validate k3s role mode")) < first_other
            and module_of(g1) == module_of(g2) == "ansible.builtin.assert"
            and "k3s_secrets_encryption_enabled is defined" in g1_that and "k3s_secrets_encryption_enabled is boolean" in g1_that
            and "k3s_server_secrets_encryption_values | reject('boolean') | list | length == 0" in g1_that
            and "k3s_server_secrets_encryption_values | unique | list == [k3s_secrets_encryption_enabled]" in g1_that
            and "groups['servers'] | map('extract', hostvars)" in values
            and "map(attribute='k3s_secrets_encryption_enabled', default=none)" in values
            and g2_that == ("k3s_secrets_encryption_enabled or (k3s_mode == 'join' and "
                            "(k3s_pre_encryption_restore_ack | default('')) == 'pre-encryption-restore')"))


def join_check_metadata_only(tasks, vars_, se_vars_):
    """The fresh-join check stats the first server's drop-in by metadata only, before any change, and requires a match."""
    st, rq = named(tasks, JSTAT), named(tasks, JREQ)
    if st is None or rq is None:
        return False
    when = ["k3s_mode == 'join'"] + FRESH
    stat = st.get("ansible.builtin.stat", {})
    reads = [t for t in tasks if module_of(t) in ("ansible.builtin.slurp", "ansible.builtin.fetch", "ansible.builtin.command",
                                                   "ansible.builtin.shell", "ansible.builtin.lineinfile")
             and "secrets_encryption_dropin_path" in json.dumps(t)]
    return (stat == {"path": "{{ k3s_server_secrets_encryption_dropin_path }}", "get_checksum": False, "get_mime": False,
                     "get_attributes": False}
            and st.get("delegate_to") == "{{ groups['servers'][0] }}" and st.get("when") == when and rq.get("when") == when
            and rq["ansible.builtin.assert"]["that"][0] == "k3s_first_server_dropin.stat.exists == k3s_secrets_encryption_enabled"
            and "k3s_first_server_dropin.stat.isreg and not k3s_first_server_dropin.stat.islnk" in " ".join(rq["ansible.builtin.assert"]["that"][1].split())
            and vars_.get("k3s_server_secrets_encryption_dropin_path") == se_vars_["secrets_encryption_dropin_path"]
            and index_of(tasks, "Check for existing k3s data") < index_of(tasks, JSTAT) < index_of(tasks, JREQ)
            < index_of(tasks, CONFDIR) < index_of(tasks, DROPIN)
            and not reads)


def installed_protected(tasks, role_dir):
    """The drop-in only on a fresh server, never removed, no restart and no handler."""
    inc = named(tasks, DROPIN)
    restart_modules = ("ansible.builtin.systemd_service", "ansible.builtin.systemd", "ansible.builtin.service")
    return (inc is not None and inc.get("when") == ["k3s_secrets_encryption_enabled | bool"] + FRESH
            and inc.get("vars") == {"secrets_encryption_dropin_state": "present"}
            and not any(t.get("vars", {}).get("secrets_encryption_dropin_state") == "absent" or module_of(t) in restart_modules
                        or "notify" in t for t in tasks)
            and not (role_dir / "handlers").exists())


def build_plays_fatal(books_):
    """Every play that runs k3s-server sets any_errors_fatal; init targets servers[0], join servers[1:] serially."""
    found = []
    for name, plays in books_.items():
        for p in plays:
            if "k3s-server" in (p.get("roles") or []):
                found.append((name, p))
    return (len(found) == 4 and all(p.get("any_errors_fatal") is True for _, p in found)
            and all((p["vars"]["k3s_mode"], p["hosts"]) in (("init", "servers[0]"), ("join", "servers[1:]")) for _, p in found)
            and all(p.get("serial") == 1 for _, p in found if p["vars"]["k3s_mode"] == "join"))


def live_paths_clean(texts):
    """No live-cluster playbook or secrets-encryption role file reads the setting, the acknowledgement or k3s-server."""
    return not any(re.search(r"k3s_secrets_encryption_enabled|k3s_pre_encryption_restore_ack|\bk3s-server\b", t) for t in texts.values())


def section(doc, start, end):
    i = doc.find(start)
    j = doc.find(end, i + len(start)) if i >= 0 else -1
    return doc[i:j] if i >= 0 and j > i else ""


FRESH_SECTION = ("## Fresh Builds and Replacement Joins", "## Rehearsals")
RESTORE_STEPS = ("### Restore procedure (manual, separately approved)", "#### Accepting the reset")
ENC_FILES = ("#### Encryption files during a restore", "### Restore in the k3d rehearsal")
COMPLETE_CLAIM = re.compile(r"fresh-build (setting|secrets encryption|prerequisite)[^.\n]{0,40}\b(is |was )?(complete|completed|done|resolved|rehearsed)\b"
                            r"|template flip|template-flip|enabled by default", re.I)


def table_row(text, first_cell):
    return next((line for line in text.splitlines() if line.startswith(f"| {first_cell} |")), "")


def docs_ok(doc, readme):
    fresh, steps, enc = section(doc, *FRESH_SECTION), section(doc, *RESTORE_STEPS), section(doc, *ENC_FILES)
    p0 = table_row(fresh, "A pre-encryption snapshot (p0) on the existing servers")
    post = table_row(fresh, "A post-encryption snapshot onto rebuilt servers (every server lost)")
    step3 = next((l for l in steps.splitlines() if l.startswith("3. ")), "")
    step7 = next((l for l in steps.splitlines() if l.startswith("7. ")), "")
    return (
        fresh != "" and steps != "" and enc != ""
        and "**Status: implementation present; three-VM fresh-build rehearsal pending.**" in fresh
        and "**enabled explicitly for the committed servers group**" in fresh
        and "implementation present; three-VM fresh-build rehearsal pending" in readme
        and "enabled explicitly for the committed servers group" in readme
        and "the fresh-build setting: implementation present, three-VM fresh-build rehearsal pending" in doc
        and not COMPLETE_CLAIM.search(doc) and not COMPLETE_CLAIM.search(readme)
        and "move the secrets-encryption drop-in out of `config.yaml.d`" in step3
        and "with the drop-in absent: `-e k3s_secrets_encryption_enabled=false -e k3s_pre_encryption_restore_ack=pre-encryption-restore`" in step7
        and "k3s_secrets_encryption_enabled: false" not in step7
        and "**Absent** on every server" in p0 and "explicit `false` plus the acknowledgement" in p0 and "**Present**" not in p0
        and "The token in use at p0" in p0
        and "**Present** on the reset server before it first starts, and on every server that joins it" in post and "**Absent**" not in post
        and "The token in use when the snapshot was taken, by `--token-file`" in post
        and "After a **failed** reset, the random key K3s generated stays on disk and is moved aside before any retry" in post
        and "**A failed reset on a freshly built server.**" in enc and "It is moved aside (preserved) before any retry" in enc
        and "**An unresolved prerequisite: installing without starting.**" in fresh
        and "It is an explicit prerequisite for Stage 4's isolated restore rehearsal (S4-4)." in fresh
        and "That capability does not exist yet." in fresh
        and "`validate-secrets-encryption.yml -e secrets_encryption_expect=fresh-enabled` (read-only)" in fresh
        and "The Stage 3 `enabled` expectation is unchanged" in fresh)


STRUCTURE = (
    ("group_vars/servers.yml commits exactly one real boolean true; the role has no default",
     lambda: committed_setting_ok(group_vars, group_vars_text, ks_defaults)),
    ("the mode check and both setting guards run before any filesystem or installation task, with complete conditions",
     lambda: guards_first(ks_tasks)),
    ("the fresh-join check reads the first server's drop-in by metadata only, before any change, and requires a match",
     lambda: join_check_metadata_only(ks_tasks, ks_vars, se_vars)),
    ("installed servers: no drop-in write or removal, restart or handler",
     lambda: installed_protected(ks_tasks, ks_role)),
    ("every K3s initialization and join play sets any_errors_fatal (init servers[0]; join servers[1:], serial 1)",
     lambda: build_plays_fatal(books)),
    ("no live-cluster playbook or secrets-encryption role file reads the setting, the acknowledgement or k3s-server",
     lambda: live_paths_clean(other_texts)),
    ("docs: Fresh Builds section, restore drop-in states, failed reset, install-without-start prerequisite, README status",
     lambda: docs_ok(DOC, README)),
)
for label, fn in STRUCTURE:
    check("structure", label, fn())


def without_key(d, key):
    d = copy.deepcopy(d)
    d.pop(key, None)
    return d


def tasks_edit(fn):
    t = copy.deepcopy(ks_tasks)
    fn(t)
    return t


def set_in(name, fn):
    return lambda tasks: fn(named(tasks, name))


def move_before_guards(name):
    def edit(tasks):
        t = tasks.pop(index_of(tasks, name))
        tasks.insert(1, t)
    return edit


def books_edit(book, play_name, fn):
    b = copy.deepcopy(books)
    fn(next(p for p in b[book] if p["name"] == play_name))
    return b


DOC_SWAP = DOC.replace("| **Absent** on every server: moved aside", "| **Present** on every server: kept")
STRUCTURAL_MUTANTS = (
    ("committed value false", lambda: committed_setting_ok({"k3s_secrets_encryption_enabled": False}, group_vars_text, ks_defaults)),
    ("committed value the string 'true'", lambda: committed_setting_ok({"k3s_secrets_encryption_enabled": "true"}, group_vars_text, ks_defaults)),
    ("committed value removed", lambda: committed_setting_ok({}, "", ks_defaults)),
    ("a role default reintroduced", lambda: committed_setting_ok(group_vars, group_vars_text, {"k3s_secrets_encryption_enabled": True})),
    ("the configuration directory created before the guards", lambda: guards_first(tasks_edit(move_before_guards(CONFDIR)))),
    ("the binary check before the guards", lambda: guards_first(tasks_edit(move_before_guards("Check for an existing k3s binary")))),
    ("the boolean check dropped", lambda: guards_first(tasks_edit(set_in(G1, lambda t: t["ansible.builtin.assert"]["that"].remove(
        "k3s_secrets_encryption_enabled is boolean"))))),
    ("the acknowledgement dropped from the false rule", lambda: guards_first(tasks_edit(set_in(G2, lambda t: t["ansible.builtin.assert"].update(
        that=["k3s_secrets_encryption_enabled or k3s_mode == 'join'"]))))),
    ("the first server's drop-in read with a checksum", lambda: join_check_metadata_only(
        tasks_edit(set_in(JSTAT, lambda t: t["ansible.builtin.stat"].update(get_checksum=True))), ks_vars, se_vars)),
    ("the first server's drop-in read by slurp", lambda: join_check_metadata_only(tasks_edit(lambda ts: ts.insert(
        index_of(ts, JREQ), {"name": "read it", "ansible.builtin.slurp": {"src": "{{ secrets_encryption_dropin_path }}"}})), ks_vars, se_vars)),
    ("the fresh-join check on the joining server instead of the first", lambda: join_check_metadata_only(
        tasks_edit(set_in(JSTAT, lambda t: t.pop("delegate_to"))), ks_vars, se_vars)),
    ("the fresh-join check after the configuration directory", lambda: join_check_metadata_only(
        tasks_edit(lambda ts: ts.insert(index_of(ts, JSTAT), ts.pop(index_of(ts, CONFDIR)))), ks_vars, se_vars)),
    ("the drop-in on installed servers too", lambda: installed_protected(
        tasks_edit(set_in(DROPIN, lambda t: t.update(when=["k3s_secrets_encryption_enabled | bool"]))), ks_role)),
    ("a K3s restart added", lambda: installed_protected(tasks_edit(lambda ts: ts.append(
        {"name": "restart", "ansible.builtin.systemd_service": {"name": "k3s", "state": "restarted"}})), ks_role)),
    ("a handler notified", lambda: installed_protected(tasks_edit(set_in(CONFDIR, lambda t: t.update(notify="restart k3s"))), ks_role)),
    ("any_errors_fatal removed from the site.yml init play", lambda: build_plays_fatal(
        books_edit("site.yml", "Initialize first k3s server", lambda p: p.pop("any_errors_fatal")))),
    ("any_errors_fatal removed from the join-servers.yml join play", lambda: build_plays_fatal(
        books_edit("join-servers.yml", "Join additional k3s servers", lambda p: p.pop("any_errors_fatal")))),
    ("a live playbook reads the setting", lambda: live_paths_clean(dict(other_texts, **{
        "secrets-encryption-restart.yml": other_texts["secrets-encryption-restart.yml"] + "\n# k3s_secrets_encryption_enabled\n"}))),
    ("docs: p0 restore keeps the drop-in present", lambda: docs_ok(DOC_SWAP, README)),
    ("docs: post-encryption restore with the drop-in absent", lambda: docs_ok(DOC.replace(
        "| **Present** on the reset server before it first starts", "| **Absent** on the reset server before it first starts"), README)),
    ("docs: rebuilt p0 peer back to the old setting without the acknowledgement", lambda: docs_ok(DOC.replace(
        "with the drop-in absent: `-e k3s_secrets_encryption_enabled=false -e k3s_pre_encryption_restore_ack=pre-encryption-restore`",
        "(`k3s_secrets_encryption_enabled: false`"), README)),
    ("docs: post-encryption restore without the snapshot's token", lambda: docs_ok(DOC.replace(
        "The token in use when the snapshot was taken, by `--token-file`", "Any current token"), README)),
    ("docs: failed reset rule removed", lambda: docs_ok(DOC.replace(
        "After a **failed** reset, the random key K3s generated stays on disk and is moved aside before any retry", "A failed reset is retried"),
        README)),
    ("docs: install-without-start no longer an unresolved prerequisite", lambda: docs_ok(DOC.replace(
        "That capability does not exist yet.", "That capability exists."), README)),
    ("docs: 'enabled by default'", lambda: docs_ok(DOC.replace("**enabled explicitly for the committed servers group**",
                                                                "**enabled explicitly for the committed servers group** (enabled by default)"), README)),
    ("docs: README claims the prerequisite complete", lambda: docs_ok(DOC, README.replace(
        "implementation present; three-VM fresh-build rehearsal pending", "implementation present; three-VM fresh-build rehearsal pending. "
        "The fresh-build setting is complete"))),
)
for label, fn in STRUCTURAL_MUTANTS:
    check("structural mutant killed", label, not fn())

# ====================================================================== behavior
tmp_root = pathlib.Path(tempfile.mkdtemp(prefix="fresh-build-test."))
env = dict(os.environ)
cfg = tmp_root / "ansible.cfg"
cfg.write_text("[defaults]\nretry_files_enabled = False\ninterpreter_python = auto_silent\nhost_key_checking = False\n")
env.update(ANSIBLE_CONFIG=str(cfg), ANSIBLE_NOCOLOR="1")
SERVERS = ("k3s01", "k3s02", "k3s03")
UNSET = object()

# The real dropin.yml, unprivileged and with an absolute template path.
dropin_copy = copy.deepcopy(se_dropin)
for t in dropin_copy:
    for m in ("ansible.builtin.file", "ansible.builtin.template"):
        if m in t:
            t[m].pop("owner", None)
            t[m].pop("group", None)
    if "ansible.builtin.template" in t:
        t["ansible.builtin.template"]["src"] = str(se_role / "templates/secrets-encryption.yaml.j2")
dropin_file = tmp_root / "dropin-tasks.yml"
dropin_file.write_text(yaml.safe_dump(dropin_copy, sort_keys=False, width=200))


def runnable(tasks):
    """The real tasks up to and including the drop-in, unprivileged; then a marker for reaching the installation."""
    out = []
    for t in copy.deepcopy(tasks):
        if t.get("name") == CONFDIR:
            t["ansible.builtin.file"]["path"] = "{{ k3s_test_config_dir }}"
            t["ansible.builtin.file"].pop("owner", None)
            t["ansible.builtin.file"].pop("group", None)
        if t.get("name") == DROPIN:
            t = {"name": t["name"], "ansible.builtin.include_tasks": str(dropin_file), "vars": t["vars"], "when": t["when"]}
        out.append(t)
        if t.get("name") == DROPIN:
            break
    return out + [{"name": "Reached the installation", "ansible.builtin.copy": {"content": "reached\n", "dest": "{{ k3s_test_marker }}"}}]


def header(book, play_name):
    p = copy.deepcopy(next(p for p in books[book] if p["name"] == play_name))
    p.pop("roles")
    p.pop("become", None)
    p["gather_facts"] = False
    return p


INIT = ("site.yml", "Initialize first k3s server")
JOIN = ("site.yml", "Join additional k3s servers")
TASK_RE = re.compile(r"^TASK \[(.+?)\] \*+$")


def failed_task(stdout):
    current = None
    for line in stdout.splitlines():
        m = TASK_RE.match(line)
        if m:
            current = m.group(1)
        elif line.startswith("fatal: ["):
            return current
    return None


def run_case(label, plays_spec, setting=True, host_settings=None, extra=None, first_dropin=None, installed=None, tasks=None,
             expect_fail=None, written=(), reached=None, invert=False, kind="behavior"):
    """plays_spec: [(header, limit-or-None)]. setting: the servers group value (UNSET for none). host_settings: per-host values.
    first_dropin: None, 'file' or 'link' on k3s01. installed: {host: 'binary'|'data'}. written: hosts whose drop-in must exist
    afterwards (besides a pre-created k3s01 one). reached: hosts that must reach the installation (default: none if refused,
    the targeted hosts otherwise)."""
    d = tmp_root / f"case-{len(list(tmp_root.glob('case-*')))}"
    hostvars = {}
    for h in SERVERS:
        hd = d / h
        hd.mkdir(parents=True)
        hostvars[h] = {"k3s_server_binary_path": str(hd / "k3s"), "k3s_server_data_dir": str(hd / "data"),
                       "secrets_encryption_dropin_path": str(hd / "config.yaml.d/20-secrets-encryption.yaml"),
                       "k3s_test_config_dir": str(hd / "etc"), "k3s_test_marker": str(hd / "reached")}
        if host_settings and h in host_settings:
            hostvars[h]["k3s_secrets_encryption_enabled"] = host_settings[h]
    for h, what in (installed or {}).items():
        (d / h / "data").mkdir() if what == "data" else (d / h / "k3s").write_text("binary")
    first = pathlib.Path(hostvars["k3s01"]["secrets_encryption_dropin_path"])
    if first_dropin:
        first.parent.mkdir(parents=True)
        if first_dropin == "file":
            first.write_text("secrets-encryption: true\n")
        else:
            (first.parent / "elsewhere.yaml").write_text("x\n")
            first.symlink_to(first.parent / "elsewhere.yaml")
    group = {"k3s_server_secrets_encryption_dropin_path": str(first), "secrets_encryption_provider": se_vars["secrets_encryption_provider"]}
    if setting is not UNSET:
        group["k3s_secrets_encryption_enabled"] = setting
    inventory = {"all": {"vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable},
                         "children": {"servers": {"hosts": hostvars, "vars": group}}}}
    inv = d / "inventory.yml"
    inv.write_text(yaml.safe_dump(inventory, sort_keys=False))
    body = runnable(tasks if tasks is not None else ks_tasks)
    plays = []
    targeted = []
    for (book, name), limit in plays_spec:
        p = header(book, name)
        if limit:
            p["hosts"] = limit
        p["tasks"] = copy.deepcopy(body)
        plays.append(p)
        targeted += [limit] if limit else (["k3s01"] if p["hosts"] == "servers[0]" else ["k3s02", "k3s03"])
    book_path = d / "play.yml"
    book_path.write_text(yaml.safe_dump(plays, sort_keys=False, width=200))
    cmd = ["ansible-playbook", "-i", str(inv), str(book_path)]
    if extra:
        cmd += ["-e", json.dumps(extra)]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    got_fail = failed_task(r.stdout) if r.returncode != 0 else None
    exists = {h: pathlib.Path(hostvars[h]["secrets_encryption_dropin_path"]).exists() for h in SERVERS}
    confdirs = {h: pathlib.Path(hostvars[h]["k3s_test_config_dir"]).exists() for h in SERVERS}
    markers = {h: pathlib.Path(hostvars[h]["k3s_test_marker"]).exists() for h in SERVERS}
    if reached is None:
        reached = () if expect_fail else tuple(targeted)
    expect_dropins = {h: (h in written) or (h == "k3s01" and first_dropin is not None) for h in SERVERS}
    ok = ((r.returncode != 0) == bool(expect_fail) and got_fail == expect_fail and exists == expect_dropins
          and markers == {h: h in reached for h in SERVERS}
          and (not expect_fail or not any(confdirs[h] for h in SERVERS if h not in reached)))
    if invert:
        ok = not ok
    check(kind, label, ok)
    if not ok and not invert:
        print(f"   expected fail={expect_fail!r} got={got_fail!r} rc={r.returncode} dropins={exists} markers={markers} confdirs={confdirs}",
              flush=True)
        print("\n".join(r.stdout.splitlines()[-40:]), r.stderr[-1500:], sep="\n", flush=True)
    return ok


K1, K2 = "k3s01", "k3s02"
CASES = {
    "missing": dict(plays_spec=[(INIT, None)], setting=UNSET, expect_fail=G1),
    "string-true": dict(plays_spec=[(INIT, None)], setting=UNSET, extra={"k3s_secrets_encryption_enabled": "true"}, expect_fail=G1),
    "string-false": dict(plays_spec=[(JOIN, K2)], setting=UNSET, extra={"k3s_secrets_encryption_enabled": "false",
                                                                         "k3s_pre_encryption_restore_ack": ACK}, expect_fail=G1),
    "integer": dict(plays_spec=[(INIT, None)], setting=UNSET, extra={"k3s_secrets_encryption_enabled": 1}, expect_fail=G1),
    "one-host-false": dict(plays_spec=[(INIT, None)], host_settings={"k3s02": False}, expect_fail=G1),
    "one-host-string": dict(plays_spec=[(INIT, None)], host_settings={"k3s03": "true"}, expect_fail=G1),
    "one-host-integer": dict(plays_spec=[(INIT, None)], host_settings={"k3s03": 1}, expect_fail=G1),
    "one-host-missing": dict(plays_spec=[(INIT, None)], setting=UNSET, host_settings={"k3s01": True, "k3s03": True}, expect_fail=G1),
    "false-no-ack": dict(plays_spec=[(JOIN, K2)], setting=False, expect_fail=G2),
    "false-wrong-ack": dict(plays_spec=[(JOIN, K2)], setting=False, extra={"k3s_pre_encryption_restore_ack": "pre-encryption"}, expect_fail=G2),
    "false-init": dict(plays_spec=[(INIT, None)], setting=False, extra={"k3s_pre_encryption_restore_ack": ACK}, expect_fail=G2),
    "false-ack-join": dict(plays_spec=[(JOIN, K2)], setting=False, extra={"k3s_pre_encryption_restore_ack": ACK}),
    "true-init": dict(plays_spec=[(INIT, None)], written=("k3s01",)),
    "true-join-match": dict(plays_spec=[(JOIN, K2)], first_dropin="file", written=("k3s02",)),
    "true-join-mismatch": dict(plays_spec=[(JOIN, K2)], expect_fail=JREQ),
    "false-join-mismatch": dict(plays_spec=[(JOIN, K2)], setting=False, extra={"k3s_pre_encryption_restore_ack": ACK}, first_dropin="file",
                                expect_fail=JREQ),
    "true-join-symlink": dict(plays_spec=[(JOIN, K2)], first_dropin="link", expect_fail=JREQ),
    "installed-binary-join": dict(plays_spec=[(JOIN, K2)], installed={"k3s02": "binary"}),
    "installed-data-join": dict(plays_spec=[(JOIN, K2)], installed={"k3s02": "data"}),
    "installed-binary-init": dict(plays_spec=[(INIT, None)], installed={"k3s01": "binary"}),
    "stop-after-init-refusal": dict(plays_spec=[(INIT, None), (JOIN, None)], setting=False, extra={"k3s_pre_encryption_restore_ack": ACK},
                                    expect_fail=G2),
    "stop-after-join-refusal": dict(plays_spec=[(JOIN, None)], expect_fail=JREQ),
}
LABELS = {
    "missing": "missing setting refused before any change",
    "string-true": 'the string "true" refused',
    "string-false": 'the string "false" refused, even with the acknowledgement',
    "integer": "an integer refused",
    "one-host-false": "a one-host false override refused on every server",
    "one-host-string": 'a one-host string "true" override refused',
    "one-host-integer": "a one-host integer 1 override refused (equal to true, but not a boolean)",
    "one-host-missing": "a server without the setting refused",
    "false-no-ack": "false without the acknowledgement refused",
    "false-wrong-ack": "false with an inexact acknowledgement refused",
    "false-init": "false in init mode refused, even with the acknowledgement",
    "false-ack-join": "false with the exact acknowledgement on a fresh join writes no drop-in (first server without one)",
    "true-init": "true on a fresh first server writes the drop-in",
    "true-join-match": "true on a fresh join with the first server's drop-in writes the drop-in",
    "true-join-mismatch": "true on a fresh join without the first server's drop-in refused",
    "false-join-mismatch": "false on a fresh join with the first server's drop-in present refused",
    "true-join-symlink": "a first-server drop-in that is a symbolic link refused",
    "installed-binary-join": "installed binary on a join: nothing written and no first-server check",
    "installed-data-join": "existing data on a join: nothing written and no first-server check",
    "installed-binary-init": "installed binary on the first server: nothing written",
    "stop-after-init-refusal": "a refused first server stops the play sequence (the join play never runs)",
    "stop-after-join-refusal": "a refused join stops the join play (the next server never runs)",
}
for key, spec in CASES.items():
    run_case(LABELS[key], **spec)


# ====================================================================== role mutants
def mut(fn):
    t = copy.deepcopy(ks_tasks)
    fn(t)
    return t


def drop_that(name, item):
    return lambda ts: named(ts, name)["ansible.builtin.assert"]["that"].remove(item)


def replace_that(name, i, value):
    def edit(ts):
        named(ts, name)["ansible.builtin.assert"]["that"][i] = value
    return edit


ROLE_MUTANTS = (
    ("the cross-server consistency check removed", [
        drop_that(G1, "k3s_server_secrets_encryption_values | unique | list == [k3s_secrets_encryption_enabled]")], "one-host-false"),
    ("the per-server boolean checks removed", [
        drop_that(G1, "k3s_secrets_encryption_enabled is boolean"),
        drop_that(G1, "k3s_server_secrets_encryption_values | reject('boolean') | list | length == 0")], "string-true"),
    ("the every-server boolean check removed", [
        drop_that(G1, "k3s_server_secrets_encryption_values | reject('boolean') | list | length == 0")], "one-host-integer"),
    ("the setting guard removed (a missing setting no longer refused there)", [
        lambda ts: named(ts, G1)["ansible.builtin.assert"].update(that=["true"])], "missing"),
    ("false accepted without the acknowledgement", [replace_that(G2, 0, "k3s_secrets_encryption_enabled or k3s_mode == 'join'")], "false-no-ack"),
    ("an inexact acknowledgement accepted", [replace_that(
        G2, 0, "k3s_secrets_encryption_enabled or (k3s_mode == 'join' and k3s_pre_encryption_restore_ack is defined)")], "false-wrong-ack"),
    ("false accepted in init mode", [replace_that(
        G2, 0, "k3s_secrets_encryption_enabled or (k3s_pre_encryption_restore_ack | default('')) == 'pre-encryption-restore'")], "false-init"),
    ("the first-server match not required", [replace_that(JREQ, 0, "true")], "true-join-mismatch"),
    ("the first-server match not required for false", [replace_that(JREQ, 0, "k3s_first_server_dropin.stat.exists or true")],
     "false-join-mismatch"),
    ("a symbolic link accepted as the first server's drop-in", [replace_that(JREQ, 1, "true")], "true-join-symlink"),
    ("the first-server check on installed servers too", [
        lambda ts: [named(ts, n).update(when=["k3s_mode == 'join'"]) for n in (JSTAT, JREQ)]], "installed-binary-join"),
    ("the drop-in written on a server with K3s installed", [lambda ts: named(ts, DROPIN).update(
        when=["k3s_secrets_encryption_enabled | bool", "not k3s_server_data.stat.exists"])], "installed-binary-init"),
    ("the drop-in written where K3s data exists", [lambda ts: named(ts, DROPIN).update(
        when=["k3s_secrets_encryption_enabled | bool", "not k3s_server_binary.stat.exists"])], "installed-data-join"),
    ("the configuration directory created before the guards", [move_before_guards(CONFDIR)], "missing"),
    ("the first-server check after the configuration directory", [
        lambda ts: ts.insert(index_of(ts, JSTAT), ts.pop(index_of(ts, CONFDIR)))], "true-join-mismatch"),
)
for label, edits, case in ROLE_MUTANTS:
    def apply(ts, edits=edits):
        for e in edits:
            e(ts)
    run_case(f"{label} (case: {LABELS[case]})", tasks=mut(apply), invert=True, kind="role mutant killed", **CASES[case])

# ====================================================================== result
print(f"fresh-build checks: {len(STRUCTURE)} structure, {len(STRUCTURAL_MUTANTS)} structural mutants, {len(CASES)} behavior cases, "
      f"{len(ROLE_MUTANTS)} role mutants; {len(failures)} failed", flush=True)
if failures:
    print("failed: " + "; ".join(failures), flush=True)
    sys.exit(1)
sys.exit(0)
