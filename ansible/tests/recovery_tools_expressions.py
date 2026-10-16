"""Expression and structure tests for the recovery-tools role and its playbooks.

First checks the structure of the role, the controlled installation playbook,
the validation playbook and site.yml: the pinned version, checksum and URL, the
private working directory and its cleanup, permissions, the absence of apt and
shell installs, the single-host guard and the site.yml scope.

Then runs real tasks on localhost:
  - the inspection, decision, platform, pin and verification tasks against
    mocked stat and version results (pass, fail closed, or specific values);
  - the version-read task against mocked stat results whose paths do not exist,
    to check which files would be executed;
  - the extracted-binary validation tasks against stand-in binaries in a local
    temporary directory, with a marker for the first destination change that
    must run only when both binaries pass;
  - the single-host guard, copied from configure-recovery-tools.yml into a
    guard-only play, against a throwaway inventory with real --limit values;
  - the role's own temporary-directory tasks and cleanup, on success and on
    failure, in a local temporary directory.

Nothing is downloaded or installed, and no cluster node is contacted.

Usage (requires ansible-core and PyYAML):
    python3 ansible/tests/recovery_tools_expressions.py
"""
import copy
import os
import pathlib
import subprocess
import sys
import tempfile

import yaml

repo = pathlib.Path(__file__).resolve().parents[2]
role = repo / "ansible/roles/recovery-tools"
role_vars = yaml.safe_load((role / "vars/main.yml").read_text())
role_defaults = yaml.safe_load((role / "defaults/main.yml").read_text())
role_main = yaml.safe_load((role / "tasks/main.yml").read_text())
role_inspect = yaml.safe_load((role / "tasks/inspect.yml").read_text())
configure = yaml.safe_load((repo / "ansible/configure-recovery-tools.yml").read_text())
validate = yaml.safe_load((repo / "ansible/validate-recovery-tools.yml").read_text())
site = yaml.safe_load((repo / "ansible/site.yml").read_text())

PINNED_VERSION = "1.3.2"
PINNED_SHA256 = "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10"
PINNED_URL = "https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz"


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


def module_of(t):
    keys = [k for k in t if k.startswith("ansible.builtin.") or k in ("block",)]
    return keys[0] if keys else None


def play(name, mocks, tasks, expect_fail, checks=(), extra_vars=None):
    pre = [{"name": f"mock {k}", "ansible.builtin.set_fact": {k: v}} for k, v in mocks.items()]
    body = [{"name": "reset outcome", "ansible.builtin.set_fact": {"harness_failed": False}},
            {"block": tasks, "rescue": [{"name": "record failure", "ansible.builtin.set_fact": {"harness_failed": True}}]}]
    post = [{"name": f"check: {name}",
             "ansible.builtin.assert": {"that": [f"harness_failed | bool == {expect_fail}"] + list(checks), "quiet": True}}]
    vars_ = dict(role_defaults)
    vars_.update(role_vars)
    vars_.update(extra_vars or {})
    return {"name": name, "hosts": "localhost", "connection": "local", "gather_facts": False,
            "vars": vars_, "tasks": pre + body + post}


plays = []

# ---------------------------------------------------------------- inspection and decision
def st(name, exists=True, isreg=True, islnk=False, isdir=False, uid=0, gid=0, mode="0755",
       wgrp=False, woth=False, xusr=True, path=None):
    s = {"exists": exists}
    if exists:
        s.update({"path": path or f"/usr/local/bin/{name}", "isreg": isreg, "islnk": islnk, "isdir": isdir,
                  "uid": uid, "gid": gid, "mode": mode, "wgrp": wgrp, "woth": woth, "xusr": xusr})
    return {"item": name, "stat": s}


def ver(stdout="v1.3.2", rc=0):
    return {"rc": rc, "stdout": stdout, "changed": False}


SKIPPED = {"skipped": True, "changed": False}


def inspect_mocks(age=None, keygen=None, age_ver=None, keygen_ver=None):
    return {
        "recovery_tools_stat": {"results": [age or st("age"), keygen or st("age-keygen")]},
        "recovery_tools_version": {"results": [age_ver or ver(), keygen_ver or ver()]},
    }


summary = [pick(role_inspect, "Reset the age binary report"), pick(role_inspect, "Summarize the age binaries")]
decide = [pick(role_main, "Refuse install paths that are neither a regular file nor a symbolic link"),
          pick(role_main, "Decide whether the pinned release must be installed")]
verify = [pick(role_main, "Verify the pinned age binaries")]
required = "recovery_tools_install_required | bool"
not_required = "not (recovery_tools_install_required | bool)"

plays.append(play("inspect: correct installation needs no change and verifies", inspect_mocks(), summary + decide + verify, False, [
    not_required, "recovery_tools_age_report['age'].compliant", "recovery_tools_age_report['age-keygen'].compliant",
    "recovery_tools_age_report['age'].version == 'v1.3.2'", "recovery_tools_age_report['age'].mode == '0755'",
    "recovery_tools_age_report['age'].owner_uid == 0"]))
plays.append(play("inspect: version output with a trailing newline is accepted",
                  inspect_mocks(age_ver=ver("v1.3.2\n")), summary + decide, False, [not_required]))
plays.append(play("inspect: missing age-keygen requires installation",
                  inspect_mocks(keygen=st("age-keygen", exists=False), keygen_ver=SKIPPED), summary + decide, False, [
                      required, "not recovery_tools_age_report['age-keygen'].exists",
                      "recovery_tools_age_report['age-keygen'].version == 'unavailable'"]))
plays.append(play("verify: missing age-keygen fails closed",
                  inspect_mocks(keygen=st("age-keygen", exists=False), keygen_ver=SKIPPED), summary + verify, True))
for label, stdout in (("older version", "v1.3.1"), ("newer version", "v1.4.0"), ("pre-release", "v1.3.2-rc1"),
                      ("unprefixed", "1.3.2"), ("empty output", "")):
    plays.append(play(f"inspect: {label} requires installation", inspect_mocks(age_ver=ver(stdout)), summary + decide, False,
                      [required, "not recovery_tools_age_report['age'].compliant"]))
    plays.append(play(f"verify: {label} fails closed", inspect_mocks(age_ver=ver(stdout)), summary + verify, True))
plays.append(play("inspect: failed version read requires installation", inspect_mocks(age_ver=ver("", rc=1)), summary + decide, False,
                  [required, "recovery_tools_age_report['age'].version == 'unavailable'"]))
plays.append(play("inspect: symbolic link requires replacement and is not refused",
                  inspect_mocks(age=st("age", isreg=False, islnk=True), age_ver=SKIPPED), summary + decide, False,
                  [required, "recovery_tools_age_report['age'].symlink", "not recovery_tools_age_report['age'].compliant"]))
plays.append(play("verify: symbolic link fails closed", inspect_mocks(age=st("age", isreg=False, islnk=True), age_ver=SKIPPED),
                  summary + verify, True))
plays.append(play("inspect: directory at an install path is refused",
                  inspect_mocks(age=st("age", isreg=False, isdir=True), age_ver=SKIPPED), summary + decide, True))
for label, kw in (("mode 0775", {"mode": "0775"}), ("mode 0700", {"mode": "0700"}), ("mode 0777", {"mode": "0777"}),
                  ("non-root owner", {"uid": 1000}), ("non-root group", {"gid": 1000})):
    plays.append(play(f"inspect: {label} requires installation", inspect_mocks(age=st("age", **kw)), summary + decide, False,
                      [required, "not recovery_tools_age_report['age'].compliant"]))
    plays.append(play(f"verify: {label} fails closed", inspect_mocks(age=st("age", **kw)), summary + verify, True))

# ---------------------------------------------------------------- version-read trust gate
# The real version-read task, against stat results whose paths do not exist:
# a trusted file is attempted (and fails harmlessly); an untrusted one is skipped.
read_version = [pick(role_inspect, "Read the version of each trusted age binary")]
nowhere = "/nonexistent/recovery-tools-expression-test"
gate_cases = [("trusted regular root file", {}, False),
              ("symbolic link", {"isreg": False, "islnk": True}, True),
              ("non-root owner", {"uid": 1000}, True),
              ("group-writable", {"wgrp": True}, True),
              ("other-writable", {"woth": True}, True),
              ("not executable", {"xusr": False}, True),
              ("directory", {"isreg": False, "isdir": True}, True)]
gate_stats = [st("age", path=f"{nowhere}/{i}", **kw) for i, (_, kw, _) in enumerate(gate_cases)]
gate_stats.append(st("age-keygen", exists=False))
gate_checks = [f"(recovery_tools_version.results[{i}].skipped | default(false)) == {skip}" for i, (_, _, skip) in enumerate(gate_cases)]
gate_checks.append(f"recovery_tools_version.results[{len(gate_cases)}].skipped | default(false)")
plays.append(play("version read: executes only trusted regular root files", {"recovery_tools_stat": {"results": gate_stats}},
                  read_version, False, gate_checks))

# ---------------------------------------------------------------- platform
platform_task = [pick(role_main, "Require Ubuntu 24.04 on x86_64")]
ok_platform = {"system": "Linux", "distribution": "Ubuntu", "version": "24.04", "architecture": "x86_64"}
plays.append(play("platform: Ubuntu 24.04 x86_64 passes", {"recovery_tools_platform": ok_platform}, platform_task, False))
for label, change in (("Ubuntu 22.04", {"version": "22.04"}), ("Ubuntu 24.10", {"version": "24.10"}),
                      ("Debian", {"distribution": "Debian", "version": "12"}), ("aarch64", {"architecture": "aarch64"}),
                      ("i686", {"architecture": "i686"}), ("non-Linux", {"system": "Darwin"})):
    plays.append(play(f"platform: {label} fails closed", {"recovery_tools_platform": dict(ok_platform, **change)}, platform_task, True))

# ---------------------------------------------------------------- pin
pin_task = [pick(role_main, "Require the pinned age release")]
plays.append(play("pin: the reviewed pin passes", {}, pin_task, False))
for label, override in (("another version", {"recovery_tools_age_version": "1.3.1"}),
                        ("another checksum", {"recovery_tools_age_sha256": "0" * 64}),
                        ("another URL", {"recovery_tools_age_url": "https://example.invalid/age.tar.gz"}),
                        ("another install directory", {"recovery_tools_install_dir": "/usr/bin"}),
                        ("another binary list", {"recovery_tools_age_binaries": ["age"]})):
    plays.append(play(f"pin: {label} fails closed", {}, pin_task, True, extra_vars=override))

# ---------------------------------------------------------------- cleanup
install_block = next(t for t in role_main if t.get("name") == "Install the pinned age release")
tmp_tasks = [pick(install_block["block"], "Create a private working directory"),
             pick(install_block["block"], "Create the extraction directory")]
always = copy.deepcopy(install_block["always"])


def cleanup_play(name, body, expect_fail):
    return {"name": name, "hosts": "localhost", "connection": "local", "gather_facts": False,
            "vars": dict(role_vars), "tasks": [
                {"name": "reset outcome", "ansible.builtin.set_fact": {"harness_failed": False}},
                {"block": body, "rescue": [{"name": "record failure", "ansible.builtin.set_fact": {"harness_failed": True}}],
                 "always": always},
                {"name": "stat the working directory", "ansible.builtin.stat": {"path": "{{ recovery_tools_tmp.path | default('/nonexistent') }}"},
                 "register": "cleanup_stat"},
                {"name": f"check: {name}", "ansible.builtin.assert": {"quiet": True, "that": [
                    f"harness_failed | bool == {expect_fail}", "not cleanup_stat.stat.exists"]}}]}


fail_task = {"name": "simulate a failed download", "ansible.builtin.fail": {"msg": "simulated failure"}}
plays.append(cleanup_play("cleanup: working directory removed after success", tmp_tasks, False))
plays.append(cleanup_play("cleanup: working directory removed after a failure", tmp_tasks + [fail_task], True))
plays.append(cleanup_play("cleanup: failure before the directory exists does not break cleanup", [fail_task], True))

# ---------------------------------------------------------------- extracted-binary validation
# The role's real extracted-binary tasks, run against stand-in binaries (small
# shell scripts) in a local temporary directory. A marker task after them stands
# in for the first destination change; it must run only when both binaries pass.
extract_checks = [pick(install_block["block"], n) for n in (
    "Inspect the extracted age binaries", "Require each extracted binary to be a regular file",
    "Run each extracted binary from the working directory", "Require each extracted binary to report the pinned version")]
mutation_marker = {"name": "stand-in for the first destination change", "ansible.builtin.set_fact": {"destination_changed": True}}


def extracted_play(name, layout, expect_fail):
    """layout maps each binary to ('script', stdout, exit_code, mode) or ('symlink',) or ('directory',) or ('missing',)."""
    base = "{{ recovery_tools_tmp.path }}/extract/age"
    setup = [{"name": "create a test working directory", "ansible.builtin.tempfile": {"state": "directory", "prefix": "recovery-tools-test."},
              "register": "recovery_tools_tmp"},
             {"name": "create the test extraction directory", "ansible.builtin.file": {"path": base, "state": "directory", "mode": "0700"}}]
    for binary, spec in layout.items():
        kind = spec[0]
        if kind in ("script", "symlink"):
            stdout, code, mode = spec[1:] if kind == "script" else ("v1.3.2", 0, "0755")
            target = f"{base}/{binary}" if kind == "script" else "{{ recovery_tools_tmp.path }}/real-" + binary
            setup.append({"name": f"write a stand-in {binary}", "ansible.builtin.copy": {
                "dest": target, "mode": mode, "content": f"#!/bin/sh\necho '{stdout}'\nexit {code}\n"}})
            if kind == "symlink":
                setup.append({"name": f"link {binary} to a correct stand-in", "ansible.builtin.file": {
                    "src": target, "dest": f"{base}/{binary}", "state": "link"}})
        elif kind == "directory":
            setup.append({"name": f"put a directory at {binary}", "ansible.builtin.file": {"path": f"{base}/{binary}", "state": "directory"}})
    checks = [f"harness_failed | bool == {expect_fail}",
              "not (destination_changed | default(false))" if expect_fail else "destination_changed | default(false)"]
    return {"name": name, "hosts": "localhost", "connection": "local", "gather_facts": False, "vars": dict(role_vars), "tasks": [
        {"name": "reset outcome", "ansible.builtin.set_fact": {"harness_failed": False, "destination_changed": False}},
        {"block": setup + extract_checks + [mutation_marker],
         "rescue": [{"name": "record failure", "ansible.builtin.set_fact": {"harness_failed": True}}],
         "always": [{"name": "remove the test working directory", "ansible.builtin.file": {"path": "{{ recovery_tools_tmp.path }}", "state": "absent"},
                     "when": "recovery_tools_tmp.path is defined"}]},
        {"name": f"check: {name}", "ansible.builtin.assert": {"quiet": True, "that": checks}}]}


good = ("script", "v1.3.2", 0, "0755")
plays.append(extracted_play("extracted: both binaries correct, destination changes may proceed", {"age": good, "age-keygen": good}, False))
plays.append(extracted_play("extracted: wrong age version is rejected before any destination change",
                            {"age": ("script", "v1.3.1", 0, "0755"), "age-keygen": good}, True))
plays.append(extracted_play("extracted: wrong age-keygen version is rejected before any destination change",
                            {"age": good, "age-keygen": ("script", "v1.4.0", 0, "0755")}, True))
plays.append(extracted_play("extracted: pre-release age-keygen version is rejected",
                            {"age": good, "age-keygen": ("script", "v1.3.2-rc1", 0, "0755")}, True))
plays.append(extracted_play("extracted: symbolic link is rejected even to a correct binary", {"age": ("symlink",), "age-keygen": good}, True))
plays.append(extracted_play("extracted: directory instead of a regular file is rejected", {"age": good, "age-keygen": ("directory",)}, True))
plays.append(extracted_play("extracted: missing binary is rejected", {"age": ("missing",), "age-keygen": good}, True))
plays.append(extracted_play("extracted: non-executable binary is rejected", {"age": ("script", "v1.3.2", 0, "0644"), "age-keygen": good}, True))
plays.append(extracted_play("extracted: binary that exits non-zero is rejected", {"age": good, "age-keygen": ("script", "v1.3.2", 3, "0755")}, True))

# ---------------------------------------------------------------- static structure checks
structure_failures = []


def require(label, condition):
    print(f"{'PASS' if condition else 'FAIL'}  structure: {label}", flush=True)
    if not condition:
        structure_failures.append(label)


def roles_of(p):
    return [r if isinstance(r, str) else r.get("role") for r in p.get("roles", [])]


require("vars: pinned version is 1.3.2", role_vars["recovery_tools_age_version"] == PINNED_VERSION)
require("vars: pinned SHA-256 is the validated value", role_vars["recovery_tools_age_sha256"] == PINNED_SHA256)
require("vars: URL is the official FiloSottile/age release for the pinned archive",
        role_vars["recovery_tools_age_url"] == "https://github.com/FiloSottile/age/releases/download/v{{ recovery_tools_age_version }}/{{ recovery_tools_age_archive }}"
        and role_vars["recovery_tools_age_archive"] == "age-v{{ recovery_tools_age_version }}-linux-amd64.tar.gz")
require("vars: installs age and age-keygen into /usr/local/bin",
        role_vars["recovery_tools_install_dir"] == "/usr/local/bin" and role_vars["recovery_tools_age_binaries"] == ["age", "age-keygen"])
require("vars: the pin is not overridable through defaults",
        not {"recovery_tools_age_version", "recovery_tools_age_sha256", "recovery_tools_age_url"} & set(role_defaults))
pin = next(t for t in role_main if t.get("name") == "Require the pinned age release")
require("role: asserts the exact version, checksum and rendered URL", all(
    s in pin["ansible.builtin.assert"]["that"] for s in (
        f"recovery_tools_age_version == '{PINNED_VERSION}'", f"recovery_tools_age_sha256 == '{PINNED_SHA256}'",
        f"recovery_tools_age_url == '{PINNED_URL}'")))
plat = next(t for t in role_main if t.get("name") == "Record the target platform")["ansible.builtin.set_fact"]["recovery_tools_platform"]
require("role: platform is read from system, distribution, version and architecture facts",
        plat == {"system": "{{ ansible_facts['system'] }}", "distribution": "{{ ansible_facts['distribution'] }}",
                 "version": "{{ ansible_facts['distribution_version'] }}", "architecture": "{{ ansible_facts['architecture'] }}"})
names = [t.get("name") for t in role_main]
order = ["Record the target platform", "Require Ubuntu 24.04 on x86_64", "Require the pinned age release",
         "Inspect the installed age binaries", "Refuse install paths that are neither a regular file nor a symbolic link",
         "Decide whether the pinned release must be installed", "Install the pinned age release",
         "Re-inspect the age binaries", "Verify the pinned age binaries"]
require("role: guards, inspection, install and verification run in order",
        all(n in names for n in order) and [names.index(n) for n in order] == sorted(names.index(n) for n in order))

all_tasks = list(walk(role_main + role_inspect))
modules = {module_of(t) for t in all_tasks} - {None, "block"}
forbidden = {"ansible.builtin.apt", "ansible.builtin.package", "ansible.builtin.dnf", "ansible.builtin.pip",
             "ansible.builtin.shell", "ansible.builtin.raw", "ansible.builtin.script",
             "ansible.builtin.systemd", "ansible.builtin.systemd_service", "ansible.builtin.service", "ansible.builtin.reboot"}
require("role: no apt, package, shell, raw, script or service tasks", not modules & forbidden)
commands = [t for t in all_tasks if "ansible.builtin.command" in t]
require("role: the only commands read --version and never change state",
        len(commands) == 2 and all(c["ansible.builtin.command"]["argv"][1:] == ["--version"] and c.get("changed_when") is False
                                   for c in commands))
require("role: one --version read inspects the installed binaries, the other runs the extracted ones from the working directory",
        sum(c in role_inspect for c in commands) == 1
        and sum(c["ansible.builtin.command"]["argv"][0].startswith("{{ recovery_tools_tmp.path }}/extract/") for c in commands) == 1)

blk = install_block["block"]
blk_names = [t["name"] for t in blk]
require("install: runs only when installation is required", install_block.get("when") == "recovery_tools_install_required | bool")
require("install: starts by creating a private temporary directory",
        blk[0].get("ansible.builtin.tempfile", {}).get("state") == "directory" and blk[0].get("register") == "recovery_tools_tmp")
restrict = next(t for t in blk if t["name"] == "Restrict the working directory to root")["ansible.builtin.file"]
require("install: working directory is root:root 0700",
        restrict == {"path": "{{ recovery_tools_tmp.path }}", "state": "directory", "owner": "root", "group": "root", "mode": "0700"})
dl = next(t for t in blk if "ansible.builtin.get_url" in t)["ansible.builtin.get_url"]
require("install: get_url downloads the pinned URL into the working directory and verifies SHA-256",
        dl["url"] == "{{ recovery_tools_age_url }}" and dl["checksum"] == "sha256:{{ recovery_tools_age_sha256 }}"
        and dl["dest"].startswith("{{ recovery_tools_tmp.path }}/") and dl["mode"] == "0600")
ex = next(t for t in blk if "ansible.builtin.unarchive" in t)["ansible.builtin.unarchive"]
require("install: unarchive extracts only the two binaries inside the working directory",
        ex["remote_src"] is True and ex["src"].startswith("{{ recovery_tools_tmp.path }}/")
        and ex["dest"].startswith("{{ recovery_tools_tmp.path }}/") and "regex_replace', '^', 'age/'" in ex["include"])
cp = next(t for t in blk if "ansible.builtin.copy" in t)
require("install: copy installs from the working directory as root:root 0755",
        cp["ansible.builtin.copy"]["remote_src"] is True and cp["ansible.builtin.copy"]["src"].startswith("{{ recovery_tools_tmp.path }}/")
        and cp["ansible.builtin.copy"]["owner"] == "root" and cp["ansible.builtin.copy"]["group"] == "root"
        and cp["ansible.builtin.copy"]["mode"] == "0755" and cp["loop"] == "{{ recovery_tools_age_binaries }}")
unlink = next(t for t in blk if t["name"] == "Remove a symbolic link at an age install path")
require("install: only symbolic links are removed before installing",
        unlink["ansible.builtin.file"]["state"] == "absent" and "selectattr('value.symlink')" in unlink["loop"])
step = {m: next(i for i, t in enumerate(blk) if m in t) for m in
        ("ansible.builtin.tempfile", "ansible.builtin.get_url", "ansible.builtin.unarchive", "ansible.builtin.copy")}
require("install: create, download, extract and install run in order",
        step["ansible.builtin.tempfile"] < step["ansible.builtin.get_url"] < step["ansible.builtin.unarchive"] < step["ansible.builtin.copy"])
extracted_checks = ["Inspect the extracted age binaries", "Require each extracted binary to be a regular file",
                    "Run each extracted binary from the working directory", "Require each extracted binary to report the pinned version"]
require("install: extracted binaries are inspected, typed, run and version-checked in order, after extraction",
        all(n in blk_names for n in extracted_checks)
        and step["ansible.builtin.unarchive"] < blk_names.index(extracted_checks[0])
        and [blk_names.index(n) for n in extracted_checks] == sorted(blk_names.index(n) for n in extracted_checks))
x_stat = next(t for t in blk if t["name"] == extracted_checks[0])
x_type = next(t for t in blk if t["name"] == extracted_checks[1])["ansible.builtin.assert"]["that"]
x_ver = next(t for t in blk if t["name"] == extracted_checks[3])["ansible.builtin.assert"]["that"]
require("install: extracted binaries are inspected inside the working directory without following links",
        x_stat["ansible.builtin.stat"]["path"].startswith("{{ recovery_tools_tmp.path }}/extract/")
        and x_stat["ansible.builtin.stat"]["follow"] is False and x_stat["loop"] == "{{ recovery_tools_age_binaries }}")
require("install: each extracted binary must exist and be a regular file, not a link",
        x_type == ["item.stat.exists", "item.stat.isreg", "not item.stat.islnk"])
require("install: each extracted binary must run and report exactly the pinned version",
        x_ver == ["(item.rc | default(1)) == 0", "(item.stdout | default('') | trim) == 'v' ~ recovery_tools_age_version"])


def mutates_install_dir(t):
    params = next((v for k, v in t.items() if k.startswith("ansible.builtin.") and isinstance(v, dict)), {})
    return any("recovery_tools_install_dir" in str(params.get(k, "")) for k in ("path", "dest"))


first_mutation = next(i for i, t in enumerate(blk) if mutates_install_dir(t))
require("install: nothing under the install directory changes until both extracted binaries pass",
        first_mutation > blk_names.index(extracted_checks[3])
        and not any(mutates_install_dir(t) for t in blk[:blk_names.index(extracted_checks[3]) + 1])
        and not any(mutates_install_dir(t) for t in role_main[:names.index("Install the pinned age release")]))
require("install: the working directory is removed in always",
        len(install_block.get("always", [])) == 1
        and install_block["always"][0]["ansible.builtin.file"] == {"path": "{{ recovery_tools_tmp.path }}", "state": "absent"}
        and install_block["always"][0].get("when") == "recovery_tools_tmp.path is defined")

stat_task = next(t for t in role_inspect if "ansible.builtin.stat" in t)["ansible.builtin.stat"]
require("inspect: stat never follows links and reads no checksum", stat_task["follow"] is False and stat_task["get_checksum"] is False)
gate = next(t for t in role_inspect if "ansible.builtin.command" in t)["when"]
require("inspect: --version runs only for regular, non-link, root-owned files group and others cannot write",
        all(c in gate for c in ("item.stat.isreg", "not item.stat.islnk", "item.stat.uid == 0",
                                "not item.stat.wgrp", "not item.stat.woth", "item.stat.xusr")))
v_that = next(t for t in role_main if t.get("name") == "Verify the pinned age binaries")["ansible.builtin.assert"]["that"]
require("verify: requires a regular non-link root:root 0755 file at the pinned version", all(s in v_that for s in (
    "recovery_tools_age_report[item].regular_file | bool", "not (recovery_tools_age_report[item].symlink | bool)",
    "recovery_tools_age_report[item].owner_uid | int == 0", "recovery_tools_age_report[item].group_gid | int == 0",
    "recovery_tools_age_report[item].mode == '0755'", "recovery_tools_age_report[item].version == 'v' ~ recovery_tools_age_version")))

live = configure[0]
guard = live["pre_tasks"][0]
require("configure: one play, servers group, become, facts, serial 1, fail-fast",
        len(configure) == 1 and live["hosts"] == "servers" and live["become"] is True and live["gather_facts"] is True
        and live["serial"] == 1 and live["any_errors_fatal"] is True and live["max_fail_percentage"] == 0)
require("configure: applies only the recovery-tools role to k3s01",
        roles_of(live) == ["recovery-tools"] and live["vars"]["recovery_tools_target_host"] == "k3s01" and "tasks" not in live)
require("configure: guard requires an exact single-host limit naming the first server",
        guard.get("run_once") is True and guard["ansible.builtin.assert"]["that"] == [
            "ansible_limit is defined", "ansible_limit == recovery_tools_target_host",
            "ansible_play_hosts_all | length == 1", "ansible_play_hosts_all[0] == recovery_tools_target_host",
            "groups['servers'][0] == recovery_tools_target_host"])

rt_plays = [p for p in site if "recovery-tools" in roles_of(p)]
require("site.yml: exactly one play applies recovery-tools, to servers[0] only",
        len(rt_plays) == 1 and rt_plays[0]["hosts"] == "servers[0]" and roles_of(rt_plays[0]) == ["recovery-tools"])
idx = site.index(rt_plays[0]) if rt_plays else -1
require("site.yml: recovery-tools runs after common preparation and leaves the time-sync plays first and last",
        idx > next(i for i, p in enumerate(site) if "k3s-common" in roles_of(p))
        and roles_of(site[0]) == ["time-sync"] and roles_of(site[-1]) == ["time-sync"])
require("site.yml: no other playbook play targets more than servers[0] with recovery-tools",
        all(p["hosts"] == "servers[0]" for p in rt_plays))

vp = validate[0]
v_modules = {module_of(t) for t in vp["tasks"]}
require("validate: read-only, no privilege escalation, first server only",
        len(validate) == 1 and vp["hosts"] == "servers[0]" and vp["become"] is False
        and v_modules <= {"ansible.builtin.include_role", "ansible.builtin.set_fact", "ansible.builtin.debug", "ansible.builtin.assert"})
inc = vp["tasks"][0]["ansible.builtin.include_role"]
require("validate: reuses the role's read-only inspection", inc == {"name": "recovery-tools", "tasks_from": "inspect.yml", "public": True})

if structure_failures:
    print(f"structure checks failed: {structure_failures}", flush=True)
    sys.exit(1)

# ---------------------------------------------------------------- run
guard_cases = [("omitted limit", None, False), ("exact k3s01", "k3s01", True), ("wildcard k3s0*", "k3s0*", False),
               ("wildcard resolving to k3s01 only", "k3s01*", False), ("regex resolving to k3s01 only", "~k3s01$", False),
               ("two hosts", "k3s01,k3s02", False), ("list ending in a comma", "k3s01,", False),
               ("wrong host", "k3s02", False), ("group", "servers", False), ("all", "all", False)]

with tempfile.TemporaryDirectory() as tmp:
    tmp = pathlib.Path(tmp)
    cfg = tmp / "ansible.cfg"
    cfg.write_text("[defaults]\nretry_files_enabled = False\ninterpreter_python = auto_silent\n")
    env = dict(os.environ, ANSIBLE_CONFIG=str(cfg), ANSIBLE_ROLES_PATH=str(repo / "ansible/roles"))

    # Guard-only play: the real pre_task, with no role, so a passing guard runs nothing else.
    guard_play = [{"name": "single-host guard", "hosts": live["hosts"], "gather_facts": False, "serial": live["serial"],
                   "any_errors_fatal": True, "max_fail_percentage": 0, "vars": live["vars"],
                   "pre_tasks": [copy.deepcopy(guard)], "tasks": [{"name": "guard passed", "ansible.builtin.debug": {"msg": "GUARD-PASSED"}}]}]
    guard_pb = tmp / "guard.yml"
    guard_pb.write_text(yaml.safe_dump(guard_play, sort_keys=False, width=200))
    local = "\n[servers:vars]\nansible_connection=local\nansible_python_interpreter=" + sys.executable + "\n"
    inv = tmp / "inventory.ini"
    inv.write_text("[servers]\nk3s01\nk3s02\nk3s03\n" + local)
    inv_reordered = tmp / "inventory-reordered.ini"
    inv_reordered.write_text("[servers]\nk3s02\nk3s01\nk3s03\n" + local)

    guard_failures = []
    cases = [(label, limit, expect, inv) for label, limit, expect in guard_cases]
    cases.append(("k3s01 is not the first server", "k3s01", False, inv_reordered))
    for label, limit, expect_pass, inventory in cases:
        cmd = ["ansible-playbook", "-i", str(inventory), str(guard_pb)] + (["--limit", limit] if limit is not None else [])
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        passed = r.returncode == 0 and "GUARD-PASSED" in r.stdout
        refused = r.returncode != 0 and "GUARD-PASSED" not in r.stdout
        ok = passed if expect_pass else refused
        print(f"{'PASS' if ok else 'FAIL'}  guard: {label} ({'allowed' if expect_pass else 'refused'})", flush=True)
        if not ok:
            guard_failures.append(label)
            print(r.stdout[-2000:], r.stderr[-2000:], sep="\n", flush=True)
    if guard_failures:
        print(f"guard checks failed: {guard_failures}", flush=True)
        sys.exit(1)

    playbook = tmp / "recovery-tools-expressions.yml"
    playbook.write_text(yaml.safe_dump(plays, sort_keys=False, width=200))
    print(f"scenarios: {len(plays)}", flush=True)
    result = subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)], env=env)
    sys.exit(result.returncode)
