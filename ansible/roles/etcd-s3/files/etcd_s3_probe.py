#!/usr/bin/env python3
"""Read-only Stage 4 probe for one K3s server (docs/etcd-s3-uploads.md).

Run by the etcd-s3 role through ansible.builtin.script, as root. It reads K3s
configuration, the K3s journal, the K3s process, ETCDSnapshotFile records and
local snapshot names, and prints exactly one JSON object made only of booleans,
integers and allowlisted key names. It never prints a credential, the bucket,
an address, a token hash, object metadata, a snapshot size or any digest.

Modes:
  preflight  versions, time zone, node name, fallback credentials, proxy and
             AWS variables, existing names with the new bases, extra metadata,
             database size against its size in use (as a ratio).
  config     the drop-in and every other K3s configuration source.
  leaks      occurrences of the drop-in's key, its secret and any key-shaped
             string in the journal, the process, the records and the ConfigMap.
  snapshots  local and S3 snapshot counts and ages per base, from names and
             record status only.
"""
import argparse
import base64
import calendar
import glob
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

KEY_SHAPED = re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}")
PROXY_VARS = re.compile(r"^(?:HTTPS?_PROXY|NO_PROXY|ALL_PROXY)$", re.IGNORECASE)
SECRET_KEYS = ("etcd-s3-access-key", "etcd-s3-secret-key")
NAME_KEYS = ("etcd-snapshot-name",)
STAGE4_KEY = re.compile(r"^(?:etcd-s3|etcd-snapshot)")
UNIT_FLAG = re.compile(rb"--etcd-s3|--etcd-snapshot")
TIMEOUT = 60


def run(argv, timeout=TIMEOUT):
    """Run a command; return (ok, stdout bytes). Never raises."""
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, b""
    return r.returncode == 0, r.stdout


def load_yaml(text):
    import yaml  # python3-yaml; preflight reports its absence
    return yaml.safe_load(text)


def config_sources(config_file, config_dir):
    """K3s order: config.yaml, then config.yaml.d/*.yaml and *.yml, alphabetically."""
    files = [config_file] if os.path.exists(config_file) else []
    extra = glob.glob(os.path.join(config_dir, "*.yaml")) + glob.glob(os.path.join(config_dir, "*.yml"))
    return files + sorted(extra, key=os.path.basename)


def parse_sources(paths):
    """Return ({path: mapping}, unparsable count)."""
    docs, bad = {}, 0
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                d = load_yaml(f.read())
        except Exception:
            bad += 1
            continue
        if d is None:
            d = {}
        if not isinstance(d, dict):
            bad += 1
            continue
        docs[p] = {str(k).rstrip("+"): v for k, v in d.items()}
    return docs, bad


def dropin_secrets(dropin):
    """The drop-in's access key and secret, as bytes, or empty."""
    try:
        with open(dropin, encoding="utf-8") as f:
            d = load_yaml(f.read())
    except Exception:
        return []
    if not isinstance(d, dict):
        return []
    return [str(d[k]).encode() for k in SECRET_KEYS if isinstance(d.get(k), str) and len(d[k]) >= 16]


def count_in(data, secrets):
    """Occurrences of each exact secret plus key-shaped strings; one total."""
    n = sum(data.count(s) for s in secrets)
    return n + len(KEY_SHAPED.findall(data))


def k3s_pids(systemctl, service):
    ok, out = run([systemctl, "show", "--property", "MainPID", "--value", service])
    pid = out.decode(errors="replace").strip() if ok else ""
    return [pid] if pid.isdigit() and pid != "0" else []


def proc_bytes(pid, name):
    try:
        with open(f"/proc/{pid}/{name}", "rb") as f:
            return f.read()
    except OSError:
        return None


def env_names(raw):
    return [e.split(b"=", 1)[0].decode(errors="replace") for e in raw.split(b"\0") if b"=" in e]


def unit_env_names(path):
    names = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    names.append(line.split("=", 1)[0].replace("export ", "").strip())
    except OSError:
        pass
    return names


def kubectl_json(k3s, args):
    ok, out = run([k3s, "kubectl", *args, "-o", "json"])
    if not ok:
        return None, b""
    try:
        return json.loads(out), out
    except ValueError:
        return None, b""


def snapshot_records(k3s):
    doc, raw = kubectl_json(k3s, ["get", "etcdsnapshotfiles.k3s.cattle.io"])
    if doc is None or not isinstance(doc.get("items"), list):
        return None, raw
    return doc["items"], raw


def epoch_of(ts):
    try:
        return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except (TypeError, ValueError):
        return -1


def mode_preflight(a, exp):
    out = {}
    ok, ver = run([a.k3s, "--version"])
    out["k3s_version_ok"] = ok and (b"k3s version " + exp["version"].encode() + b" ") in ver
    try:
        import yaml  # noqa: F401
        out["yaml_available"] = True
    except ImportError:
        out["yaml_available"] = False
    target = os.path.realpath(a.localtime) if os.path.exists(a.localtime) else ""
    out["timezone_utc"] = (not os.path.lexists(a.localtime)) or target.endswith(("/UTC", "/Etc/UTC", "/UCT", "/Etc/UCT"))
    try:
        with open(a.hostname_file, encoding="utf-8") as f:
            out["hostname_matches"] = f.read().strip() == a.host
    except OSError:
        out["hostname_matches"] = False
    docs, bad = parse_sources(config_sources(a.config_file, a.config_dir)) if out["yaml_available"] else ({}, -1)
    out["config_unparsable"] = bad
    out["node_name_overrides"] = sum(1 for d in docs.values() if "node-name" in d)
    out["root_aws_absent"] = not os.path.lexists(a.root_aws)
    names = unit_env_names(a.unit_env)
    pids = k3s_pids(a.systemctl, a.service)
    for pid in pids:
        raw = proc_bytes(pid, "environ")
        names += env_names(raw) if raw is not None else []
    out["k3s_processes"] = len(pids)
    out["aws_env_vars"] = sum(1 for n in names if n.upper().startswith("AWS_"))
    out["proxy_env_vars"] = sum(1 for n in names if PROXY_VARS.match(n))
    try:
        with open(a.unit, "rb") as f:
            out["unit_stage4_flags"] = len(UNIT_FLAG.findall(f.read()))
    except OSError:
        out["unit_stage4_flags"] = -1
    try:
        files = os.listdir(a.snapshot_dir)
    except OSError:
        files = None
    bases = [exp["scheduled_base"], exp["ondemand_base"]]
    out["snapshot_dir_read"] = files is not None
    out["existing_new_base_files"] = sum(1 for n in files or [] if n.startswith(tuple(bases)))
    ok, _ = run([a.k3s, "kubectl", "get", "configmap", "-n", "kube-system", "k3s-etcd-snapshot-extra-metadata",
                 "-o", "name"])
    out["extra_metadata_configmap"] = ok
    out["db_in_use_percent"] = -1
    try:
        with urllib.request.urlopen(a.metrics_url, timeout=10) as r:  # noqa: S310 (fixed local URL)
            text = r.read().decode(errors="replace")
        total = re.search(r"^etcd_mvcc_db_total_size_in_bytes (\S+)$", text, re.MULTILINE)
        used = re.search(r"^etcd_mvcc_db_total_size_in_use_in_bytes (\S+)$", text, re.MULTILINE)
        if total and used and float(total.group(1)) > 0:
            out["db_in_use_percent"] = int(round(100 * float(used.group(1)) / float(total.group(1))))
    except Exception:
        pass
    return out


def mode_config(a, exp):
    out = {}
    paths = config_sources(a.config_file, a.config_dir)
    docs, bad = parse_sources(paths)
    out["unparsable"] = bad
    others = {p: d for p, d in docs.items() if p != a.dropin}
    out["stage4_keys_elsewhere"] = sum(1 for d in others.values() for k in d if STAGE4_KEY.match(k))
    out["name_definitions"] = sum(1 for d in docs.values() for k in d if k in NAME_KEYS)
    try:
        st = os.lstat(a.dropin)
        out["dropin_exists"] = True
        out["dropin_regular"] = os.path.isfile(a.dropin) and not os.path.islink(a.dropin)
        out["dropin_mode_ok"] = (st.st_mode & 0o7777) == 0o600
        out["dropin_owner_ok"] = st.st_uid == int(exp["owner_uid"]) and st.st_gid == int(exp["owner_uid"])
    except OSError:
        out.update(dropin_exists=False, dropin_regular=False, dropin_mode_ok=False, dropin_owner_ok=False)
    d = docs.get(a.dropin, {})
    expected = exp["values"]
    allowed = set(exp["keys"])
    out["dropin_unknown_keys"] = sum(1 for k in d if k not in allowed)
    out["dropin_missing_keys"] = sum(1 for k in expected if k not in d) + sum(1 for k in SECRET_KEYS + ("etcd-s3-bucket",) if k not in d)
    out["values_match"] = all(d.get(k) == v for k, v in expected.items()) and not any(
        k in d for k in allowed - set(expected) - set(SECRET_KEYS) - {"etcd-s3-bucket"})
    out["name_ok"] = d.get("etcd-snapshot-name") == exp["scheduled_name"] and str(exp["scheduled_name"]).startswith(exp["scheduled_base_prefix"])
    out["access_key_format_ok"] = isinstance(d.get("etcd-s3-access-key"), str) and re.fullmatch(exp["access_key_pattern"].strip("^$"), d["etcd-s3-access-key"]) is not None
    out["secret_key_format_ok"] = isinstance(d.get("etcd-s3-secret-key"), str) and re.fullmatch(exp["secret_key_pattern"].strip("^$"), d["etcd-s3-secret-key"]) is not None
    out["bucket_format_ok"] = isinstance(d.get("etcd-s3-bucket"), str) and re.fullmatch(exp["bucket_pattern"].strip("^$"), d["etcd-s3-bucket"]) is not None
    try:
        with open(a.unit, "rb") as f:
            out["unit_stage4_flags"] = len(UNIT_FLAG.findall(f.read()))
    except OSError:
        out["unit_stage4_flags"] = -1
    out["root_aws_absent"] = not os.path.lexists(a.root_aws)
    return out


def mode_leaks(a, exp):
    secrets = dropin_secrets(a.dropin)
    out = {"dropin_secrets_read": len(secrets) == 2, "unavailable": 0}
    ok, journal = run([a.journalctl, "--unit", a.service, "--no-pager", "--output", "cat"], timeout=300)
    out["journal"] = count_in(journal, secrets) if ok else -1
    pids = k3s_pids(a.systemctl, a.service)
    out["k3s_processes"] = len(pids)
    n = 0
    for pid in pids:
        for name in ("cmdline", "environ"):
            raw = proc_bytes(pid, name)
            n += count_in(raw, secrets) if raw is not None else 0
    out["process"] = n
    records, raw = snapshot_records(a.k3s)
    out["records"] = count_in(raw, secrets) if records is not None else -1
    doc, raw = kubectl_json(a.k3s, ["get", "configmap", "-n", "kube-system", "k3s-etcd-snapshots"])
    out["configmap"] = count_in(raw, secrets) if doc is not None else 0
    out["configmap_present"] = doc is not None
    out["unavailable"] = sum(1 for k in ("journal", "records") if out[k] < 0)
    return out


def classify(name, host, exp):
    if name.startswith(exp["scheduled_base_prefix"] + host + "-"):
        return "scheduled_s4"
    if name.startswith(exp["ondemand_base_prefix"] + host + "-"):
        return "ondemand_s4"
    if name.startswith(("stage3-",)):
        return "stage3"
    if name.startswith(exp["scheduled_base_prefix"]) or name.startswith(exp["ondemand_base_prefix"]):
        return "other_server_s4"
    if name.startswith("etcd-snapshot-"):
        return "legacy_scheduled"
    return "other"


def mode_snapshots(a, exp):
    """With exp["wait"] = {since, seconds, delay}, poll until this node's newest
    ready on-demand S3 record is at least `since`, or the time runs out."""
    wait = exp.get("wait") or {}
    deadline = time.time() + int(wait.get("seconds", 0))
    while True:
        out = snapshots_once(a, exp)
        if not wait or out["s3_newest_ondemand_epoch"] >= int(wait["since"]) or time.time() >= deadline:
            return out
        time.sleep(int(wait.get("delay", 10)))


def snapshots_once(a, exp):
    now = int(time.time())
    out = {}
    try:
        files = [(n, int(os.lstat(os.path.join(a.snapshot_dir, n)).st_mtime)) for n in os.listdir(a.snapshot_dir)]
        out["local_read"] = True
    except OSError:
        files, out["local_read"] = [], False
    local = {k: 0 for k in ("scheduled_s4", "ondemand_s4", "stage3", "other_server_s4", "legacy_scheduled", "other")}
    newest = {"scheduled_s4": 0, "ondemand_s4": 0}
    for n, m in files:
        c = classify(n, a.host, exp)
        local[c] += 1
        if c in newest:
            newest[c] = max(newest[c], m)
    out["local"] = local
    out["local_newest_scheduled_age_s"] = now - newest["scheduled_s4"] if newest["scheduled_s4"] else -1
    out["local_newest_ondemand_epoch"] = newest["ondemand_s4"]
    records, _ = snapshot_records(a.k3s)
    out["records_read"] = records is not None
    s3 = {"scheduled_s4": 0, "ondemand_s4": 0, "ready": 0, "not_ready": 0, "unapproved_base": 0}
    s3_newest = {"scheduled_s4": 0, "ondemand_s4": 0}
    for r in records or []:
        spec, status = r.get("spec") or {}, r.get("status") or {}
        if not spec.get("s3"):
            continue
        name = str(spec.get("snapshotName", ""))
        if not name.startswith(tuple(exp["approved_bases"])):
            s3["unapproved_base"] += 1
        if spec.get("nodeName") != a.host:
            continue
        c = classify(name, a.host, exp)
        ready = status.get("readyToUse") is True
        s3["ready" if ready else "not_ready"] += 1
        if c in s3_newest and ready:
            s3[c] += 1
            s3_newest[c] = max(s3_newest[c], epoch_of(status.get("creationTime")))
    out["s3"] = s3
    out["s3_newest_scheduled_age_s"] = now - s3_newest["scheduled_s4"] if s3_newest["scheduled_s4"] > 0 else -1
    out["s3_newest_ondemand_epoch"] = s3_newest["ondemand_s4"]
    return out


def checked(obj):
    """Only booleans, integers and nested mappings of them leave the probe."""
    if isinstance(obj, dict):
        return {str(k): checked(v) for k, v in obj.items() if re.fullmatch(r"[a-z0-9_]+", str(k))}
    if isinstance(obj, bool) or isinstance(obj, int):
        return obj
    raise ValueError("probe output must be booleans and integers only")


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--mode", required=True, choices=("preflight", "config", "leaks", "snapshots"))
    for opt in ("host", "k3s", "systemctl", "journalctl", "service", "config-file", "config-dir", "dropin", "unit",
                "unit-env", "root-aws", "snapshot-dir", "hostname-file", "localtime", "metrics-url", "expected"):
        p.add_argument("--" + opt, required=True)
    a = p.parse_args(argv)
    exp = json.loads(base64.b64decode(a.expected))
    modes = {"preflight": mode_preflight, "config": mode_config, "leaks": mode_leaks, "snapshots": mode_snapshots}
    try:
        result = checked(modes[a.mode](a, exp))
    except Exception:
        print(json.dumps({"probe_error": True}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
