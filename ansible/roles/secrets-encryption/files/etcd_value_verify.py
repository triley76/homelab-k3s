#!/usr/bin/env python3
"""Check the stored form of one etcd record read from standard input.

Usage: etcdctl get --write-out=json -- KEY | etcd_value_verify.py MODE PREFIX KEY

The input is etcdctl's JSON response for a single-key get. MODE is "encrypted"
or "plaintext". PREFIX is the expected provider prefix, for example
"k8s:enc:secretbox:v1:"; it is used only in "encrypted" mode. KEY is the exact
key that was requested.

The record never leaves this process. Exactly one token is printed:
PASS, FAIL-JSON, FAIL-MISSING, FAIL-MULTIPLE, FAIL-KEY, FAIL-EMPTY,
FAIL-OVERSIZE, FAIL-PREFIX, FAIL-MALFORMED, FAIL-ENCRYPTED or FAIL-USAGE.
The exit status is 0 only for PASS.

The response must hold exactly one record (count 1, one kv, more unset), and
its key must equal KEY byte for byte: a range or prefix result fails.

"encrypted" passes only for <PREFIX><key name>:<payload>, where the payload is
at least as long as the provider's nonce or IV plus one block or tag.
"plaintext" passes only for an unencrypted Kubernetes protobuf record, which
starts with the four bytes "k8s\\0". It is the positive control: it shows that
the query reads the real current record of an object that is stored in clear.
"""
import base64
import binascii
import json
import re
import sys

LIMIT = 4 << 20
# Bytes after "<prefix><key name>:" that a real record must contain at least:
# secretbox: 24-byte nonce + 16-byte Poly1305 tag + 1 byte of ciphertext;
# aescbc: 16-byte IV + one 16-byte block.
MIN_PAYLOAD = {"k8s:enc:secretbox:v1:": 41, "k8s:enc:aescbc:v1:": 32}
KEY_NAME = re.compile(rb"[A-Za-z0-9._-]{1,128}:")
PROTOBUF_MAGIC = b"k8s\x00"
ENCRYPTED_MARK = b"k8s:enc:"
CANARY_KEY = re.compile(r"^/registry/(secrets|configmaps)/[a-z0-9-]{1,63}/[a-z0-9-]{1,253}$")


def verdict(data, mode, prefix):
    """Classify one stored value (bytes)."""
    if not data:
        return "FAIL-EMPTY"
    if mode == "encrypted":
        if prefix not in MIN_PAYLOAD:
            return "FAIL-USAGE"
        expected = prefix.encode("ascii")
        if not data.startswith(expected):
            return "FAIL-PREFIX"
        name = KEY_NAME.match(data, len(expected))
        if not name or len(data) - name.end() < MIN_PAYLOAD[prefix]:
            return "FAIL-MALFORMED"
        return "PASS"
    if mode == "plaintext":
        if data.startswith(ENCRYPTED_MARK):
            return "FAIL-ENCRYPTED"
        if not data.startswith(PROTOBUF_MAGIC):
            return "FAIL-MALFORMED"
        return "PASS"
    return "FAIL-USAGE"


def record(raw, key):
    """Return (token, value) for etcdctl's JSON response; value only if one exact record."""
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return "FAIL-JSON", None
    if not isinstance(doc, dict):
        return "FAIL-JSON", None
    kvs = doc.get("kvs") or []
    count = doc.get("count", 0)
    if not isinstance(kvs, list) or not isinstance(count, int) or isinstance(count, bool):
        return "FAIL-JSON", None
    if count == 0 and not kvs:
        return "FAIL-MISSING", None
    if count != 1 or len(kvs) != 1 or doc.get("more", False):
        return "FAIL-MULTIPLE", None
    kv = kvs[0]
    if not isinstance(kv, dict):
        return "FAIL-JSON", None
    try:
        got_key = base64.b64decode(kv.get("key", ""), validate=True)
        value = base64.b64decode(kv.get("value", ""), validate=True)
    except (binascii.Error, TypeError, ValueError):
        return "FAIL-JSON", None
    if got_key != key.encode("utf-8"):
        return "FAIL-KEY", None
    return None, value


def main(argv):
    if len(argv) != 4 or argv[1] not in ("encrypted", "plaintext") or not CANARY_KEY.match(argv[3]):
        token = "FAIL-USAGE"
    else:
        raw = sys.stdin.buffer.read(LIMIT + 1)
        if len(raw) > LIMIT:
            token = "FAIL-OVERSIZE"
        else:
            token, value = record(raw, argv[3])
            if token is None:
                token = verdict(value, argv[1], argv[2])
    print(token)
    return 0 if token == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
