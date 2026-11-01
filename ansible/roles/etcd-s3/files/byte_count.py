#!/usr/bin/env python3
"""Rehearsal-only D6 residue counter (docs/etcd-s3-uploads.md, Residual plaintext).

    byte_count.py MARKER_FILE TARGET_FILE

Counts the exact occurrences, overlapping included, of the marker file's raw
bytes in the target file, which is read as bytes in chunks (an occurrence
across a chunk boundary is counted once). A text, base64 or hex rendering of
the marker is a different byte sequence and is not counted. Prints only the
count; on a usage error prints FAIL-USAGE and exits 2. The marker is never
printed. No Stage 4 playbook runs this tool.
"""
import os
import stat
import sys

CHUNK = 1 << 20
MIN_MARKER, MAX_MARKER = 16, 4096


def regular(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def count(marker, target, chunk=CHUNK):
    n, carry, keep = 0, b"", len(marker) - 1
    with open(target, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                return n
            data = carry + block
            i = data.find(marker)
            while i != -1:
                n += 1
                i = data.find(marker, i + 1)
            # Keep the last len(marker) - 1 bytes: an occurrence completed by the
            # next block starts there. The tail is shorter than the marker, so no
            # occurrence counted here can be counted again.
            carry = data[-keep:] if keep else b""


def main(argv):
    if len(argv) != 3 or not regular(argv[1]) or not regular(argv[2]):
        print("FAIL-USAGE")
        return 2
    with open(argv[1], "rb") as f:
        marker = f.read()
    if not MIN_MARKER <= len(marker) <= MAX_MARKER:
        print("FAIL-USAGE")
        return 2
    print(count(marker, argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
