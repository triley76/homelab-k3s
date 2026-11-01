#!/usr/bin/env python3
"""Rehearsal-only equality check of a local snapshot and a downloaded object.

    snapshot_compare.py LOCAL_FILE DOWNLOADED_FILE

Compares the two regular files byte for byte. Prints MATCH (exit 0) or
MISMATCH (exit 1), or FAIL-USAGE (exit 2). It never prints a size, a digest or
any content, and it never uses an ETag or remote checksum: it is the candidate
"download and compare" integrity method for the S4-2 rehearsal, not yet
approved for live use (etcd_s3_integrity_approved_methods). No Stage 4
playbook runs this tool.
"""
import os
import stat
import sys

CHUNK = 1 << 20


def regular(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def same(a, b):
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(CHUNK), fb.read(CHUNK)
            if x != y:
                return False
            if not x:
                return True


def main(argv):
    if len(argv) != 3 or not regular(argv[1]) or not regular(argv[2]) or os.path.samefile(argv[1], argv[2]):
        print("FAIL-USAGE")
        return 2
    if same(argv[1], argv[2]):
        print("MATCH")
        return 0
    print("MISMATCH")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
