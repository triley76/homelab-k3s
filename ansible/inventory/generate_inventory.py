#!/usr/bin/env python3
"""
generate_inventory.py - reads nodes.py (source of truth) and writes
ansible/inventory/hosts.ini
"""

import sys
import os
import json

# nodes.py lives at the repo root, one level up from ansible/inventory/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from nodes import (
    NODES,
    VIP,
    KUBE_VIP_INTERFACE,
    K3S_VERSION,
    GATEWAY,
    DNS_SERVERS,
    DNS_ZONE,
)

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "hosts.ini")

def main():
    lines = []
    lines.append("[servers]")
    for node in NODES:
        lines.append(f"{node['name']} ansible_host={node['ip']}")

    lines.append("")
    lines.append("[servers:vars]")
    lines.append("ansible_user=ansible")
    lines.append("ansible_ssh_private_key_file=~/.ssh/id_ed25519")
    lines.append(f"vip_address={VIP}")
    lines.append(f"kube_vip_interface={KUBE_VIP_INTERFACE}")
    lines.append(f"k3s_version={K3S_VERSION}")
    lines.append(f"gateway={GATEWAY}")
    lines.append(f"dns_servers={json.dumps(DNS_SERVERS, separators=(',', ':'))}")
    lines.append(f"dns_zone={DNS_ZONE}")

    lines.append("")
    lines.append("[k3s_cluster:children]")
    lines.append("servers")

    with open(OUTPUT_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Wrote inventory to {OUTPUT_PATH}")
    for node in NODES:
        print(f"  {node['name']} -> {node['ip']} (init={node['init']})")

if __name__ == "__main__":
    main()
