# nodes.py - single source of truth for cluster configuration
# Example topology uses RFC 5737 documentation addresses.
# Customize these values for your environment before deployment.

NODES = [
    {"name": "k3s01", "ip": "192.0.2.11", "role": "server", "init": True},
    {"name": "k3s02", "ip": "192.0.2.12", "role": "server", "init": False},
    {"name": "k3s03", "ip": "192.0.2.13", "role": "server", "init": False},
]

VIP = "192.0.2.10"

KUBE_VIP_INTERFACE = "ens160"

K3S_VERSION = "v1.36.4+k3s1"

DNS_ZONE = "lab.example"

GATEWAY = "192.0.2.1"

DNS_SERVERS = ["192.0.2.1"]
