# Build Guide

## Overview

This document describes the end-to-end workflow used to construct the three-node K3s platform.

The build is divided into distinct stages:

1\. Prepare local configuration.

2\. Build a reusable Ubuntu base VM with Packer.

3\. Clone the Kubernetes nodes.

4\. Discover their temporary network addresses.

5\. Bootstrap each node.

6\. Generate the permanent Ansible inventory.

7\. Build the K3s HA control plane.

8\. Deploy kube-vip.

9\. Join the remaining control-plane nodes.

10\. Validate the resulting cluster.

11\. Bootstrap Flux separately for ongoing GitOps reconciliation.

The automation spans Windows and Linux tooling. VMware and PowerShell handle the VM lifecycle, while Ansible performs operating-system and Kubernetes configuration.

## Prerequisites

The current implementation assumes:

- Windows workstation

- VMware Workstation

- Packer

- PowerShell

- Python

- WSL or another Linux environment capable of running Ansible

- Ansible

- SSH key pair for the automation account

- Ubuntu Server 24.04 installation ISO

The exact workstation paths are intentionally not committed to the repository.

## 1. Configure the Cluster Topology

Cluster-level configuration is maintained in:

```text

nodes.py

```

The public repository contains an example topology using RFC 5737 documentation addresses:

```python

NODES = \[

    {"name": "k3s01", "ip": "192.0.2.11", "role": "server", "init": True},

    {"name": "k3s02", "ip": "192.0.2.12", "role": "server", "init": False},

    {"name": "k3s03", "ip": "192.0.2.13", "role": "server", "init": False},

]

VIP = "192.0.2.10"

KUBE_VIP_INTERFACE = "ens160"

K3S_VERSION = "v1.36.4+k3s1"

DNS_ZONE = "lab.example"

GATEWAY = "192.0.2.1"

DNS_SERVERS = \["192.0.2.1"]

```

These values must be customized for the target environment before deployment.

`nodes.py` acts as a shared configuration source for both the PowerShell and Ansible portions of the workflow.

## 2. Configure the Workstation

Copy:

```text

config/workstation.example.ps1

```

to:

```text

config/workstation.ps1

```

Customize the local copy with the VMware and repository paths appropriate for the workstation.

Example:

```powershell

@{

    VmrunPath = "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe"

    VmRoot    = "D:\\Virtual_Machines"

    RepoWsl   = "/mnt/c/path/to/homelab-k3s"

}

```

`config/workstation.ps1` is excluded by `.gitignore`.

The tracked example documents the required configuration without committing workstation-specific paths.

## 3. Configure Packer Variables

The Packer configuration requires local values for the Ubuntu installation ISO and SSH private key.

Use:

```text

packer/variables.example.pkrvars.hcl

```

as the starting point.

Create a local file such as:

```text

packer/variables.auto.pkrvars.hcl

```

and provide values appropriate for the workstation.

Example:

```hcl

iso_url = "file:///C:/path/to/ubuntu-24.04.5-live-server-amd64.iso"

ssh_private_key_file = "C:/Users/your-user/.ssh/id_ed25519"

```

Optional overrides are available for:

- VMware output directory

- VMware virtual network

- VM name

- CPU count

- Memory

- Disk size

- Headless operation

Local `*.auto.pkrvars.hcl` files are ignored by Git.

## 4. Configure Ubuntu Autoinstall

Packer uses the files under:

```text

packer/http/

```

to automate the Ubuntu installation.

Before using the example configuration, replace the placeholders in:

```text

packer/http/user-data.example

```

with environment-appropriate values.

The example includes placeholders for:

- SSH public key

- SHA-512 password hash

The repository intentionally does not contain the corresponding SSH private key or a real password hash.

Copy packer/http/user-data.example to packer/http/user-data, then replace the placeholders in the local user-data file before running Packer. The local user-data file is excluded by .gitignore so credentials are not committed.

## 5. Build the Base VM

The primary Packer build definition is:

```text

packer/ubuntu-2404.pkr.hcl

```

It creates an Ubuntu Server 24.04 VMware VM with configurable sizing.

The default VM sizing in the current definition is:

| Resource | Default |

| --- | ---: |

| vCPU | 4 |

| Memory | 8192 MB |

| Disk | 40000 MB |

The VM uses a VMware `vmxnet3` network adapter.

Packer performs the automated Ubuntu installation and prepares the resulting VM to serve as the reusable source for the Kubernetes nodes.

The base image is deliberately separated from the Kubernetes configuration. Kubernetes is installed later by Ansible rather than baked into the VM image.

## 6. Clone the Kubernetes Nodes

After the reusable VM exists, run:

```text

clone_nodes.ps1

```

The script reads the node definitions from `nodes.py` and creates the required Kubernetes VMs from the base VM.

The default public example creates:

```text

k3s01

k3s02

k3s03

```

Separating cloning from configuration allows the same base operating-system image to be reused for every cluster member.

## 7. Discover Temporary Node Addresses

New VMs initially receive temporary network addresses before the permanent node configuration is applied.

Run:

```text

discover_nodes.ps1

```

The discovery workflow uses VMware tooling to identify the guest addresses of the newly created machines.

These addresses provide the temporary connectivity needed for the bootstrap phase.

## 8. Generate the Bootstrap Inventory

Run:

```text

generate_bootstrap_inventory.ps1

```

This creates:

```text

ansible/inventory/bootstrap.ini

```

The temporary inventory maps the desired nodes to the addresses discovered before permanent networking is configured.

`bootstrap.ini` is generated locally and excluded from source control.

## 9. Bootstrap the Nodes

The bootstrap workflow is coordinated by:

```text

bootstrap_nodes.ps1

```

and the Ansible bootstrap playbook.

The process configures the nodes for their permanent role in the cluster.

The bootstrap automation includes configuration and validation around:

- Hostname

- Static IP address

- Network configuration

- Default route

- Gateway

- DNS

- cloud-init state

The nodes are rebooted as part of the transition from temporary addressing to their permanent network configuration.

The automation then validates the resulting node state.

## 10. Generate the Permanent Ansible Inventory

After the nodes are available at their permanent addresses, generate the main inventory using:

```text

ansible/inventory/generate_inventory.py

```

The generator imports the cluster configuration from `nodes.py`.

The resulting inventory is written to:

```text

ansible/inventory/hosts.ini

```

The generated inventory includes the server nodes and shared cluster variables required by the Ansible roles.

`hosts.ini` is excluded from source control because it is generated from the authoritative configuration.

## 11. Run Preflight Validation

Before constructing the Kubernetes cluster, the Ansible preflight workflow can be used to verify that the nodes satisfy the expected prerequisites.

The playbook is:

```text

ansible/preflight.yml

```

The purpose of this stage is to identify node or network problems before cluster formation introduces additional variables.

## 12. Construct the K3s Cluster

The primary orchestration playbook is:

```text

ansible/site.yml

```

Its logical sequence is:

```text

Prepare all servers

        |

        v

Initialize first K3s server

        |

        v

Deploy kube-vip

        |

        v

Join remaining K3s servers

        |

        v

Three-node HA control plane

```

### Common Server Preparation

The `k3s-common` role prepares the server nodes with the common prerequisites required by the K3s deployment.

### Initialize the First Server

The first server defined by the cluster configuration initializes the K3s cluster.

This node establishes the initial embedded etcd datastore.

### Deploy kube-vip

After the first server is available, kube-vip is deployed to provide the Kubernetes API virtual address.

Clients can then use the VIP instead of depending on the address of a specific server.

### Join the Remaining Servers

The remaining servers join the existing K3s cluster.

The join process is intentionally serialized:

```yaml

serial: 1

```

Sequential joining was introduced after development testing encountered an etcd learner issue when additional control-plane servers attempted to join concurrently.

## 13. Runtime Cluster Token Handling

The K3s join token is obtained from the initialized server during the deployment process.

The automation:

1\. Waits for the server token to exist.

2\. Reads it from the initialized K3s server.

3\. Transfers it to each joining server.

4\. Stores it with restricted permissions.

5\. Uses the token file during the K3s join.

The actual token is not stored in this repository.

Sensitive token-handling tasks use Ansible `no_log` where appropriate.

## 14. Validate the Cluster

After the playbook completes, validation should confirm at minimum:

- All expected K3s servers joined the cluster.

- All expected Kubernetes nodes report Ready.

- The Kubernetes API responds through the virtual address.

- Exactly one control-plane server owns the kube-vip address.

- Embedded etcd formed successfully across the server nodes.

The project also includes controlled failure testing beyond initial installation.

See:

```text

docs/validation.md

```

for the documented validation scope.

## 15. Bootstrap GitOps

GitOps configuration is intentionally separated from infrastructure provisioning.

Once the Kubernetes foundation is operational, Flux is bootstrapped against the companion GitOps repository.

The GitOps repository becomes the desired-state source for platform components and workloads.

The validated V2 foundation uses Flux 2.9.5.

Flux reconciliation has been validated for:

- Git source synchronization

- Kustomization reconciliation

- Flux controller health

- V2 branch synchronization

Platform services are then introduced incrementally through GitOps.

## Generated and Local Files

Several files are intentionally generated or maintained locally and should not be committed.

These include:

```text

config/workstation.ps1

packer/*.auto.pkrvars.hcl

ansible/inventory/bootstrap.ini

ansible/inventory/hosts.ini

```

Additional cache, output, editor, Python, log, and temporary files are also excluded through `.gitignore`.

## Build Philosophy

The workflow intentionally separates concerns.

```text

Packer

  |

  | creates a consistent OS foundation

  v

VMware VM

  |

  | cloned and discovered by

  v

PowerShell

  |

  | hands nodes to

  v

Ansible

  |

  | constructs

  v

K3s + etcd + kube-vip

  |

  | subsequently managed through

  v

Flux GitOps

```

This separation makes failures easier to isolate and allows individual layers to evolve without requiring the entire platform to be rebuilt as a single monolithic process.

The goal is not simply to produce a running Kubernetes cluster. The goal is to make the construction process understandable, repeatable, testable, and improvable.
