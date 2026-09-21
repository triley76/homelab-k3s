# Architecture

## Overview

This project implements a reproducible three-node Kubernetes platform on VMware Workstation.

The architecture separates the platform lifecycle into distinct layers:

1\. **Image construction** with Packer

2\. **Virtual machine lifecycle and discovery** with PowerShell

3\. **Operating system and Kubernetes configuration** with Ansible

4\. **Highly available Kubernetes control plane** with K3s, embedded etcd, and kube-vip

5\. **Ongoing platform configuration** through Flux GitOps

The intent is to make the cluster reproducible from source-controlled automation while keeping workstation-specific configuration and runtime secrets outside the repository.

## Logical Architecture

```text

                         Git Repository

                              |

                              | Flux reconciliation

                              v

                     +------------------+

                     | GitOps Desired   |

                     | State            |

                     +---------+--------+

                               |

                               v

                    Kubernetes Platform

                               ^

                               |

                        API Virtual IP

                         192.0.2.10

                          (kube-vip)

                               |

              +----------------+----------------+

              |                |                |

              v                v                v

         +----------+     +----------+     +----------+

         |  k3s01   |     |  k3s02   |     |  k3s03   |

         |  Server  |     |  Server  |     |  Server  |

         | .0.2.11  |     | .0.2.12  |     | .0.2.13  |

         +-----+----+     +-----+----+     +-----+----+

               \\                |                /

                \\               |               /

                 +--------------+--------------+

                                |

                         Embedded etcd

                                ^

                                |

                  Ansible Configuration

                                ^

                                |

                  PowerShell Automation

                                ^

                                |

                    Packer Base Image

                                ^

                                |

                    Ubuntu Server 24.04

```

The addresses in this repository use the RFC 5737 `192.0.2.0/24` documentation network and are not the addresses used by the working lab.

## Workstation and Virtualization Layer

The current implementation uses a Windows workstation running VMware Workstation.

The workstation performs several roles in the build process:

- Runs Packer to construct the reusable Ubuntu base VM

- Uses PowerShell and VMware tooling to clone and interact with virtual machines

- Discovers temporary addresses assigned to newly created VMs

- Invokes the Linux-based Ansible workflow

- Provides the operator interface for cluster construction and validation

Workstation-specific paths are deliberately separated from the automation.

`config/workstation.example.ps1` documents the required settings. The operator creates an untracked `config/workstation.ps1` containing values appropriate for the local environment.

This prevents workstation paths from becoming embedded throughout the automation.

## Base Image Construction

Packer is responsible for creating the reusable Ubuntu Server base image.

The build definition is located under:

```text

packer/

```

The image establishes a consistent starting point for every Kubernetes node.

The Packer configuration defines the virtual machine characteristics and uses Ubuntu autoinstall data under `packer/http/` to automate operating-system installation.

Local values such as the ISO location and SSH private-key path are supplied through Packer variables rather than committed directly into the build definition.

A tracked example file documents the expected configuration:

```text

packer/variables.example.pkrvars.hcl

```

Local `*.auto.pkrvars.hcl` files are excluded from source control.

## Cluster Configuration Source of Truth

Cluster topology and shared network settings are defined in:

```text

nodes.py

```

The configuration includes:

- Kubernetes server names

- Node addresses

- Initial server designation

- Kubernetes API virtual address

- kube-vip network interface

- K3s version

- Default gateway

- DNS servers

- DNS zone

For example:

```python

NODES = \[

    {"name": "k3s01", "ip": "192.0.2.11", "role": "server", "init": True},

    {"name": "k3s02", "ip": "192.0.2.12", "role": "server", "init": False},

    {"name": "k3s03", "ip": "192.0.2.13", "role": "server", "init": False},

]

VIP = "192.0.2.10"

```

Multiple automation components consume this configuration rather than maintaining independent copies of the topology.

This reduces configuration drift and provides a clear location for cluster-level changes.

## VM Creation and Discovery

PowerShell provides the bridge between the Windows/VMware environment and the Linux/Ansible configuration layer.

The root-level scripts divide the workflow into several operations.

### `clone_nodes.ps1`

Creates the Kubernetes VMs from the reusable base VM according to the nodes defined in `nodes.py`.

### `discover_nodes.ps1`

Discovers the temporary addresses assigned to newly created virtual machines.

This allows automation to locate a new VM before its permanent network configuration has been applied.

### `generate_bootstrap_inventory.ps1`

Creates the temporary Ansible inventory used during the bootstrap phase.

### `bootstrap_nodes.ps1`

Coordinates initial node configuration and validation.

The bootstrap process includes configuration and checks around:

- Hostname

- Static addressing

- Default route

- Netplan

- cloud-init state

- Gateway reachability

- DNS configuration

After bootstrap and restart, the nodes are available at the addresses defined by the cluster configuration.

## Ansible Architecture

Ansible handles node preparation and Kubernetes cluster construction.

The main orchestration is defined in:

```text

ansible/site.yml

```

The workflow is intentionally ordered.

### 1. Prepare All Servers

The `k3s-common` role prepares all Kubernetes server nodes with common prerequisites.

### 2. Initialize the First Server

The server marked as the initial node is configured first.

It initializes the K3s cluster and embedded etcd datastore.

### 3. Deploy kube-vip

kube-vip is deployed after the initial server becomes available.

It provides the virtual API endpoint used to access the Kubernetes control plane.

### 4. Join Additional Servers

The remaining server nodes are joined to the cluster sequentially.

The join play uses:

```yaml

serial: 1

```

This is deliberate.

During development, concurrent control-plane joins exposed an etcd learner issue. Changing the workflow to sequential joins produced a more controlled and reliable cluster-formation process.

This is an example of the automation being changed in response to observed platform behavior rather than treating the initial implementation as final.

## K3s Control Plane

The Kubernetes control plane consists of three K3s server nodes:

| Node | Example Address | Function |

| --- | --- | --- |

| `k3s01` | `192.0.2.11` | Server / initial cluster node |

| `k3s02` | `192.0.2.12` | Server |

| `k3s03` | `192.0.2.13` | Server |

K3s is pinned to:

```text

v1.36.4+k3s1

```

Pinning the version makes the build more deterministic and prevents an automated rebuild from silently consuming a different K3s release.

## Embedded etcd

The three K3s server nodes use embedded etcd as the control-plane datastore.

This keeps the HA architecture compact while allowing Kubernetes control-plane state to be replicated across the server nodes.

The design intentionally uses an odd number of server nodes to support etcd quorum.

The validation performed for this project includes a controlled failure of one server. It should not be interpreted as validation of arbitrary multi-node failure scenarios.

## Kubernetes API High Availability

Clients interact with the Kubernetes API through a virtual address rather than the address of a specific server.

Example public configuration:

```text

192.0.2.10

```

kube-vip manages ownership of this virtual address across the control-plane nodes.

This decouples the API endpoint from an individual VM.

During controlled failure testing, the node holding the virtual address was powered off. The VIP moved to another control-plane server and remained there after the original node returned.

This validated API endpoint failover for the single-node failure scenario tested.

## Cluster Token Handling

The K3s server join token is not stored in the repository.

During cluster construction, Ansible:

1\. Waits for the initial server token to become available.

2\. Reads the token from the initialized server.

3\. Transfers it to joining servers at runtime.

4\. Stores the joining-server copy with restricted permissions.

5\. Uses the token file during the K3s join operation.

Sensitive Ansible tasks use `no_log` where appropriate so that the runtime token is not intentionally written into normal automation output.

This separates runtime cluster credentials from source-controlled configuration.

## Generated Inventory

The permanent Ansible inventory is generated from `nodes.py` by:

```text

ansible/inventory/generate_inventory.py

```

This produces the inventory required by the Ansible cluster workflow without requiring node definitions to be maintained independently in multiple files.

Generated inventory files are excluded from Git.

The architecture therefore follows the flow:

```text

nodes.py

   |

   +--> PowerShell automation

   |

   +--> Ansible inventory generator

   |

   +--> Cluster topology and network configuration

```

## Provisioning and GitOps Boundary

This repository is responsible primarily for creating the infrastructure and Kubernetes foundation.

Ongoing Kubernetes desired state is maintained separately through GitOps.

```text

homelab-k3s

     |

     | builds

     v

Kubernetes Cluster

     ^

     | reconciles

     |

home-cluster

```

This separation provides two distinct responsibilities:

**Infrastructure provisioning**

- VM image creation

- VM lifecycle

- Node bootstrap

- Kubernetes installation

- Control-plane formation

- API high availability

**GitOps desired state**

- Kubernetes platform services

- Networking components

- Storage components

- Observability

- Application workloads

Flux provides the reconciliation mechanism between the GitOps repository and the running cluster.

## Flux Foundation

Flux 2.9.5 has been bootstrapped against the V2 cluster.

Validation included:

- Git source reconciliation

- Kustomization reconciliation

- Healthy Flux controllers

- Successful synchronization of the V2 GitOps branch

This establishes the GitOps control plane but does not imply that every planned platform service has already been deployed.

Platform capabilities are being introduced incrementally after the Kubernetes foundation is validated.

## Failure and Recovery Model

High availability is treated as a behavior to test rather than a property inferred solely from configuration.

The current validated scenario is:

```text

Three healthy control-plane nodes

              |

              v

Power off current kube-vip owner

              |

              v

VIP transfers to surviving server

              |

              v

Kubernetes remains accessible

              |

              v

Original server powered on

              |

              v

Server rejoins cluster

              |

              v

Single VIP owner remains

```

This test provides evidence for recovery from the specific single-server failure exercised.

Further failure testing remains part of the platform roadmap.

## Design Decisions

Several architecture decisions are documented separately under:

```text

docs/decisions/

```

The major decisions include:

- K3s as the Kubernetes distribution

- Embedded etcd for the HA datastore

- kube-vip for the Kubernetes API endpoint

- Flux for GitOps reconciliation

These records document not just what technology was selected, but the engineering reasoning and tradeoffs behind each choice.

## Current Architecture Boundary

The currently validated foundation includes:

- Automated Ubuntu VM image construction

- Automated VM creation and bootstrap

- Generated Ansible inventory

- Three-node K3s server cluster

- Embedded etcd

- kube-vip API endpoint

- Single-node control-plane failure and recovery testing

- Flux GitOps foundation

The next layers of the platform include:

- MetalLB

- Ingress

- Persistent storage

- Observability

- Application workloads

- Expanded resilience testing

Each layer is intended to be introduced and validated incrementally rather than added as an untested platform stack.
