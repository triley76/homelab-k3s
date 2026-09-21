# Validation

## Overview

This document records the validation performed against the V2 Kubernetes platform.

The purpose is to distinguish between:

- Architecture that has been implemented

- Behavior that has been directly observed

- Capabilities that remain planned or require additional testing

The validation described here applies to the specific lab configuration and test scenarios exercised. It is not intended to represent production certification, exhaustive resilience testing, or a guarantee of application-level availability.

## Validated Platform

The tested platform consists of:

| Component | Validated Configuration |

| --- | --- |

| Kubernetes distribution | K3s |

| K3s version | `v1.36.4+k3s1` |

| Control-plane nodes | 3 |

| Datastore | Embedded etcd |

| API high availability | kube-vip |

| GitOps | Flux 2.9.5 |

| VM platform | VMware Workstation |

| Guest operating system | Ubuntu Server 24.04 |

The public repository substitutes RFC 5737 documentation addresses for the private addressing used by the working lab.

## Automation Validation

The automation has been exercised across the major stages required to construct the cluster.

### Packer

The Packer workflow has been used to create the reusable Ubuntu VMware base image used by the Kubernetes nodes.

The build establishes a consistent operating-system foundation before Kubernetes-specific configuration is applied.

### PowerShell

The PowerShell automation has been used for:

- VM cloning

- Guest discovery

- Bootstrap inventory generation

- Node bootstrap coordination

- Post-bootstrap validation

The scripts consume the common cluster configuration from `nodes.py`.

### Ansible

Ansible has been used to:

- Prepare Kubernetes server nodes

- Initialize the first K3s server

- Deploy kube-vip

- Join additional K3s servers

- Configure the three-node control plane

The top-level Ansible playbooks have also been syntax-checked as part of repository validation.

## Cluster Formation

The V2 automation successfully constructed a three-node K3s server cluster using embedded etcd.

Expected cluster members:

```text

k3s01

k3s02

k3s03

```

All three servers successfully joined the cluster.

K3s was pinned to:

```text

v1.36.4+k3s1

```

rather than allowing the build to select an unspecified latest version.

## Sequential Control-Plane Join Validation

An important finding during development involved the process used to add the additional K3s servers.

An earlier workflow attempted control-plane joins concurrently.

Testing exposed an etcd learner issue during this process.

The join workflow was changed to:

```yaml

serial: 1

```

This causes additional control-plane nodes to join sequentially.

The cluster subsequently formed successfully using the serialized workflow.

This behavior is retained in the automation as an engineering decision derived from observed cluster behavior.

## Kubernetes API Validation

kube-vip provides a virtual address for the Kubernetes API.

Rather than requiring clients to connect directly to one control-plane server, the API is accessed through the virtual endpoint.

Validation confirmed that:

- The VIP was present on a control-plane server.

- The Kubernetes API was reachable through the VIP.

- A single server owned the VIP during normal operation.

- VIP ownership could transfer during the controlled failure test.

## Controlled Single-Node Failure Test

A controlled failure test was performed against the running three-node cluster.

### Initial State

Before the test:

- Three K3s server VMs were running.

- The Kubernetes nodes were participating in the cluster.

- kube-vip had a single active owner.

- The Kubernetes API was available through the virtual address.

### Failure Injection

The entire VM hosting the kube-vip address was powered off.

This tested more than a Kubernetes process restart. From the cluster's perspective, the server itself disappeared.

### Observed Behavior

After the VM was powered off:

- The kube-vip address moved to another control-plane server.

- The surviving Kubernetes nodes remained available.

- The Kubernetes API continued to be served through the virtual endpoint.

- Workloads were able to reschedule onto surviving capacity.

This demonstrated successful control-plane API failover for the specific single-node failure scenario tested.

## Node Recovery Test

The powered-off server was subsequently restarted.

Observed behavior included:

- The server returned to the network.

- K3s restarted.

- The server rejoined the existing cluster.

- The cluster returned to three participating server nodes.

- kube-vip remained on the surviving server that had assumed ownership.

- Only one server owned the VIP.

The returning node therefore did not cause competing VIP ownership during the observed recovery.

## What the Failure Test Demonstrates

The controlled test provides direct evidence for the following scenario:

```text

Healthy three-node cluster

          |

          v

Current VIP owner fails

          |

          v

VIP moves to surviving server

          |

          v

API remains available

          |

          v

Failed server returns

          |

          v

Server rejoins cluster

          |

          v

Single VIP owner remains

```

The result supports the architecture's intended behavior under the tested loss of one control-plane VM.

## What Has Not Been Claimed

The validation scope is intentionally narrow.

The test does **not** establish that the platform can tolerate every possible failure condition.

In particular, this validation does not claim:

- Arbitrary multi-node failure tolerance

- Survival of simultaneous loss of two control-plane servers

- Zero application downtime

- Zero interrupted client connections

- Storage-level application resilience

- Production-scale performance

- Production security certification

- Disaster recovery across physical sites

- Automated recovery from every etcd failure mode

Those scenarios require separate tests and, in some cases, additional architecture.

The distinction between configured capability and observed behavior is intentional.

## Flux GitOps Validation

Flux 2.9.5 has been bootstrapped against the V2 cluster.

The validated GitOps foundation includes:

- Flux controllers installed and healthy

- Git source reconciliation

- Kustomization reconciliation

- Synchronization from the V2 GitOps branch

A validated reconciliation reached revision:

```text

feature/v2-cluster@sha1:153da6ff

```

This demonstrates that the GitOps control plane can retrieve and reconcile the desired state from the companion repository.

It does not imply that every planned Kubernetes platform service has already been deployed.

## Repository Validation

Before preparing the public portfolio version of this repository, the automation was subjected to additional static validation.

### Python

The Python configuration and inventory-generation code was compiled with Python's `py_compile` mechanism.

The inventory generator was also executed against the sanitized public configuration and successfully generated the expected three-node inventory.

### PowerShell

The PowerShell scripts were parsed to detect syntax errors.

The scripts validated include:

```text

bootstrap_nodes.ps1

clone_nodes.ps1

discover_nodes.ps1

generate_bootstrap_inventory.ps1

config/workstation.example.ps1

```

### Ansible

The Ansible environment used for repository validation reported:

```text

ansible-core 2.16.3

Python 3.12.3

Jinja 3.1.2

```

The top-level playbooks were syntax-checked:

```text

bootstrap.yml

deploy-kube-vip.yml

init-first-server.yml

join-servers.yml

preflight.yml

site.yml

```

The bootstrap playbook depends on the temporary bootstrap inventory generated during VM discovery. Static syntax validation therefore confirms the playbook structure but does not substitute for a live bootstrap execution.

### Packer

The Packer configuration was processed with `packer fmt` and passed `packer fmt -check`.

A validation run using placeholder workstation paths progressed through HCL/configuration parsing and produced expected environmental errors for deliberately nonexistent example inputs.

This repository therefore does not claim that the sanitized public example values themselves constitute a complete Packer build environment.

## Public Repository Sanitization

The public portfolio tree was rebuilt separately from the original repository history.

Validation of the clean tree included checks for:

- Private lab addressing

- Private DNS names

- Personal filesystem paths

- Personal email references

- SSH private-key material

- Password hashes from the original environment

- GitHub token patterns

- Other obvious credential material

The tracked public configuration uses documentation/example values instead.

Runtime-sensitive values such as the K3s cluster token are obtained during deployment rather than committed to source control.

Generated inventories and workstation-specific configuration are excluded through `.gitignore`.

## Current Validation Boundary

The following foundation has direct implementation and validation evidence:

```text

Packer Ubuntu VM foundation

            |

            v

PowerShell VM automation

            |

            v

Node bootstrap

            |

            v

Generated Ansible inventory

            |

            v

Three-node K3s control plane

            |

            v

Embedded etcd

            |

            v

kube-vip API endpoint

            |

            v

Single-node failover/recovery test

            |

            v

Flux GitOps reconciliation

```

## Planned Validation

As additional platform layers are introduced, validation can expand to include:

- MetalLB address allocation and failover behavior

- Ingress routing

- Persistent-storage behavior

- Workload recovery with persistent data

- Observability and alerting

- Application-level availability measurements

- Reboot and maintenance scenarios

- Additional control-plane failure scenarios

- Backup and restore

- etcd recovery procedures

- Full rebuild testing from a clean environment

The intent is to keep validation evidence alongside the platform as it evolves.

## Validation Philosophy

A configured feature is not automatically considered a validated capability.

For this project, the preferred progression is:

```text

Design

  |

  v

Automate

  |

  v

Deploy

  |

  v

Observe

  |

  v

Test failure

  |

  v

Document evidence

  |

  v

Iterate

```

This keeps the project focused on observable engineering behavior rather than a checklist of installed technologies.
