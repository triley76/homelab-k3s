# ADR-002: Use Embedded etcd for the K3s Control Plane

## Status

Accepted

## Context

The V2 platform is designed as a three-node Kubernetes control plane rather than a single-server cluster.

The control-plane datastore therefore needs to support:

- Multiple K3s server nodes

- High-availability operation

- Quorum-based consistency

- Server failure and recovery testing

- Automated cluster construction

- A practical footprint for a workstation-based lab

K3s supports multiple datastore configurations, including embedded etcd and external database services.

Running a separate datastore would add another infrastructure layer that would need to be provisioned, secured, monitored, backed up, and made highly available.

For the current scope of the platform, that additional infrastructure is not required.

## Decision

Use **K3s embedded etcd** as the datastore for the three-node Kubernetes control plane.

The topology is:

```text

              Kubernetes API VIP

                     |

         +-----------+-----------+

         |           |           |

         v           v           v

       k3s01       k3s02       k3s03

         |           |           |

         +-----------+-----------+

                     |

               embedded etcd

```

The first server initializes the cluster. The remaining servers join the existing cluster sequentially.

## Rationale

### High-Availability Control Plane

Embedded etcd allows the K3s server nodes to participate in the Kubernetes datastore without requiring a separate database tier.

The three-server architecture provides an odd-sized etcd membership suitable for quorum-based operation.

This allows the platform to exercise control-plane failure and recovery behavior while keeping the datastore architecture understandable and compact.

### Reduced Infrastructure Complexity

An external datastore would introduce additional systems and lifecycle concerns.

Those could be useful subjects for a different lab, but they are not required to achieve the current goals of:

- Multi-node Kubernetes

- Control-plane high availability

- API endpoint failover

- Node failure testing

- Automated cluster construction

- GitOps experimentation

Using embedded etcd keeps the focus on the Kubernetes platform itself.

### Automation

The embedded datastore fits naturally into the Ansible orchestration model.

Cluster construction follows an explicit sequence:

```text

Prepare all servers

        |

        v

Initialize k3s01

        |

        v

Deploy kube-vip

        |

        v

Join k3s02

        |

        v

Join k3s03

```

The first server creates the cluster and provides the runtime join token used by subsequent servers.

The token is retrieved during automation rather than stored in the repository.

### Controlled Server Joins

During V2 development, concurrent server joins produced an etcd learner-related issue.

The orchestration was changed so additional K3s servers join sequentially using Ansible:

```yaml

serial: 1

```

This makes server admission deterministic and avoids attempting multiple control-plane joins simultaneously.

The behavior is encoded in the automation rather than relying on an operator to remember the required sequence.

## Alternatives Considered

### External etcd

A separately managed etcd cluster could provide greater separation between the Kubernetes control plane and datastore.

It would also require additional virtual machines or services, networking, lifecycle automation, monitoring, and failure handling.

That complexity is not currently justified by the objectives of this workstation-based platform.

### External SQL Datastore

K3s can support external datastore configurations using supported database systems.

This could be useful where an organization already operates a highly available database service or where datastore responsibilities need to be separated from Kubernetes nodes.

The lab does not currently have that requirement.

### Single-Server Datastore

A single K3s server would be simpler and consume fewer resources.

It would not support the multi-server control-plane and failure scenarios that are central to the V2 architecture.

## Consequences

### Positive

- No separate datastore infrastructure is required

- Datastore membership follows the K3s server topology

- Supports a three-server high-availability control plane

- Enables quorum and server-failure testing

- Reduces the number of independent infrastructure components

- Integrates cleanly with the existing Ansible build process

### Tradeoffs

- Control-plane and datastore roles share the same server nodes

- etcd health is directly tied to the health and membership of those nodes

- Quorum must be preserved for datastore operations

- Cluster backup and restore procedures must account for etcd state

- Adding or removing server nodes requires awareness of etcd membership

- The current validation does not establish tolerance for arbitrary multiple simultaneous server failures

## Failure Model

The current architecture contains three K3s server nodes participating in the embedded-etcd control plane.

A controlled test powered off the server that owned the Kubernetes API virtual IP.

During that test:

- The API VIP moved to another server

- The two surviving Kubernetes server nodes remained available

- Kubernetes API access continued through the VIP

- Workloads were able to reschedule onto surviving capacity

- The failed server later rejoined the cluster after being powered back on

- The VIP remained owned by a single server after recovery

This validates the tested single-server failure scenario.

It should not be interpreted as validation of every etcd failure mode or multiple simultaneous server failures.

## Operational Implications

Because etcd is the authoritative datastore for Kubernetes cluster state, future operational work should include:

- etcd snapshot strategy

- Snapshot retention

- Restore testing

- Quorum-loss recovery procedures

- Server replacement procedures

- Monitoring of datastore health

These are intentionally treated as future platform capabilities rather than claimed as completed features.

## Result

Embedded etcd provides the datastore architecture needed for the current three-node K3s platform without introducing a separate database tier.

It supports the project's high-availability and failure-testing goals while preserving a compact, reproducible architecture appropriate for the lab.

The decision can be revisited if future requirements justify separating datastore services from the Kubernetes server nodes.
