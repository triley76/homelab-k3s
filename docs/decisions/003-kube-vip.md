# ADR-003: Use kube-vip for the Kubernetes API Endpoint

## Status

Accepted

## Context

The V2 platform uses three K3s server nodes with embedded etcd.

A multi-server control plane requires a stable Kubernetes API endpoint that does not depend on clients knowing which individual server currently provides access.

Without a shared endpoint, cluster clients and automation would need to target a specific server address:

```text

192.0.2.11

192.0.2.12

192.0.2.13

```

That would make the selected server an unnecessary dependency for API access.

The platform therefore requires a virtual endpoint that can move between control-plane nodes when necessary.

## Decision

Use **kube-vip** to provide a virtual IP address for the Kubernetes API.

The example topology defines:

```text

VIP: 192.0.2.10

Interface: ens160

```

These values are defined centrally in `nodes.py` and can be changed for another environment.

The resulting API topology is:

```text

                  Clients

                     |

                     v

              192.0.2.10

             Kubernetes VIP

                     |

          +----------+----------+

          |          |          |

          v          v          v

        k3s01      k3s02      k3s03

          |          |          |

          +----------+----------+

                     |

               embedded etcd

```

At a given time, the VIP is owned by one participating server.

If that server becomes unavailable, kube-vip can move the address to another eligible server.

## Rationale

### Stable API Endpoint

Clients should not need to know which K3s server currently owns the API endpoint.

Using a VIP provides a single address for:

- `kubectl`

- Cluster administration

- Automation

- GitOps components

- Other Kubernetes API clients

This separates API access from the lifecycle of an individual control-plane node.

### High-Availability Testing

A central objective of the V2 platform is to exercise actual failure and recovery behavior rather than simply construct multiple servers.

kube-vip provides a mechanism for testing whether API access can survive the loss of the server currently hosting the virtual address.

That behavior has been exercised in a controlled full-VM failure test.

### Compact Architecture

A dedicated external load balancer would add another virtual machine, appliance, or service to the platform.

For this workstation-based lab, kube-vip provides the required control-plane endpoint behavior without adding a separate load-balancer tier.

This keeps the architecture compact while still exposing the operational behavior of a movable API endpoint.

### Configuration as Code

The VIP and network interface are defined in the repository's central cluster configuration.

For example:

```python

VIP = "192.0.2.10"

KUBE_VIP_INTERFACE = "ens160"

```

The kube-vip configuration is then generated and deployed through the infrastructure automation.

This keeps the API endpoint definition visible and version controlled rather than relying on an undocumented manual configuration.

## Deployment Sequence

kube-vip is deployed after initialization of the first K3s server and before the remaining servers join.

The orchestration sequence is:

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

This gives the cluster a stable API endpoint early in the control-plane construction process.

## Alternatives Considered

### Direct Node Address

Clients could target one K3s server directly.

This is simpler, but it makes that server's availability part of the API access path and does not provide the failover behavior required by the platform design.

### Dedicated Load Balancer

A separate load balancer could provide a stable endpoint in front of the K3s servers.

That is a valid architecture and may be appropriate in environments where dedicated load-balancing infrastructure already exists.

For this lab, it would add infrastructure and lifecycle overhead without being necessary to achieve the current API high-availability objectives.

### DNS-Based Failover

DNS records could potentially be changed to direct clients toward another server.

That approach introduces DNS update and caching behavior into the recovery path and does not provide the same movable-address model used by the current architecture.

## Consequences

### Positive

- Provides a stable Kubernetes API address

- Removes the need for clients to select an individual control-plane server

- Supports controlled API endpoint failover testing

- Does not require a separate load-balancer VM

- Fits the workstation resource constraints of the lab

- Integrates with the existing automated cluster build

- Keeps VIP configuration in source control

### Tradeoffs

- kube-vip becomes part of the control-plane availability design

- Correct network-interface configuration is required

- The VIP must not conflict with another device on the network

- Network behavior must support movement of the virtual address between nodes

- API VIP availability alone does not prove that every Kubernetes control-plane component or workload remains healthy

- Failure behavior should be tested rather than inferred from configuration alone

## Validation

The V2 platform has been tested by powering off the K3s server that currently owned the API VIP.

During the controlled test:

1\. The current VIP-owning server was powered off.

2\. The VIP moved to another K3s server.

3\. The two surviving Kubernetes servers remained available.

4\. Kubernetes API access continued through the VIP.

5\. Workloads were able to reschedule onto surviving capacity.

6\. The powered-off server was restarted.

7\. The server rejoined the cluster.

8\. The VIP remained assigned to a single server after recovery.

This validates the tested single-server failure and recovery path.

It does not establish zero-downtime behavior, tolerance of multiple simultaneous server failures, or every possible network failure scenario.

Detailed validation scope is maintained in:

```text

docs/validation.md

```

## Relationship to Service Load Balancing

The Kubernetes API VIP and application service load balancing are separate concerns.

kube-vip in this architecture provides the control-plane API endpoint.

Future platform work may use a separate mechanism, such as MetalLB, for Kubernetes `LoadBalancer` services.

Keeping these responsibilities distinct makes the architecture easier to reason about:

```text

Control-plane traffic

        |

        v

     kube-vip

        |

        v

 Kubernetes API

Application traffic

        |

        v

 Service load balancing

        |

        v

 Kubernetes workloads

```

## Result

kube-vip provides a compact and automatable stable endpoint for the three-node K3s control plane.

It supports the platform's current high-availability objectives without requiring dedicated external load-balancer infrastructure and has been validated through a controlled single-server failure and recovery test.

The decision can be revisited if future requirements justify moving API load balancing to dedicated infrastructure.
