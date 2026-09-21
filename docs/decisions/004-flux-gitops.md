# ADR-004: Use Flux for GitOps Reconciliation

## Status

Accepted

## Context

The V2 platform separates infrastructure provisioning from ongoing Kubernetes platform configuration.

Packer, PowerShell, and Ansible construct the virtual machines and Kubernetes control plane. Once Kubernetes is operational, the platform needs a repeatable mechanism for managing cluster resources from version-controlled configuration.

Manually applying manifests with `kubectl` would make the running cluster dependent on operator actions that are not necessarily captured in source control.

The platform therefore requires a GitOps reconciliation layer that can continuously compare declared configuration in Git with resources in the Kubernetes cluster.

## Decision

Use **Flux** as the GitOps reconciliation mechanism for Kubernetes platform configuration.

The validated V2 environment uses Flux 2.9.5.

The `homelab-k3s` repository is responsible for constructing the Kubernetes infrastructure. The companion `home-cluster` repository represents declarative cluster configuration consumed by Flux.

The responsibility boundary is:

    homelab-k3s
         |
         | Packer / PowerShell / Ansible
         v
    Kubernetes control plane
         |
         | bootstrap
         v
        Flux
         |
         | reconcile
         v
    home-cluster
         |
         v
    Kubernetes platform resources

## Rationale

### Declarative Cluster Management

GitOps provides a version-controlled desired state for Kubernetes resources.

Rather than relying on a sequence of manually executed commands, configuration can be reviewed, committed, and reconciled against the cluster.

This provides a clearer relationship between repository state and cluster state.

### Separation of Provisioning and Platform Configuration

The platform separates two lifecycle concerns.

**Infrastructure provisioning**

- Ubuntu VM construction
- VM cloning and discovery
- Operating-system configuration
- K3s installation
- Embedded-etcd control-plane formation
- kube-vip deployment

**GitOps configuration**

- Kubernetes platform services
- Networking components
- Storage components
- Observability
- Application workloads

This boundary allows the Kubernetes infrastructure to be rebuilt without requiring all platform services to be embedded in the provisioning automation.

### Continuous Reconciliation

Flux continuously reconciles declared configuration rather than treating deployment as a one-time operation.

This provides a foundation for detecting and correcting configuration drift as additional platform components are introduced.

### Version-Controlled Change History

Platform configuration changes can be represented as Git commits.

This provides an auditable history of intended changes and supports controlled experimentation in the lab.

## Alternatives Considered

### Manual kubectl Application

Kubernetes manifests could be applied directly using `kubectl`.

This is useful for troubleshooting and experimentation, but it does not provide continuous reconciliation and can make the running cluster dependent on undocumented operator actions.

### Ansible for Ongoing Kubernetes Resources

Ansible could manage both infrastructure provisioning and Kubernetes platform resources.

That would reduce the number of tools, but it would also combine infrastructure construction with ongoing cluster desired-state management.

The V2 architecture intentionally keeps those responsibilities separate.

### Other GitOps Controllers

Other GitOps implementations could provide similar declarative reconciliation capabilities.

Flux was selected for this lab because it supports a repository-driven reconciliation model and integrates with the desired separation between infrastructure provisioning and cluster configuration.

The decision is specific to this platform and is not intended to establish Flux as universally preferable to other GitOps implementations.

## Consequences

### Positive

- Kubernetes platform configuration is represented in Git.
- Desired state can be reviewed before reconciliation.
- Flux provides continuous reconciliation after the initial cluster build.
- Infrastructure provisioning remains separate from ongoing platform configuration.
- Platform services can be introduced incrementally.
- Git history provides a record of configuration changes.
- The architecture provides a foundation for drift correction and repeatable cluster configuration.

### Tradeoffs

- Flux introduces another platform component that must be operated and understood.
- Git repository availability becomes relevant to reconciliation.
- Repository structure and dependency ordering require deliberate design.
- GitOps does not eliminate the need for operational validation.
- Incorrect desired state can also be reconciled automatically, making review and validation important.
- Secrets require an appropriate GitOps-compatible management strategy rather than being committed directly to the repository.

## Validation

Flux 2.9.5 has been bootstrapped and validated against the V2 Kubernetes cluster.

Observed validation included:

- Flux controllers installed and healthy
- Git source reconciliation functioning
- Kustomization reconciliation functioning
- Synchronization from the V2 GitOps branch
- Successful reconciliation at revision `feature/v2-cluster@sha1:153da6ff`

This establishes the GitOps foundation and verifies communication between the running cluster and the GitOps repository.

It does **not** establish that every planned platform service has already been deployed through Flux.

Networking services, ingress, persistent storage, observability, and application workloads are being introduced incrementally and validated separately.

## Result

Flux provides the reconciliation layer between the running Kubernetes cluster and version-controlled platform configuration.

The resulting lifecycle is:

    Packer
      |
      v
    PowerShell
      |
      v
    Ansible
      |
      v
    K3s HA control plane
      |
      v
    Flux
      |
      v
    Git-managed platform configuration

This establishes a clear boundary between reproducible infrastructure construction and declarative Kubernetes platform management.