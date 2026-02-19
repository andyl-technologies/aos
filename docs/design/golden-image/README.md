# Golden Image with Cloud-Init Provisioning

> **Status:** Proposal
>
> Replace all five AOS system variants (`base`, `server`, `seed`,
> `k8s-worker`, `k8s-control-plane`) with a single minimal golden image.
> All runtime configuration -- hostname, networking, users, firewall,
> Kubernetes role, services -- moves from Nix evaluation time into
> cloud-init processing at boot time.

---

## Table of Contents

1. [Executive Summary](01-executive-summary.md)
2. [Architecture Overview](02-architecture-overview.md)
3. [Golden Image Composition](03-golden-image-composition.md)
4. [Cloud-Init Integration](04-cloud-init-integration.md)
5. [Security Architecture](05-security-architecture.md)
6. [Kubernetes Activation (k3s)](06-kubernetes-activation.md)
7. [Networking](07-networking.md)
8. [Firewall](08-firewall.md)
9. [Persistent Storage (ZFS)](09-persistent-storage.md)
10. [Update and Lifecycle](10-update-and-lifecycle.md)
11. [Migration Path](11-migration-path.md)
12. [Open Questions](12-open-questions.md)

## Related Documents

- [Envoy Proxy Implementation Plan](../../implementation/envoyproxy/) — Phased plan for building Envoy from source in AOS (OpenJDK, Bazel, Envoy)
