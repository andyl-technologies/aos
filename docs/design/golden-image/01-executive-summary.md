# 1. Executive Summary

Today AOS builds five separate disk images, one per system variant. Each
image bakes in its role at Nix evaluation time. Changing a machine's role
requires re-imaging. This proposal consolidates everything into a **single
minimal golden image** that:

- Contains a **minimal** package set: k3s, containerd, Cilium, and the
  security stack. No monitoring agents, web servers, or identity daemons.
- Boots into a **fully hardened state** with no cloud-init needed: SELinux
  enforcing, default-deny firewall, key-only SSH, dm-verity-protected root.
- Uses **cloud-init** to activate a role (`server`, `k8s-worker`,
  `k8s-control-plane`) by writing systemd units and configuration files to
  the ephemeral overlay `/etc`.
- Uses **k3s** instead of full Kubernetes (kubelet/kubeadm/kubectl) for a
  ~72 MB single binary that embeds etcd and CoreDNS.
- Uses **Cilium** as the CNI, kube-proxy replacement, ingress controller,
  and local IP provisioner (eBPF-based, includes Envoy for L7).
- Uses **ZFS** as a CSI persistent volume provider for pod storage.
- Re-applies configuration from the authoritative datasource on **every
  boot**, preventing configuration drift.
- Supports **generation-based updates** via APM, with multiple coexisting
  system generations, instant switching, and rollback to any previous
  generation. Live switching via `systemd soft-reboot` avoids full reboot.
- Deploys to **AWS, GCP, Azure, bare-metal, and KVM/QEMU** from a single
  artifact.

## Key Architectural Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Single image for all roles | Yes | One artifact to build, test, sign, distribute |
| k3s instead of full K8s | Yes | ~72 MB single binary vs ~400 MB for kubelet+kubeadm+kubectl+etcd |
| Cilium as CNI + ingress | Yes | eBPF-native, replaces kube-proxy + flannel + ingress controller |
| ZFS for persistent volumes | Yes | Already present for /var; CSI driver provides PVs to pods |
| Minimal image (no monitoring/identity agents) | Yes | Operators deploy monitoring as K8s workloads |
| Cloud-init in userspace, not initrd | Userspace | Needs overlay /etc, ZFS /var, and network |
| Ignition retained for storage | Yes | ZFS pool creation requires initrd phase |
| /etc regenerated every boot | Yes | Datasource is single source of truth; no drift |
| Services disabled via absent unit files | Yes | Leverages existing `lib.mkIf cfg.enable` pattern |
| Pre-rendered unit templates | Yes | Avoids Nix evaluation at runtime |
| Generation-based updates | Yes | Multiple roots coexist; switch/rollback to any generation via `aos system` |
| APM for system updates | Yes | System generations downloaded as store closures; `aos gc --generations` for cleanup |
