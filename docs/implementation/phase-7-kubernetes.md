# Phase 7: Container and Kubernetes Packages

**Plan Phase:** 5 (Container + K8s Packages) + relevant modules from Phase 6

## Objective

Build all container runtime and Kubernetes packages (`pkgs/containers/`, `pkgs/kubernetes/`) using the production stdenv. This includes containerd, runc, kubelet, kubeadm, kubectl, crictl, CNI plugins, Helm, and supporting tools. The packages provide a pluggable CNI architecture: standard CNI plugin binaries are included, but no specific CNI implementation is baked in -- the CNI plugin (Cilium, Calico, Flannel) is deployed at runtime via Helm or DaemonSet.

## Prerequisites

- Phase 2 complete: Production stdenv with GCC 13.3 + glibc 2.39
- Phase 3 complete: Kernel with all K8s-required features (cgroups v2, namespaces, eBPF, OverlayFS, bridge, VXLAN, IP_VS, seccomp)
- Go build system available (either bootstrapped or pre-built Go wrapped in a derivation)
- `pkgs/containers/libseccomp.nix` available for runc

## Deliverables

### Container Runtime (`pkgs/containers/`)

- `pkgs/containers/containerd.nix` -- containerd 1.7.24
- `pkgs/containers/runc.nix` -- runc 1.2.4
- `pkgs/containers/libseccomp.nix` -- libseccomp (runc dependency)

### Kubernetes (`pkgs/kubernetes/`)

- `pkgs/kubernetes/kubelet.nix` -- kubelet 1.31.4
- `pkgs/kubernetes/kubeadm.nix` -- kubeadm 1.31.4
- `pkgs/kubernetes/kubectl.nix` -- kubectl 1.31.4
- `pkgs/kubernetes/crictl.nix` -- crictl 1.31.1
- `pkgs/kubernetes/cni-plugins.nix` -- CNI plugins 1.6.1
- `pkgs/kubernetes/helm.nix` -- Helm 3.16.4
- `pkgs/kubernetes/nerdctl.nix` -- nerdctl (Docker-compatible CLI for containerd)
- `pkgs/kubernetes/ethtool.nix` -- ethtool 6.11
- `pkgs/kubernetes/socat.nix` -- socat 1.8.0.1 (needed for `kubectl port-forward`)
- `pkgs/kubernetes/conntrack-tools.nix` -- conntrack-tools 1.4.8
- `pkgs/kubernetes/ipvsadm.nix` -- ipvsadm 1.31

## Detailed Task Checklist

### 7.1 Container Runtime Packages

- [ ] Write `pkgs/containers/libseccomp.nix`:
  - [ ] Required by runc for seccomp filtering
  - [ ] Standard autoconf build
- [ ] Write `pkgs/containers/runc.nix` (runc 1.2.4):
  - [ ] Go build system
  - [ ] `runtimeDeps`: libseccomp
  - [ ] Verify: `runc --version`
- [ ] Write `pkgs/containers/containerd.nix` (containerd 1.7.24):
  - [ ] Go build system
  - [ ] Install: `containerd`, `containerd-shim-runc-v2`, `ctr`
  - [ ] Verify: `containerd --version`

### 7.2 Kubernetes Core Packages

- [ ] Write `pkgs/kubernetes/kubelet.nix` (1.31.4):
  - [ ] Go build or pre-built binary wrapped in derivation
  - [ ] Verify: `kubelet --version`
- [ ] Write `pkgs/kubernetes/kubeadm.nix` (1.31.4):
  - [ ] For control plane bootstrapping
  - [ ] Verify: `kubeadm version`
- [ ] Write `pkgs/kubernetes/kubectl.nix` (1.31.4):
  - [ ] Kubernetes CLI
  - [ ] Verify: `kubectl version --client`
- [ ] Write `pkgs/kubernetes/crictl.nix` (1.31.1):
  - [ ] CRI-compatible container runtime CLI
  - [ ] Verify: `crictl --version`

### 7.3 CNI Plugins

- [ ] Write `pkgs/kubernetes/cni-plugins.nix` (1.6.1):
  - [ ] Standard CNI plugins: bridge, loopback, host-local, portmap, firewall, tuning
  - [ ] Additional: bandwidth, dhcp, macvlan, ipvlan, vlan, ptp
  - [ ] Install to store path (symlinked to `/opt/cni/bin/` by the module)
  - [ ] No CNI config baked in -- config is written at runtime by the deployed CNI plugin

### 7.4 Supporting Tools

- [ ] Write `pkgs/kubernetes/helm.nix` (3.16.4): Kubernetes package manager
- [ ] Write `pkgs/kubernetes/nerdctl.nix`: Docker-compatible CLI for containerd
- [ ] Write `pkgs/kubernetes/ethtool.nix` (6.11): Network interface configuration
- [ ] Write `pkgs/kubernetes/socat.nix` (1.8.0.1): Required for `kubectl port-forward`
- [ ] Write `pkgs/kubernetes/conntrack-tools.nix` (1.4.8): Connection tracking utilities
- [ ] Write `pkgs/kubernetes/ipvsadm.nix` (1.31): IPVS administration (for kube-proxy IPVS mode)

### 7.5 Pluggable CNI Architecture

The image ships standard CNI plugin binaries and directory structure but does NOT include any specific CNI implementation. The CNI plugin is deployed at runtime.

- [ ] Standard CNI plugins at `/opt/cni/bin/` (via symlink from store)
- [ ] Empty `/etc/cni/net.d/` directory (on mutable /etc overlay)
- [ ] No default CNI config (no `10-bridge.conflist`)
- [ ] `/opt/cni/bin/` writable by init containers (CNI plugins like Cilium install additional binaries)
- [ ] CNI deployment workflow: Helm/DaemonSet writes config to `/etc/cni/net.d/`, optionally copies binaries to `/opt/cni/bin/`
- [ ] Node is NotReady until CNI plugin is deployed -- this is by design

### 7.6 Pluggable CSI Extension Points

- [ ] `/var/lib/kubelet/plugins/` exists and is writable (on ZFS)
- [ ] `/var/lib/kubelet/plugins_registry/` exists and is writable
- [ ] CSI drivers deploy as DaemonSets and register via these directories

### 7.7 Device Plugin Extension Point

- [ ] `/var/lib/kubelet/device-plugins/` exists and is writable
- [ ] Device plugins register via kubelet device-plugin API

### 7.8 containerd Configuration (Module-Generated)

Generated by `modules/kubernetes/containerd.nix`:
- [ ] gRPC address: `/run/containerd/containerd.sock`
- [ ] Sandbox image: `registry.k8s.io/pause:3.10`
- [ ] Snapshotter: `overlayfs` (default) or `zfs`
- [ ] Default runtime: runc
- [ ] SystemdCgroup: true
- [ ] CNI bin_dir: `/opt/cni/bin`
- [ ] CNI conf_dir: `/etc/cni/net.d`
- [ ] Delegate=yes for cgroup delegation to containers

### 7.9 kubelet Configuration (Module-Generated)

Generated by `modules/kubernetes/kubelet.nix`:
- [ ] Container runtime endpoint: `unix:///run/containerd/containerd.sock`
- [ ] Cgroup driver: systemd
- [ ] Cluster DNS: 10.96.0.10
- [ ] Static pod path: `/etc/kubernetes/manifests`
- [ ] protectKernelDefaults: true
- [ ] readOnlyPort: 0 (disabled)
- [ ] Resource reservations: 500m CPU, 512Mi memory
- [ ] Eviction thresholds: memory <256Mi, nodefs <10%, imagefs <15%
- [ ] All mutable paths on `/var`: kubelet state, containerd images, pod logs

### 7.10 Integration Verification

- [ ] `aos build kubelet` succeeds
- [ ] `aos build containerd` succeeds
- [ ] `aos build cni-plugins` succeeds
- [ ] K8s worker image boots in QEMU
- [ ] containerd starts, `crictl info` succeeds
- [ ] kubelet starts, registers as node (NotReady without CNI)
- [ ] Deploy Cilium via Helm: node transitions to Ready
- [ ] Schedule test pod: `kubectl run test --image=busybox -- sleep 30`
- [ ] Pod reaches Running state
- [ ] `crictl ps` shows the running container
- [ ] No writes to read-only root during normal operation
- [ ] All mutable state lives on `/var`
- [ ] CNI swap test: uninstall Cilium, deploy Flannel, node remains functional

## Acceptance Criteria

1. containerd starts and responds to CRI requests (`crictl info`)
2. kubelet starts and registers as a node
3. Node is NotReady before CNI deployment (no CNI baked in)
4. CNI plugin (Cilium) deployed via Helm makes the node Ready
5. A test pod can be scheduled and reaches Running
6. All mutable state (kubelet, containerd, pod logs) lives on `/var`
7. cgroups v2 unified hierarchy is active
8. Seccomp default profile is enforced
9. No writes to read-only root during normal K8s operation
10. Standard CNI plugin binaries exist at `/opt/cni/bin/`
11. CNI plugin can be swapped at runtime without rebuilding the image
12. CSI and device plugin directories exist and are writable
13. Worker and control plane image variants build successfully

## Key Design Decisions

### Pluggable CNI

The base image provides extension points (directories, standard binaries, kernel features) while the specific CNI implementation is deployed at runtime. This means:
- Images are CNI-agnostic -- the same image works with Cilium, Calico, or Flannel
- CNI upgrades don't require new OS images
- Different clusters can use different CNI plugins

### Go Packages

Many K8s components are written in Go. Two approaches:
1. Build from source using a bootstrapped Go compiler
2. Download pre-built binaries and wrap in derivations (setting RPATH, etc.)

Option 2 is pragmatic for initial development. Option 1 provides full source control and is the long-term goal.

### All Mutable State on /var

kubelet, containerd, pod logs, and container images all live under `/var/` on ZFS. Nothing writes to the read-only root. This is enforced by:
- kubelet `--root-dir=/var/lib/kubelet`
- containerd `root = "/var/lib/containerd"`
- Pod logs at `/var/log/pods/`

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Go binaries require glibc version mismatch | Medium | Segfaults or link errors | Build from source against our glibc, or use static binaries |
| kubelet expects FHS paths on mutable root | High | kubelet fails to start | Map all paths to `/var/`; use `--root-dir=/var/lib/kubelet` |
| CNI plugin init container can't write to /opt/cni/bin | Medium | CNI deployment fails | Bind-mount from mutable path if needed |
| containerd ZFS snapshotter creates excessive datasets | Medium | Performance degradation | Use overlayfs snapshotter by default even on ZFS |
| kubeadm expects systemd services it can manage | Medium | Init fails | Pre-configure all services; use `--skip-phases` as needed |
