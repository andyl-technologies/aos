# Phase 7: Kubernetes Node Support

**Phase Number:** 7

## Objective

Package containerd, kubelet, standard CNI plugin binaries, and supporting tools as Guix packages. Configure the base image for Kubernetes worker and control plane roles with a pluggable plugin architecture: the base image provides CNI/CSI/device-plugin extension points (directories, standard binaries, kernel features) while the specific CNI implementation (Cilium, Calico, Flannel, etc.) is deployed at runtime via Helm or DaemonSet. Validate that a single-node Kubernetes cluster boots, accepts a runtime CNI deployment, and reaches Ready state on ANDYL OS.

## Prerequisites

- Phase 4 complete: Base image boots with systemd, cgroups v2 unified hierarchy, all required kernel features
- Phase 6 complete (or in progress): Ignition can configure kubelet/containerd settings per machine
- Kernel config includes: namespaces (all types), cgroups v2, overlayfs, eBPF, seccomp, bridge, VXLAN, IP_VS

## Deliverables

- `channel/andyl/packages/containerd.scm` -- containerd package
- `channel/andyl/packages/runc.scm` -- runc OCI runtime package
- `channel/andyl/packages/kubernetes.scm` -- kubelet, kubectl, kubeadm, crictl packages
- `channel/andyl/packages/cni.scm` -- CNI plugins package
- `channel/andyl/packages/k8s-tools.scm` -- ethtool, socat, conntrack-tools, ipvsadm, nerdctl
- containerd systemd service and configuration
- kubelet systemd service and configuration
- k8s-worker image variant (extends base image, CNI-agnostic)
- k8s-control-plane image variant (extends base image, CNI-agnostic)
- Pluggable CNI extension point: `/opt/cni/bin/` with standard plugins, empty `/etc/cni/net.d/`
- Pluggable CSI extension point: `/var/lib/kubelet/plugins/`, `/var/lib/kubelet/plugins_registry/`
- Device plugin extension point: `/var/lib/kubelet/device-plugins/`
- Single-node Kubernetes cluster boots, accepts runtime CNI deployment (Cilium via Helm), and node reaches Ready state in QEMU
- CNI swap test: Cilium uninstalled, Flannel deployed, node remains functional

## Detailed Task Checklist

### 7.1 containerd Package

- [ ] Create `channel/andyl/packages/containerd.scm`
- [ ] Define `andyl-containerd` package (version 1.7.x)
- [ ] Source: containerd GitHub release tarball
- [ ] Build with Go build system or extract pre-built binaries
- [ ] Install binaries: `containerd`, `containerd-shim-runc-v2`, `ctr`
- [ ] Build and verify: `containerd --version`

### 7.2 runc Package

- [ ] Create `channel/andyl/packages/runc.scm`
- [ ] Define `andyl-runc` package (version 1.2.x)
- [ ] Source: runc GitHub release
- [ ] Build with Go build system (requires libseccomp as input)
- [ ] Install `runc` binary
- [ ] Build and verify: `runc --version`

### 7.3 Kubernetes Packages

- [ ] Create `channel/andyl/packages/kubernetes.scm`
- [ ] Define `andyl-kubelet` package (version 1.31.x)
- [ ] Source: Kubernetes GitHub release or download pre-built binary
- [ ] Install `kubelet` binary
- [ ] Define `andyl-kubectl` package (same version)
- [ ] Install `kubectl` binary
- [ ] Define `andyl-kubeadm` package (same version, for control plane)
- [ ] Install `kubeadm` binary
- [ ] Define `andyl-crictl` package (version 1.31.x)
- [ ] Source: cri-tools GitHub release
- [ ] Install `crictl` binary
- [ ] Build and verify all packages

### 7.4 CNI Plugins Package

- [ ] Create `channel/andyl/packages/cni.scm`
- [ ] Define `andyl-cni-plugins` package (version 1.5.x)
- [ ] Source: containernetworking/plugins GitHub release
- [ ] Build or extract standard CNI plugins:
  - [ ] bridge, loopback, host-local, portmap, firewall, tuning
  - [ ] bandwidth, dhcp, macvlan, ipvlan, vlan, ptp
- [ ] Install to `/opt/cni/bin/` (or store equivalent)
- [ ] Build and verify: all plugin binaries exist

### 7.5 Supporting Tools

- [ ] Create `channel/andyl/packages/k8s-tools.scm`
- [ ] Define `andyl-iptables-nft` package (iptables 1.8.x with nftables backend)
- [ ] Define `andyl-ethtool` package
- [ ] Define `andyl-socat` package (needed for `kubectl port-forward`)
- [ ] Define `andyl-conntrack-tools` package
- [ ] Define `andyl-ipvsadm` package (for IPVS-mode kube-proxy)
- [ ] Define `andyl-nerdctl` package (optional, Docker-compatible CLI for containerd)
- [ ] Build and verify all packages

### 7.6 containerd Configuration

- [ ] Create `/etc/containerd/config.toml` as part of the image:
  - [ ] gRPC address: `/run/containerd/containerd.sock`
  - [ ] Sandbox image: `registry.k8s.io/pause:3.10`
  - [ ] Snapshotter: `overlayfs` (default for ext4) or `zfs` (for ZFS layout)
  - [ ] Default runtime: runc
  - [ ] SystemdCgroup: true
  - [ ] CNI bin_dir: `/opt/cni/bin`
  - [ ] CNI conf_dir: `/etc/cni/net.d`
  - [ ] Registry config_path: `/etc/containerd/certs.d`
- [ ] Create containerd systemd service unit:
  - [ ] `ExecStart=/gnu/store/...-containerd/bin/containerd --config /etc/containerd/config.toml`
  - [ ] `Restart=always`, `RestartSec=5`
  - [ ] `KillMode=process`
  - [ ] `Delegate=yes` (important for cgroup delegation to containers)
  - [ ] `LimitNPROC=infinity`, `LimitCORE=infinity`, `LimitNOFILE=1048576`
- [ ] Verify containerd starts and `crictl info` succeeds

### 7.7 kubelet Configuration

- [ ] Create kubelet config template (`/var/lib/kubelet/config.yaml`, written by Ignition):
  - [ ] `containerRuntimeEndpoint: unix:///run/containerd/containerd.sock`
  - [ ] `cgroupDriver: systemd`
  - [ ] `clusterDNS: [10.96.0.10]`
  - [ ] `clusterDomain: cluster.local`
  - [ ] `staticPodPath: /etc/kubernetes/manifests`
  - [ ] `authentication.x509.clientCAFile: /etc/ssl/andyl-os/ca.pem`
  - [ ] `authorization.mode: Webhook`
  - [ ] `protectKernelDefaults: true`
  - [ ] `readOnlyPort: 0` (disable insecure port)
  - [ ] Resource reservations: `systemReserved` and `kubeReserved` (500m CPU, 512Mi memory each)
  - [ ] Eviction thresholds: `memory.available < 256Mi`, `nodefs.available < 10%`, `imagefs.available < 15%`
- [ ] Create kubelet systemd service unit:
  - [ ] `After=containerd.service`, `Requires=containerd.service`
  - [ ] `ExecStart` with flags: `--config`, `--kubeconfig`, `--bootstrap-kubeconfig`, `--cert-dir`, `--root-dir`, `--node-labels`, `--v=2`
  - [ ] `Restart=always`, `RestartSec=10`
  - [ ] `CPUAccounting=true`, `MemoryAccounting=true`
- [ ] All mutable paths must be on `/var`:
  - [ ] `/var/lib/kubelet` -- kubelet state
  - [ ] `/var/lib/containerd` -- container images and snapshots
  - [ ] `/var/log/pods` -- pod logs
  - [ ] `/var/log/containers` -- container log symlinks

### 7.8 Pluggable CNI Architecture

The base image ships standard CNI plugin binaries and the directory
structure, but does NOT include any specific CNI implementation. The CNI
plugin (e.g., Cilium, Calico, Flannel) is deployed at runtime.

- [ ] Include standard CNI plugin binaries in the base image at `/opt/cni/bin/`:
  - [ ] `bridge`, `loopback`, `host-local`, `portmap`, `firewall`, `tuning`
  - [ ] `bandwidth`, `dhcp`, `macvlan`, `ipvlan`, `vlan`, `ptp`
- [ ] Symlink or bind-mount CNI binaries from Guix store to `/opt/cni/bin/`
- [ ] Create empty `/etc/cni/net.d/` directory on the mutable /etc overlay
- [ ] Do NOT create any default CNI config (no `10-bridge.conflist`) -- CNI config is written at runtime by the deployed plugin
- [ ] Verify `/opt/cni/bin/` is writable by init containers (CNI plugins like Cilium install additional binaries here)
- [ ] Verify CNI plugins are accessible from containerd (`crictl info` shows correct bin_dir and conf_dir)
- [ ] Document the CNI deployment workflow (Helm/DaemonSet) in operator runbook

### 7.9 K8s Worker Image Variant

- [ ] Create `channel/andyl/images/k8s-worker.scm`
- [ ] Define `andyl-os-k8s-worker` operating-system (inherits from `andyl-os-base`):
  - [ ] Add packages: containerd, runc, kubelet, kubectl, cni-plugins, crictl, nerdctl, iptables-nft, ethtool, socat, conntrack-tools, ipvsadm
  - [ ] Add services: containerd.service, kubelet.service
  - [ ] Include containerd config.toml
- [ ] Build the k8s-worker image
- [ ] Verify image size is reasonable

### 7.10 K8s Control Plane Image Variant

- [ ] Create `channel/andyl/images/k8s-control.scm`
- [ ] Define `andyl-os-k8s-control` operating-system (inherits from k8s-worker):
  - [ ] Add packages: kubeadm, etcd (if running etcd as system service)
  - [ ] Add static pod manifest directory
  - [ ] Or: control plane components run as static pods managed by kubelet
- [ ] Create etcd configuration template (if applicable):
  - [ ] Data directory: `/var/lib/etcd` (must be on fast storage)
  - [ ] ZFS considerations: `recordsize=4K`, `logbias=throughput` for etcd dataset
  - [ ] Quota: 8 GiB backend
  - [ ] Auto-compaction
- [ ] Build the control plane image

### 7.11 Kernel Verification for K8s

- [ ] Run the Kubernetes node conformance check against the kernel config:
  - [ ] All namespace types enabled (USER_NS, PID_NS, NET_NS, etc.)
  - [ ] cgroups v2 with all required controllers
  - [ ] OverlayFS enabled
  - [ ] Seccomp filter enabled
  - [ ] Bridge and VXLAN modules available
  - [ ] IP_VS modules available (for kube-proxy IPVS mode)
  - [ ] eBPF full stack (for Cilium CNI)
  - [ ] Conntrack enabled
- [ ] Boot kernel cmdline includes `systemd.unified_cgroup_hierarchy=1`

### 7.12 Single-Node Cluster Test

- [ ] Boot k8s-worker image in QEMU with Ignition config containing:
  - [ ] kubelet config
  - [ ] Bootstrap kubeconfig (self-signed for single-node test)
  - [ ] Or use kubeadm to bootstrap a single-node cluster
- [ ] Initialize cluster: `kubeadm init --pod-network-cidr=10.244.0.0/16`
- [ ] Verify node is in NotReady state before CNI deployment (no CNI config baked in)
- [ ] Deploy a CNI plugin via Helm (Cilium as default):
  - [ ] `helm install cilium cilium/cilium --namespace kube-system --set kubeProxyReplacement=true --set cni.binPath=/opt/cni/bin --set cni.confPath=/etc/cni/net.d`
  - [ ] Verify CNI config was written to `/etc/cni/net.d/`
  - [ ] Verify node transitions to Ready state after CNI deployment
- [ ] Run a test pod: `kubectl run test --image=busybox --restart=Never -- sleep 30`
- [ ] Verify pod reaches Running state: `kubectl get pods`
- [ ] Verify `crictl ps` shows the running container
- [ ] Clean up test pod
- [ ] Verify containerd did not write outside of `/var`

### 7.13 Pod Security Standards

- [ ] Configure namespace-level Pod Security Standards enforcement:
  - [ ] `restricted` profile for production namespaces
  - [ ] Requires: non-root, no privilege escalation, seccomp, no host namespaces
- [ ] Document how to apply PSS labels to namespaces
- [ ] Test that a privileged pod is rejected in a `restricted` namespace

### 7.14 ZFS Snapshotter (If Using ZFS Layout)

- [ ] If using ZFS partition layout, configure containerd with ZFS snapshotter:
  - [ ] `snapshotter = "zfs"` in containerd config
  - [ ] Create ZFS dataset for containerd: `datapool/containerd`
  - [ ] Test: pull an image, verify ZFS datasets are created per layer
  - [ ] Monitor dataset count with `zfs list`
- [ ] If using ext4 layout, use default overlayfs snapshotter (no additional config)

### 7.15 CNI Plugin Swap Test

Validates that the pluggable CNI architecture allows swapping one CNI
plugin for another without rebuilding the base image.

- [ ] Starting from a working cluster with Cilium deployed:
  - [ ] Uninstall Cilium: `helm uninstall cilium --namespace kube-system`
  - [ ] Clean CNI config: `rm -f /etc/cni/net.d/*`
  - [ ] Deploy Flannel: `kubectl apply -f <flannel-manifest>`
  - [ ] Verify node becomes Ready with Flannel
  - [ ] Verify a test pod can be scheduled and reaches Running
  - [ ] Clean up Flannel and restore Cilium for subsequent tests

### 7.16 CSI Extension Point Verification

- [ ] Verify CSI plugin directories exist on mutable `/var`:
  - [ ] `/var/lib/kubelet/plugins/` exists and is writable
  - [ ] `/var/lib/kubelet/plugins_registry/` exists and is writable
- [ ] Deploy a CSI driver (e.g., hostpath-csi for testing):
  - [ ] Verify CSI driver DaemonSet starts successfully
  - [ ] Verify CSI driver registers its socket in `/var/lib/kubelet/plugins/`
  - [ ] Verify CSINode object is created with the driver listed
- [ ] Verify CSI driver did not write to immutable paths

### 7.17 Device Plugin Extension Point Verification

- [ ] Verify `/var/lib/kubelet/device-plugins/` directory exists and is writable
- [ ] (Optional) Deploy a test device plugin and verify registration with kubelet

### 7.18 justfile Targets

- [ ] Add `build-image-k8s-worker` target
- [ ] Add `build-image-k8s-control` target
- [ ] Add `test-k8s` target: boots image and runs K8s readiness checks
- [ ] Add `test-k8s-cni-swap` target: tests deploying and swapping CNI plugins
- [ ] Add `test-k8s-csi` target: tests CSI driver deployment

## Acceptance Criteria

1. containerd starts and responds to CRI requests (`crictl info` succeeds)
2. kubelet starts and registers itself as a node
3. Node is in NotReady state before CNI plugin deployment (no CNI baked in)
4. A CNI plugin (Cilium) deployed via Helm makes the node Ready
5. A test pod can be scheduled, reaches Running, and completes
6. All mutable state (kubelet, containerd, pod logs) lives on `/var`
7. cgroups v2 unified hierarchy is active
8. Seccomp default profile is enforced
9. No writes to read-only root filesystem occur during normal k8s operation
10. Standard CNI plugin binaries (bridge, loopback, host-local, portmap) exist in the base image at `/opt/cni/bin/`
11. CNI plugin can be swapped at runtime (Cilium to Flannel) without rebuilding the image
12. CSI plugin directories exist and a CSI driver can register at runtime
13. Worker and control plane image variants build successfully

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Go binaries (kubelet, containerd) require glibc version mismatch | Medium | Segfaults or link errors | Build from source against andyl-glibc; or use statically-linked binaries |
| kubelet expects standard FHS paths that don't exist on immutable root | High | kubelet fails to start | Carefully map all kubelet paths to `/var`; use `--root-dir=/var/lib/kubelet` |
| cgroup v2 unified hierarchy not fully supported by older k8s versions | Low | Pod scheduling issues | Use k8s 1.31+ which has full cgroup v2 support |
| containerd ZFS snapshotter creates excessive datasets | Medium | Performance degradation | Monitor dataset count; set limits; consider overlayfs even on ZFS |
| CNI plugin path mismatch (expected /opt/cni/bin) | Medium | Pod networking fails | Symlink from store path to /opt/cni/bin; or configure containerd CNI path |
| CNI plugin init container cannot write to /opt/cni/bin | Medium | CNI deployment fails | Ensure /opt/cni/bin is writable (bind-mount from mutable path if needed) |
| Node stays NotReady if CNI deployment is delayed | Low | Scheduling delays | Document that CNI must be deployed as part of cluster bootstrap; include in operator runbook |
| CSI driver socket path mismatch | Low | Volume mount fails | Verify kubelet `--root-dir` aligns with CSI driver socket path expectations |
| kubeadm expects systemd services it can manage | Medium | Init fails | Pre-configure all services; use kubeadm with `--skip-phases` as needed |

## Estimated Complexity

**L (Large)**

Packaging multiple Go-based Kubernetes components for Guix is straightforward but tedious. The main complexity is in the integration: ensuring kubelet, containerd, and the pluggable CNI/CSI extension points all work correctly on an immutable filesystem with non-standard paths. The pluggable plugin architecture adds testing surface (CNI deployment, CNI swap, CSI registration) but reduces image build complexity since CNI implementations are no longer baked in. The single-node cluster test validates the full stack including runtime CNI deployment. Control plane packaging adds further complexity with etcd and static pods.
