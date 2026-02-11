# RFC-0007: Kubernetes Production Support

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS provides first-class Kubernetes support by baking container runtime, node agent binaries, and standard CNI plugin binaries into role-specific golden images while keeping the choice of CNI, CSI, and device plugins fully pluggable at runtime. All mutable Kubernetes state runs on `/var`, and per-machine identity and cluster membership are delivered via Ignition. Kubernetes plugins (CNI such as Cilium, CSI drivers, device plugins) are deployed post-boot as Helm releases or DaemonSets rather than hardcoded into the image. This RFC specifies the containerd CRI setup, the pluggable plugin architecture and its extension points, kubelet adaptation for an immutable OS, static pod manifests for control plane components, node labels and taints via Ignition, etcd operational considerations, and Pod Security Standards enforcement.

## Motivation

Running Kubernetes on a general-purpose Linux distribution introduces configuration drift, unaudited package updates, and a large attack surface from unnecessary software. ANDYL OS eliminates these risks by providing a minimal, immutable, purpose-built OS where every binary is traceable through the bootstrap chain (RFC-0002) and the root filesystem is read-only at runtime (RFC-0001). Kubernetes components are included in role-specific image variants (RFC-0004) and machine-specific identity is applied via Ignition (RFC-0006). This separation ensures that every node of the same role boots from an identical image, differing only in network identity and cluster credentials.

## Design

### 1. Role-Based Package Sets

Kubernetes functionality is split across two image variants that extend the common base operating-system declaration (see RFC-0004, Section 5).

**K8s Worker Node packages:**

| Package | Version | Purpose |
|---------|---------|---------|
| containerd | 1.7.x | Container runtime (CRI implementation) |
| runc | 1.2.x | OCI container runtime |
| kubelet | 1.31.x | Kubernetes node agent |
| kubectl | 1.31.x | CLI tool (included for on-node debugging) |
| cni-plugins | 1.5.x | Standard CNI plugin binaries (bridge, loopback, host-local) |
| crictl | 1.31.x | CRI debugging and inspection tool |
| iptables-nft | 1.8.x | Network filtering (fallback for non-eBPF policy) |
| ethtool | 6.x | NIC configuration and diagnostics |
| socat | 1.8.x | Port forwarding support (used by `kubectl port-forward`) |
| conntrack-tools | 1.4.x | Connection tracking utilities |
| ipvsadm | 1.31.x | IPVS management (for IPVS-mode kube-proxy, if used) |
| nerdctl | 1.7.x | containerd-native CLI (debugging) |

**K8s Control Plane (adds to worker set):**

| Package | Version | Purpose |
|---------|---------|---------|
| kubeadm | 1.31.x | Cluster bootstrap and lifecycle management |
| etcd | 3.5.x | Distributed key-value store for cluster state |
| kube-apiserver | 1.31.x | Kubernetes API server |
| kube-scheduler | 1.31.x | Pod scheduling |
| kube-controller-manager | 1.31.x | Controller loops (replication, endpoints, etc.) |

All binaries reside in content-addressed store paths under `/gnu/store` and are referenced via the system profile symlink tree. They are read-only at runtime.

```scheme
;; andyl-os/images/k8s-worker.scm
(define andyl-os-k8s-worker
  (operating-system
   (inherit andyl-os-base)
   (host-name "k8s-worker")       ;; overridden by Ignition
   (packages
    (append
     (list containerd runc kubectl kubelet cni-plugins
           crictl nerdctl iptables-nft ethtool socat conntrack-tools ipvsadm)
     (operating-system-packages andyl-os-base)))
   (services
    (append
     (list (service kubelet-service-type kubelet-config)
           (service containerd-service-type containerd-config))
     (operating-system-user-services andyl-os-base)))))

;; andyl-os/images/k8s-control-plane.scm
(define andyl-os-k8s-control-plane
  (operating-system
   (inherit andyl-os-k8s-worker)
   (host-name "k8s-cp")           ;; overridden by Ignition
   (packages
    (append
     (list kubeadm etcd kube-apiserver kube-scheduler
           kube-controller-manager)
     (operating-system-packages andyl-os-k8s-worker)))))
```

### 2. Container Runtime Interface (CRI): containerd

containerd is the CRI implementation for ANDYL OS. It provides the interface between kubelet and the OCI runtime (runc).

**Configuration file (baked into the golden image):**

```toml
# /etc/containerd/config.toml
version = 2

[grpc]
  address = "/run/containerd/containerd.sock"

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    sandbox_image = "registry.k8s.io/pause:3.10"

    [plugins."io.containerd.grpc.v1.cri".containerd]
      snapshotter = "overlayfs"
      default_runtime_name = "runc"

      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          runtime_type = "io.containerd.runc.v2"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            # Use systemd cgroup driver to match kubelet's cgroupDriver setting
            SystemdCgroup = true

    [plugins."io.containerd.grpc.v1.cri".cni]
      bin_dir = "/opt/cni/bin"
      conf_dir = "/etc/cni/net.d"

    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"

  [plugins."io.containerd.internal.v1.opt"]
    path = "/var/lib/containerd/opt"
```

**Path mapping for an immutable OS:**

| Path | Location | Type | Purpose |
|------|----------|------|---------|
| `/gnu/store/...-containerd/bin/containerd` | Store | Read-only | containerd binary |
| `/gnu/store/...-runc/bin/runc` | Store | Read-only | OCI runtime binary |
| `/etc/containerd/config.toml` | /etc overlay | Read-only base, overlayable | Configuration |
| `/var/lib/containerd` | /var | Mutable, persistent | Container images, snapshots, metadata |
| `/run/containerd/containerd.sock` | /run (tmpfs) | Ephemeral | gRPC socket |
| `/opt/cni/bin` | Store symlink | Read-only | Standard CNI plugin binaries (bridge, loopback, etc.) |
| `/etc/cni/net.d` | /etc overlay | Mutable | CNI configuration (written at runtime by the deployed CNI plugin) |
| `/etc/containerd/certs.d` | /etc overlay | Mutable | Registry TLS certificates |

**systemd unit file:**

```ini
# /etc/systemd/system/containerd.service
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target
Before=kubelet.service

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/gnu/store/HASH-containerd/bin/containerd \
  --config=/etc/containerd/config.toml
Restart=always
RestartSec=5
Delegate=yes
KillMode=process
OOMScoreAdjust=-999
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity

[Install]
WantedBy=multi-user.target
```

The `Delegate=yes` directive is critical: it tells systemd to delegate cgroup management to containerd, which in turn delegates to runc. Without this, systemd would interfere with container cgroup hierarchies.

**ZFS snapshotter variant:**

For machines using the ZFS partition layout (RFC-0004, Section 3), the snapshotter must be changed:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "zfs"
```

This causes containerd to manage container filesystem layers as ZFS clones instead of overlayfs mounts. Each container layer becomes a ZFS dataset under `datapool/containerd`. Monitor dataset count with `zfs list | wc -l` as high pod churn can create thousands of datasets.

### 3. Pluggable CNI Architecture

ANDYL OS ships standard CNI plugin binaries (bridge, loopback, host-local, portmap) in the base image at `/opt/cni/bin/` and creates the CNI configuration directory at `/etc/cni/net.d/` (on the mutable /etc overlay). The base image does **not** include any specific CNI implementation such as Cilium or Calico. Instead, the CNI plugin is deployed at runtime as a Helm release or DaemonSet after the node boots and joins the cluster.

This pluggable design means:

- **Any conformant CNI plugin works.** The operator chooses the CNI that fits their requirements and deploys it via standard Kubernetes tooling (Helm, kubectl apply).
- **CNI plugins are swappable.** Uninstall one CNI, clean `/etc/cni/net.d/`, and deploy another. The base image does not need to change.
- **CNI upgrades are decoupled from OS upgrades.** A Cilium version bump does not require building a new golden image.

**Recommended default: Cilium** (eBPF-based networking). Cilium replaces kube-proxy entirely by implementing service load balancing, network policy enforcement, and observability using eBPF programs loaded into the kernel.

**Why Cilium is recommended:**

- Eliminates iptables rules entirely. Traditional kube-proxy creates O(N) iptables rules per service, causing performance degradation at scale. Cilium uses eBPF hash maps with O(1) lookup.
- Network policy enforcement happens in the kernel data path (eBPF), not in userspace.
- Built-in observability via Hubble provides L3/L4/L7 flow visibility without additional sidecars.
- Service mesh capabilities (mutual TLS, L7 policy) without sidecar injection.
- Runs as a DaemonSet, requiring no host filesystem modifications beyond kernel support, which aligns with the immutable OS model.

**Cilium deployment via Helm:**

```yaml
# cilium-values.yaml
cilium:
  # Replace kube-proxy entirely with eBPF
  kubeProxyReplacement: "true"

  # API server endpoint
  k8sServiceHost: "k8s-api.andyl.internal"
  k8sServicePort: 6443

  # eBPF settings
  bpf:
    masquerade: true
    # Mount the BPF filesystem (already available on ANDYL OS kernel)
    # The kernel config includes CONFIG_BPF_SYSCALL=y and CONFIG_BPFILTER=y
    hostLegacyRouting: false

  # IP address management
  ipam:
    mode: "kubernetes"
    # Pod CIDR is configured via kubelet/controller-manager
    # Default: 10.244.0.0/16

  # Hubble observability
  hubble:
    enabled: true
    relay:
      enabled: true
    ui:
      enabled: true
    metrics:
      enabled:
        - dns
        - drop
        - tcp
        - flow
        - port-distribution
        - icmp
        - httpV2:exemplars=true;labelsContext=source_ip,source_namespace,destination_ip,destination_namespace

  # Cilium agent resource limits
  resources:
    requests:
      cpu: "100m"
      memory: "256Mi"
    limits:
      cpu: "1000m"
      memory: "1Gi"

  # Use the existing containerd socket
  containerRuntime:
    integration: containerd
    socketPath: "/run/containerd/containerd.sock"

  # ANDYL OS specific: CNI binary path
  cni:
    binPath: "/opt/cni/bin"
    confPath: "/etc/cni/net.d"
    # Cilium writes its own CNI config to /etc/cni/net.d
    # which is on the /etc overlay and persists across reboots
    exclusive: true

  # Security
  encryption:
    enabled: false
    # Enable WireGuard encryption for pod-to-pod traffic:
    # encryption:
    #   enabled: true
    #   type: wireguard

  # Disable installation of kube-proxy since Cilium replaces it
  kubeProxyReplacementHealthzBindAddr: "0.0.0.0:10256"
```

```bash
# Deploy Cilium
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium \
  --namespace kube-system \
  --values cilium-values.yaml
```

**Required kernel features for Cilium (cross-reference RFC-0003):**

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_CGROUP_BPF=y
CONFIG_NET_CLS_BPF=y
CONFIG_NET_ACT_BPF=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_XDP_SOCKETS=y
CONFIG_LWTUNNEL_BPF=y
```

All of these are enabled in the ANDYL OS kernel configuration (RFC-0003, Section 3).

**Alternative CNI: Calico with eBPF dataplane:**

If Cilium proves too complex or requires features not yet stable, Calico with its eBPF dataplane is the fallback:

```yaml
# calico-values.yaml
calico:
  bpfEnabled: true
  bpfExternalServiceMode: "DSR"
  linuxDataplane: "BPF"
```

### 3a. Kubernetes Plugin Extension Points and Lifecycle

ANDYL OS treats Kubernetes plugins (CNI, CSI, device plugins) as runtime extensions rather than image-time dependencies. The base image provides the scaffolding (directories, standard binaries, kernel features) and operators deploy the specific plugins they need after the node boots.

#### Extension Point: CNI (Container Network Interface)

| Aspect | Detail |
|--------|--------|
| Base image provides | Standard CNI binaries (`bridge`, `loopback`, `host-local`, `portmap`, etc.) at `/opt/cni/bin/` |
| Base image provides | Empty configuration directory at `/etc/cni/net.d/` (mutable /etc overlay) |
| Deployed at runtime | CNI implementation (Cilium, Calico, Flannel, Weave, etc.) via Helm or DaemonSet |
| Plugin writes to | `/etc/cni/net.d/` (mutable) -- CNI config files |
| Plugin writes to | `/opt/cni/bin/` -- Additional CNI binaries if needed (some plugins install their own binaries here via init containers) |
| Plugin writes to | `/var/run/cilium/` or equivalent (mutable /var or tmpfs) -- runtime state |
| Plugin must NOT write to | Immutable root filesystem paths outside of `/var`, `/etc` overlay, `/run`, `/opt/cni/bin` |

**CNI deployment workflow:**

```bash
# 1. Node boots with base image (no CNI config present)
# 2. Node joins cluster, kubelet starts in NotReady state (no CNI)
# 3. Operator deploys CNI plugin:
helm install cilium cilium/cilium \
    --namespace kube-system \
    --set cni.binPath=/opt/cni/bin \
    --set cni.confPath=/etc/cni/net.d \
    --values cilium-values.yaml

# 4. CNI DaemonSet starts, writes config to /etc/cni/net.d/
# 5. kubelet detects CNI config, node transitions to Ready
```

**CNI swap workflow:**

```bash
# 1. Cordon the node to prevent new pod scheduling
kubectl cordon <node>
# 2. Drain existing pods
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data
# 3. Uninstall old CNI
helm uninstall cilium --namespace kube-system
# 4. Clean up old CNI config
rm -f /etc/cni/net.d/*
# 5. Deploy new CNI
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml
# 6. Uncordon node once new CNI is ready
kubectl uncordon <node>
```

#### Extension Point: CSI (Container Storage Interface)

| Aspect | Detail |
|--------|--------|
| Base image provides | Plugin socket directories at `/var/lib/kubelet/plugins/` and `/var/lib/kubelet/plugins_registry/` (mutable /var) |
| Deployed at runtime | CSI driver (e.g., Rook-Ceph, OpenEBS, Longhorn, AWS EBS CSI) via Helm or DaemonSet |
| Plugin writes to | `/var/lib/kubelet/plugins/<driver-name>/csi.sock` -- gRPC socket |
| Plugin writes to | `/var/lib/kubelet/plugins_registry/` -- kubelet plugin registration socket |
| Plugin writes to | `/var/lib/csi-<driver>/` or equivalent -- driver-specific persistent state (mutable /var) |

CSI drivers interact with kubelet via the Kubernetes CSI registration mechanism. The node-driver-registrar sidecar registers the CSI driver's Unix socket with kubelet. All paths are on mutable `/var`, so no immutable filesystem changes are needed.

#### Extension Point: Device Plugins (GPU, FPGA, SR-IOV)

| Aspect | Detail |
|--------|--------|
| Base image provides | Device plugin socket directory at `/var/lib/kubelet/device-plugins/` (mutable /var) |
| Deployed at runtime | Device plugin (e.g., NVIDIA GPU device plugin, Intel FPGA plugin) via DaemonSet |
| Plugin writes to | `/var/lib/kubelet/device-plugins/` -- registration socket |
| Kernel requirement | Relevant kernel modules must be available (GPU drivers, SR-IOV VF support, etc.) |

Device plugins follow the same pattern: the base image provides the socket directory, and the plugin DaemonSet registers itself with kubelet at runtime.

#### Plugin Interaction with the Immutable Root Filesystem

All Kubernetes plugins must follow these rules on ANDYL OS:

1. **Write only to mutable paths:** `/var/`, `/etc/` overlay, `/run/` (tmpfs), `/opt/cni/bin/`. Never write to `/gnu/store/`, `/usr/`, or other read-only paths.
2. **Use DaemonSet or Helm for deployment.** Plugins that require host-level installation scripts will not work. All plugin logic must run inside containers.
3. **Host path mounts are restricted.** Plugins may mount specific mutable host paths (`/opt/cni/bin`, `/etc/cni/net.d`, `/var/lib/kubelet/plugins/`) but cannot assume a writable root filesystem.
4. **Init containers for binary installation.** CNI plugins that install additional binaries (e.g., Cilium installs `cilium-cni` into `/opt/cni/bin/`) should use init containers that copy binaries into the mutable `/opt/cni/bin/` path.

#### Plugin Upgrade Strategy

Kubernetes plugins are upgraded independently of the OS generation:

| Plugin Type | Upgrade Method | Rollback |
|------------|---------------|----------|
| CNI (Cilium) | `helm upgrade cilium cilium/cilium --values ...` | `helm rollback cilium` |
| CNI (manifest-based) | `kubectl apply -f <new-manifest>` | `kubectl apply -f <old-manifest>` |
| CSI driver | `helm upgrade <driver>` or `kubectl apply -f <new-manifest>` | `helm rollback` or apply previous manifest |
| Device plugin | Update DaemonSet image tag | Revert DaemonSet image tag |

Key considerations for plugin upgrades:

- **CNI upgrades should be rolling.** Cordon and drain nodes one at a time, upgrade the CNI, verify pod networking, then proceed to the next node.
- **CSI driver upgrades must not disrupt mounted volumes.** Follow the CSI driver's documented upgrade procedure, which typically involves upgrading the controller first, then node plugins.
- **Plugin version compatibility.** Track the Kubernetes version, kernel version, and plugin version matrix. The ANDYL OS release notes should document tested plugin versions.

### 4. Kubelet on an Immutable OS

The kubelet requires careful configuration to operate on an immutable root filesystem. All mutable state must reside on `/var` or `/run`.

**Kubelet configuration (delivered via Ignition to `/var/lib/kubelet/config.yaml`):**

```yaml
# /var/lib/kubelet/config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

# Cluster identity (per-cluster, delivered via Ignition)
clusterDNS:
  - 10.96.0.10
clusterDomain: cluster.local

# Container runtime
containerRuntimeEndpoint: "unix:///run/containerd/containerd.sock"
cgroupDriver: systemd

# Static pod manifests (control plane components)
staticPodPath: /etc/kubernetes/manifests

# Logging
containerLogMaxSize: "50Mi"
containerLogMaxFiles: 5

# Authentication and authorization
authentication:
  x509:
    clientCAFile: /etc/ssl/andyl-os/ca.pem
  webhook:
    enabled: true
    cacheTTL: "2m0s"
  anonymous:
    enabled: false
authorization:
  mode: Webhook

# Resource management
# Reserve resources for system daemons and kubelet itself
systemReserved:
  cpu: "500m"
  memory: "512Mi"
  ephemeral-storage: "1Gi"
kubeReserved:
  cpu: "500m"
  memory: "512Mi"
  ephemeral-storage: "1Gi"

# Eviction thresholds
evictionHard:
  memory.available: "256Mi"
  nodefs.available: "10%"
  imagefs.available: "15%"
evictionSoft:
  memory.available: "512Mi"
  nodefs.available: "15%"
  imagefs.available: "20%"
evictionSoftGracePeriod:
  memory.available: "1m"
  nodefs.available: "1m"
  imagefs.available: "1m"

# Immutable OS hardening
protectKernelDefaults: true
readOnlyPort: 0
makeIPTablesUtilChains: false

# Node allocatable enforcement
enforceNodeAllocatable:
  - pods
  - system-reserved
  - kube-reserved

# TLS
tlsCertFile: /var/lib/kubelet/pki/kubelet.crt
tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key

# Feature gates (enable as needed)
featureGates:
  RotateKubeletServerCertificate: true
  GracefulNodeShutdown: true

# Graceful shutdown (integrates with systemd)
shutdownGracePeriod: "30s"
shutdownGracePeriodCriticalPods: "10s"
```

**Mutable paths kubelet requires (all on `/var` or `/run`):**

| Path | Partition | Purpose |
|------|-----------|---------|
| `/var/lib/kubelet` | /var | Kubelet state, pod checkpoints, device plugins |
| `/var/lib/kubelet/config.yaml` | /var | Kubelet configuration (written by Ignition) |
| `/var/lib/kubelet/kubeconfig` | /var | API server credentials |
| `/var/lib/kubelet/bootstrap-kubeconfig` | /var | TLS bootstrap credentials |
| `/var/lib/kubelet/pki` | /var | Kubelet TLS certificates |
| `/var/lib/kubelet/pods` | /var | Pod volumes and metadata |
| `/var/lib/kubelet/plugins` | /var | CSI and device plugin sockets |
| `/var/lib/containerd` | /var | Container images, snapshots, metadata |
| `/var/log/pods` | /var | Pod log files |
| `/var/log/containers` | /var | Container log symlinks |
| `/run/containerd` | /run (tmpfs) | containerd gRPC socket |
| `/etc/kubernetes/manifests` | /etc overlay | Static pod manifests |
| `/etc/cni/net.d` | /etc overlay | CNI configuration (written at runtime by deployed CNI plugin) |

**kubelet systemd unit:**

```ini
# /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
Documentation=https://kubernetes.io/docs/
After=containerd.service
Requires=containerd.service

[Service]
ExecStart=/gnu/store/HASH-kubelet/bin/kubelet \
  --config=/var/lib/kubelet/config.yaml \
  --kubeconfig=/var/lib/kubelet/kubeconfig \
  --bootstrap-kubeconfig=/var/lib/kubelet/bootstrap-kubeconfig \
  --cert-dir=/var/lib/kubelet/pki \
  --root-dir=/var/lib/kubelet \
  --node-labels=node.andyl.internal/os=andyl-os \
  --register-with-taints="" \
  --v=2

Restart=always
RestartSec=10
StartLimitInterval=0
KillMode=process
CPUAccounting=true
MemoryAccounting=true
IOAccounting=true

[Install]
WantedBy=multi-user.target
```

**`protectKernelDefaults: true` implications:**

This setting causes kubelet to verify that the running kernel parameters match Kubernetes-expected values and refuse to start if they do not. The ANDYL OS base image includes a sysctl configuration that satisfies these requirements:

```ini
# /etc/sysctl.d/90-kubernetes.conf (baked into image)
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
vm.overcommit_memory = 1
vm.panic_on_oom = 0
kernel.panic = 10
kernel.panic_on_oops = 1
```

### 5. Static Pods for Control Plane Components

On control plane nodes, the Kubernetes API server, scheduler, controller manager, and optionally etcd run as static pods managed by the kubelet. Static pod manifests are placed in `/etc/kubernetes/manifests` (on the /etc overlay, writable via Ignition).

**kube-apiserver static pod manifest:**

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
  labels:
    component: kube-apiserver
    tier: control-plane
spec:
  hostNetwork: true
  priorityClassName: system-node-critical
  containers:
    - name: kube-apiserver
      image: registry.k8s.io/kube-apiserver:v1.31.4
      command:
        - kube-apiserver
        - --advertise-address=$(HOST_IP)
        - --bind-address=0.0.0.0
        - --secure-port=6443
        - --etcd-servers=https://127.0.0.1:2379
        - --etcd-cafile=/etc/ssl/andyl-os/ca.pem
        - --etcd-certfile=/etc/ssl/andyl-os/etcd-client.pem
        - --etcd-keyfile=/etc/ssl/andyl-os/etcd-client-key.pem
        - --client-ca-file=/etc/ssl/andyl-os/ca.pem
        - --tls-cert-file=/etc/ssl/andyl-os/apiserver.pem
        - --tls-private-key-file=/etc/ssl/andyl-os/apiserver-key.pem
        - --kubelet-certificate-authority=/etc/ssl/andyl-os/ca.pem
        - --kubelet-client-certificate=/etc/ssl/andyl-os/apiserver-kubelet-client.pem
        - --kubelet-client-key=/etc/ssl/andyl-os/apiserver-kubelet-client-key.pem
        - --service-account-key-file=/etc/ssl/andyl-os/sa.pub
        - --service-account-signing-key-file=/etc/ssl/andyl-os/sa.key
        - --service-account-issuer=https://k8s-api.andyl.internal:6443
        - --service-cluster-ip-range=10.96.0.0/12
        - --authorization-mode=Node,RBAC
        - --enable-admission-plugins=NodeRestriction,PodSecurity
        - --audit-log-path=/var/log/kubernetes/audit.log
        - --audit-log-maxage=30
        - --audit-log-maxbackup=10
        - --audit-log-maxsize=100
        - --enable-bootstrap-token-auth=true
        - --feature-gates=GracefulNodeShutdownBasedOnPodPriority=true
      env:
        - name: HOST_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
      resources:
        requests:
          cpu: "250m"
          memory: "512Mi"
      volumeMounts:
        - name: ssl-certs
          mountPath: /etc/ssl/andyl-os
          readOnly: true
        - name: audit-log
          mountPath: /var/log/kubernetes
      livenessProbe:
        httpGet:
          host: 127.0.0.1
          path: /livez
          port: 6443
          scheme: HTTPS
        initialDelaySeconds: 10
        periodSeconds: 10
        timeoutSeconds: 15
        failureThreshold: 8
      readinessProbe:
        httpGet:
          host: 127.0.0.1
          path: /readyz
          port: 6443
          scheme: HTTPS
        periodSeconds: 1
        timeoutSeconds: 15
  volumes:
    - name: ssl-certs
      hostPath:
        path: /etc/ssl/andyl-os
        type: DirectoryOrCreate
    - name: audit-log
      hostPath:
        path: /var/log/kubernetes
        type: DirectoryOrCreate
```

**kube-scheduler static pod manifest:**

```yaml
# /etc/kubernetes/manifests/kube-scheduler.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-scheduler
  namespace: kube-system
  labels:
    component: kube-scheduler
    tier: control-plane
spec:
  hostNetwork: true
  priorityClassName: system-node-critical
  containers:
    - name: kube-scheduler
      image: registry.k8s.io/kube-scheduler:v1.31.4
      command:
        - kube-scheduler
        - --kubeconfig=/var/lib/kubernetes/scheduler.kubeconfig
        - --authentication-kubeconfig=/var/lib/kubernetes/scheduler.kubeconfig
        - --authorization-kubeconfig=/var/lib/kubernetes/scheduler.kubeconfig
        - --bind-address=0.0.0.0
        - --leader-elect=true
      resources:
        requests:
          cpu: "100m"
          memory: "128Mi"
      volumeMounts:
        - name: kubeconfig
          mountPath: /var/lib/kubernetes
          readOnly: true
      livenessProbe:
        httpGet:
          host: 127.0.0.1
          path: /healthz
          port: 10259
          scheme: HTTPS
        initialDelaySeconds: 10
        periodSeconds: 10
        timeoutSeconds: 15
  volumes:
    - name: kubeconfig
      hostPath:
        path: /var/lib/kubernetes
        type: DirectoryOrCreate
```

**kube-controller-manager static pod manifest:**

```yaml
# /etc/kubernetes/manifests/kube-controller-manager.yaml
apiVersion: v1
kind: Pod
metadata:
  name: kube-controller-manager
  namespace: kube-system
  labels:
    component: kube-controller-manager
    tier: control-plane
spec:
  hostNetwork: true
  priorityClassName: system-node-critical
  containers:
    - name: kube-controller-manager
      image: registry.k8s.io/kube-controller-manager:v1.31.4
      command:
        - kube-controller-manager
        - --kubeconfig=/var/lib/kubernetes/controller-manager.kubeconfig
        - --authentication-kubeconfig=/var/lib/kubernetes/controller-manager.kubeconfig
        - --authorization-kubeconfig=/var/lib/kubernetes/controller-manager.kubeconfig
        - --bind-address=0.0.0.0
        - --cluster-cidr=10.244.0.0/16
        - --service-cluster-ip-range=10.96.0.0/12
        - --cluster-signing-cert-file=/etc/ssl/andyl-os/ca.pem
        - --cluster-signing-key-file=/etc/ssl/andyl-os/ca-key.pem
        - --root-ca-file=/etc/ssl/andyl-os/ca.pem
        - --service-account-private-key-file=/etc/ssl/andyl-os/sa.key
        - --use-service-account-credentials=true
        - --leader-elect=true
        - --allocate-node-cidrs=true
        - --controllers=*,bootstrapsigner,tokencleaner
        - --node-cidr-mask-size=24
      resources:
        requests:
          cpu: "200m"
          memory: "256Mi"
      volumeMounts:
        - name: ssl-certs
          mountPath: /etc/ssl/andyl-os
          readOnly: true
        - name: kubeconfig
          mountPath: /var/lib/kubernetes
          readOnly: true
      livenessProbe:
        httpGet:
          host: 127.0.0.1
          path: /healthz
          port: 10257
          scheme: HTTPS
        initialDelaySeconds: 10
        periodSeconds: 10
        timeoutSeconds: 15
  volumes:
    - name: ssl-certs
      hostPath:
        path: /etc/ssl/andyl-os
        type: DirectoryOrCreate
    - name: kubeconfig
      hostPath:
        path: /var/lib/kubernetes
        type: DirectoryOrCreate
```

**Static pod delivery:** Control plane static pod manifests are delivered via Ignition (RFC-0006). The Ignition config for control plane nodes creates the `/etc/kubernetes/manifests/` directory on the /etc overlay and writes each manifest file. Kubelet watches this directory and starts the pods automatically.

### 6. etcd on Control Plane Nodes

etcd stores all Kubernetes cluster state and requires special consideration on an immutable OS.

**etcd static pod manifest:**

```yaml
# /etc/kubernetes/manifests/etcd.yaml
apiVersion: v1
kind: Pod
metadata:
  name: etcd
  namespace: kube-system
  labels:
    component: etcd
    tier: control-plane
spec:
  hostNetwork: true
  priorityClassName: system-node-critical
  containers:
    - name: etcd
      image: registry.k8s.io/etcd:3.5.16-0
      command:
        - etcd
        - --name=$(HOSTNAME)
        - --data-dir=/var/lib/etcd
        - --wal-dir=/var/lib/etcd/wal
        - --listen-client-urls=https://0.0.0.0:2379
        - --advertise-client-urls=https://$(HOST_IP):2379
        - --listen-peer-urls=https://0.0.0.0:2380
        - --initial-advertise-peer-urls=https://$(HOST_IP):2380
        - --initial-cluster=$(ETCD_INITIAL_CLUSTER)
        - --initial-cluster-state=new
        - --cert-file=/etc/ssl/andyl-os/etcd.pem
        - --key-file=/etc/ssl/andyl-os/etcd-key.pem
        - --trusted-ca-file=/etc/ssl/andyl-os/ca.pem
        - --client-cert-auth=true
        - --peer-cert-file=/etc/ssl/andyl-os/etcd-peer.pem
        - --peer-key-file=/etc/ssl/andyl-os/etcd-peer-key.pem
        - --peer-trusted-ca-file=/etc/ssl/andyl-os/ca.pem
        - --peer-client-cert-auth=true
        - --snapshot-count=10000
        - --quota-backend-bytes=8589934592
        - --auto-compaction-mode=periodic
        - --auto-compaction-retention=8
        - --max-snapshots=5
        - --max-wals=5
      env:
        - name: HOSTNAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: HOST_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
        - name: ETCD_INITIAL_CLUSTER
          value: "cp-1=https://10.0.1.1:2380,cp-2=https://10.0.1.2:2380,cp-3=https://10.0.1.3:2380"
      resources:
        requests:
          cpu: "200m"
          memory: "512Mi"
      volumeMounts:
        - name: etcd-data
          mountPath: /var/lib/etcd
        - name: ssl-certs
          mountPath: /etc/ssl/andyl-os
          readOnly: true
      livenessProbe:
        httpGet:
          host: 127.0.0.1
          path: /health?serializable=true
          port: 2379
          scheme: HTTPS
        initialDelaySeconds: 10
        periodSeconds: 10
        timeoutSeconds: 15
        failureThreshold: 8
  volumes:
    - name: etcd-data
      hostPath:
        path: /var/lib/etcd
        type: DirectoryOrCreate
    - name: ssl-certs
      hostPath:
        path: /etc/ssl/andyl-os
        type: DirectoryOrCreate
```

**etcd data directory:** `/var/lib/etcd` resides on the mutable `/var` partition, which persists across generations. This means OS upgrades (new generations) do not affect etcd data. The data directory survives rollbacks as well.

**etcd on ZFS:** If using the ZFS partition layout, create a dedicated dataset with optimized properties:

```bash
zfs create -o recordsize=4K \
           -o logbias=throughput \
           -o compression=off \
           -o sync=standard \
           datapool/etcd
```

The `recordsize=4K` matches etcd's small, frequent write pattern. Compression is disabled because etcd data (boltdb) does not compress well and the CPU overhead harms latency. `sync=standard` ensures data integrity (do not use `sync=disabled` for etcd).

**etcd upgrade strategy with generational deployment:**

1. etcd supports only one minor version upgrade at a time (e.g., 3.5.x to 3.6.x, not 3.5.x to 3.7.x).
2. Rolling upgrade: update one control plane node at a time, verify etcd cluster health between each.
3. Verify with `etcdctl endpoint health --cluster` after each node update.
4. The previous generation remains available for instant rollback via boot counting (RFC-0005).
5. etcd data on `/var/lib/etcd` persists across generation switches, so rollback does not lose committed data.
6. Before major etcd upgrades, take a snapshot: `etcdctl snapshot save /var/lib/etcd/pre-upgrade.snapshot`.

### 7. Node Labels and Taints via Ignition

Node labels and taints are set via a systemd oneshot service delivered by Ignition (RFC-0006). This service runs after kubelet registers the node with the API server.

**Ignition-delivered systemd unit:**

```ini
# Delivered via Ignition to /etc/systemd/system/kubelet-node-labels.service
[Unit]
Description=Set Kubernetes Node Labels and Taints
After=kubelet.service
Requires=kubelet.service

[Service]
Type=oneshot
# Wait for kubelet to register the node
ExecStartPre=/bin/bash -c 'until /gnu/store/HASH-kubectl/bin/kubectl \
  --kubeconfig=/var/lib/kubelet/kubeconfig get node ${HOSTNAME}; do sleep 5; done'

# Apply labels
ExecStart=/gnu/store/HASH-kubectl/bin/kubectl \
  --kubeconfig=/var/lib/kubelet/kubeconfig \
  label node ${HOSTNAME} \
  topology.kubernetes.io/region=REGION \
  topology.kubernetes.io/zone=ZONE \
  node.andyl.internal/role=ROLE \
  node.andyl.internal/rack=RACK \
  node.andyl.internal/os-generation=GENERATION \
  node.kubernetes.io/instance-type=bare-metal-xlarge \
  --overwrite

RemainAfterExit=yes
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

The placeholders (`REGION`, `ZONE`, `ROLE`, `RACK`, `GENERATION`) are filled by the Ignition templating system (RFC-0006, Section 8) from the machine inventory.

**Standard labels applied:**

| Label | Source | Example |
|-------|--------|---------|
| `topology.kubernetes.io/region` | Inventory | `us-east-1` |
| `topology.kubernetes.io/zone` | Inventory | `us-east-1a` |
| `node.andyl.internal/role` | Image variant | `worker` or `control-plane` |
| `node.andyl.internal/rack` | Inventory | `rack-07` |
| `node.andyl.internal/os-generation` | Deployment | `42` |
| `node.kubernetes.io/instance-type` | Inventory | `bare-metal-xlarge` |

**Control plane taints:**

Control plane nodes receive a taint to prevent workload scheduling:

```ini
# Additional ExecStart line for control plane nodes
ExecStart=/gnu/store/HASH-kubectl/bin/kubectl \
  --kubeconfig=/var/lib/kubelet/kubeconfig \
  taint node ${HOSTNAME} \
  node-role.kubernetes.io/control-plane:NoSchedule \
  --overwrite
```

**OS generation label updates:** When a node is updated to a new generation (RFC-0005), the `node.andyl.internal/os-generation` label is updated by the health check service after boot verification succeeds. This enables operators to query which generation each node is running:

```bash
kubectl get nodes -l 'node.andyl.internal/os-generation=42'
```

### 8. Pod Security Standards

ANDYL OS enforces the Kubernetes Pod Security Standards at the cluster level, aligning with the immutable OS philosophy of minimizing the attack surface.

**Enforcement via namespace labels:**

```yaml
# Apply to production namespaces
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: latest
```

**What the `restricted` profile requires:**

| Requirement | Effect |
|-------------|--------|
| `runAsNonRoot: true` | Containers must not run as UID 0 |
| `allowPrivilegeEscalation: false` | No setuid binaries or capability escalation |
| `seccompProfile.type: RuntimeDefault` | Seccomp filtering enabled |
| No `hostNetwork`, `hostPID`, `hostIPC` | No access to host namespaces |
| No `hostPath` volumes (except specific paths) | No arbitrary host filesystem access |
| `readOnlyRootFilesystem: true` | Container root filesystem is read-only |
| `capabilities.drop: [ALL]` | All Linux capabilities dropped |

**PodSecurity admission controller configuration:**

The API server is started with `--enable-admission-plugins=...,PodSecurity` (see Section 5). A cluster-wide default is applied via an AdmissionConfiguration:

```yaml
# /var/lib/kubernetes/admission-config.yaml (delivered via Ignition)
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:
        enforce: "baseline"
        enforce-version: "latest"
        audit: "restricted"
        audit-version: "latest"
        warn: "restricted"
        warn-version: "latest"
      exemptions:
        usernames: []
        runtimeClasses: []
        namespaces:
          - kube-system
```

This configuration:
- Enforces `baseline` by default (blocks known privilege escalations).
- Audits and warns at the `restricted` level (logs violations but does not block).
- Exempts `kube-system` since control plane components and CNI DaemonSets require elevated privileges.
- Production namespaces override this with `restricted` enforcement via labels.

**Seccomp profile delivery:**

The default seccomp profile (`RuntimeDefault`) is provided by containerd and covers most workloads. Custom seccomp profiles can be placed at `/var/lib/kubelet/seccomp/profiles/` via Ignition or a ConfigMap-based delivery mechanism.

### 9. TLS Bootstrap and Certificate Rotation

Kubelet uses TLS bootstrapping to obtain its serving certificate from the API server, avoiding the need to pre-provision per-node certificates for the kubelet-to-apiserver connection.

**Bootstrap flow:**

1. Ignition delivers a bootstrap kubeconfig at `/var/lib/kubelet/bootstrap-kubeconfig` containing a bootstrap token.
2. Kubelet starts and presents the bootstrap token to the API server.
3. The API server validates the token and issues a client certificate.
4. Kubelet stores the certificate at `/var/lib/kubelet/pki/kubelet-client-current.pem`.
5. The `RotateKubeletServerCertificate` feature gate enables automatic rotation before expiry.

```yaml
# /var/lib/kubelet/bootstrap-kubeconfig (delivered via Ignition)
apiVersion: v1
kind: Config
clusters:
  - cluster:
      certificate-authority: /etc/ssl/andyl-os/ca.pem
      server: https://k8s-api.andyl.internal:6443
    name: andyl-cluster
contexts:
  - context:
      cluster: andyl-cluster
      user: kubelet-bootstrap
    name: bootstrap
current-context: bootstrap
users:
  - name: kubelet-bootstrap
    user:
      token: "BOOTSTRAP_TOKEN"
```

The bootstrap token is generated per-machine by the fleet templating system (RFC-0006) and encrypted with sops/age in the secrets inventory.

### 10. Health Checks for Kubernetes Roles

The ANDYL OS health check service (RFC-0005, Section 9) includes role-specific checks for Kubernetes nodes:

```bash
# Role-specific health checks (from /usr/bin/andyl-os-health-check)
ROLE=$(cat /etc/andyl-os/role 2>/dev/null || echo "base")
case "$ROLE" in
    k8s-worker)
        check "containerd running"   systemctl is-active --quiet containerd
        check "kubelet running"      systemctl is-active --quiet kubelet
        check "cni plugins exist"    test -d /opt/cni/bin
        check "kubelet healthz"      curl -sf http://localhost:10248/healthz
        check "containerd healthz"   crictl --runtime-endpoint \
            unix:///run/containerd/containerd.sock info > /dev/null 2>&1
        ;;
    k8s-control-plane)
        check "containerd running"   systemctl is-active --quiet containerd
        check "kubelet running"      systemctl is-active --quiet kubelet
        check "cni plugins exist"    test -d /opt/cni/bin
        check "kubelet healthz"      curl -sf http://localhost:10248/healthz
        check "etcd healthz"         curl -sf --cacert /etc/ssl/andyl-os/ca.pem \
            --cert /etc/ssl/andyl-os/etcd-client.pem \
            --key /etc/ssl/andyl-os/etcd-client-key.pem \
            https://localhost:2379/health
        check "apiserver healthz"    curl -sf --cacert /etc/ssl/andyl-os/ca.pem \
            https://localhost:6443/healthz
        check "scheduler healthz"    curl -sf --cacert /etc/ssl/andyl-os/ca.pem \
            https://localhost:10259/healthz
        check "controller healthz"   curl -sf --cacert /etc/ssl/andyl-os/ca.pem \
            https://localhost:10257/healthz
        ;;
esac
```

If any health check fails after a generation upgrade, the boot counting protocol (RFC-0005) triggers automatic rollback after 3 consecutive failures. This ensures that a broken kubelet, containerd, or control plane component does not leave the node in an unrecoverable state.

### 11. Kubernetes Upgrade Strategy

Kubernetes upgrades on ANDYL OS follow the generational deployment model (RFC-0005) with Kubernetes-specific constraints:

**Worker node upgrade:**

1. Build a new image variant with updated K8s packages (new kubelet, containerd versions).
2. Cordon the node: `kubectl cordon <node>`.
3. Drain the node: `kubectl drain <node> --ignore-daemonsets --delete-emptydir-data`.
4. Apply the update (new generation via andyl-os-agent).
5. Node reboots into the new generation.
6. Health check verifies kubelet, containerd, and CNI functionality.
7. If health check passes, boot is marked as good. Uncordon: `kubectl uncordon <node>`.
8. If health check fails, boot counting triggers rollback. Node reboots into previous generation and uncordons automatically.

**Control plane upgrade (requires careful ordering):**

1. Upgrade etcd first (one minor version at a time, rolling, verify cluster health).
2. Upgrade kube-apiserver on all control plane nodes (rolling).
3. Upgrade kube-controller-manager and kube-scheduler (rolling).
4. Upgrade kubelet on control plane nodes.
5. Upgrade worker nodes (rolling, respecting PodDisruptionBudgets).

**Version skew policy:** Kubernetes supports kubelet being at most one minor version behind the API server. ANDYL OS enforces this by building control plane and worker image variants from the same Kubernetes version. If a version skew is required during a rolling upgrade, it is temporary and limited to the upgrade window.

## Alternatives Considered

**CRI-O instead of containerd:** CRI-O is a lightweight CRI-only runtime. Rejected because containerd has broader ecosystem support, better tooling (nerdctl, crictl), and is the default runtime for most managed Kubernetes distributions. containerd also supports non-CRI workloads if needed.

**Baking Cilium into the golden image instead of runtime deployment:** Considered for faster time-to-ready on first boot, but rejected because it couples the CNI lifecycle to the OS image lifecycle, prevents operators from choosing alternative CNI plugins, and violates the principle of keeping the base image minimal and plugin-agnostic. The pluggable architecture allows Cilium, Calico, Flannel, or any conformant CNI to be deployed at runtime.

**Flannel instead of Cilium as default recommendation:** Flannel is simpler but uses VXLAN overlays and iptables, which do not scale well and do not provide network policy enforcement. Cilium's eBPF-based approach eliminates iptables overhead and provides built-in network policies and observability. However, with the pluggable architecture, operators can deploy Flannel if it better fits their use case.

**kube-proxy in iptables/IPVS mode:** Rejected in favor of Cilium's kube-proxy replacement. kube-proxy creates O(N) iptables rules per service and requires periodic rule reconciliation. Cilium's eBPF implementation provides O(1) service lookup and eliminates the need for a separate kube-proxy process.

**kubeadm for all cluster lifecycle management:** kubeadm is used for initial cluster bootstrap but not for ongoing management. ANDYL OS's generational deployment model (RFC-0005) handles OS-level upgrades including Kubernetes component binaries. kubeadm's upgrade workflow conflicts with the immutable image approach.

**Running control plane components as systemd services instead of static pods:** Considered for simplicity, but rejected because static pods provide consistent lifecycle management, health checking, and resource limits through the kubelet. Static pods also align with kubeadm conventions and make it easier to adopt kubeadm for initial cluster bootstrap.

## Security Considerations

- **Immutable binaries:** All Kubernetes binaries (kubelet, containerd, runc, kubectl) are stored in content-addressed paths under `/gnu/store` and are read-only at runtime. Tampering is detectable by comparing store path hashes against the generation manifest (RFC-0004).
- **TLS everywhere:** All Kubernetes component communication is encrypted with mutual TLS. Certificates are delivered via Ignition (RFC-0006) and rotated automatically by kubelet.
- **Pod Security Standards:** The `restricted` profile prevents containers from escalating privileges, accessing host namespaces, or mounting arbitrary host paths. This limits the blast radius of container escapes.
- **Seccomp filtering:** The `RuntimeDefault` seccomp profile blocks ~50 dangerous syscalls by default. Custom profiles can further restrict workload syscalls.
- **Read-only root filesystem:** Both the host OS and containers (via Pod Security Standards) enforce read-only root filesystems. Writable state is confined to explicit, known paths.
- **No shell in production containers:** Pod Security Standards combined with minimal base images reduce the attack surface inside containers.
- **Network policy enforcement:** The deployed CNI plugin is responsible for enforcing Kubernetes NetworkPolicy resources. Cilium (recommended) enforces policies in eBPF at the kernel level, providing fast, reliable microsegmentation between pods. Operators who choose a different CNI must verify that it supports NetworkPolicy enforcement.
- **etcd encryption:** etcd communication uses mutual TLS. At-rest encryption for Kubernetes secrets should be configured via the API server's `--encryption-provider-config`.
- **Bootstrap token security:** Bootstrap tokens used for TLS bootstrapping are short-lived (24h default) and scoped to the `system:bootstrappers` group.

## Compatibility

- **Kubernetes version:** ANDYL OS targets Kubernetes 1.31.x. The generational model allows multiple K8s versions to coexist (different image variants), but a single cluster runs one version at a time (per the version skew policy).
- **containerd version:** containerd 1.7.x is the CRI implementation. It supports the CRI v1 API required by Kubernetes 1.31+.
- **CNI plugins:** Any conformant CNI plugin that deploys as a DaemonSet or Helm release is supported. Cilium 1.16.x is the recommended default and requires Linux kernel 5.10+ (ANDYL OS provides 6.12.x). Calico, Flannel, and other CNI plugins have been validated with the pluggable architecture.
- **etcd version:** etcd 3.5.x is the target. It supports the storage backend required by Kubernetes 1.31.
- **Container images:** Workload containers use standard OCI images from any registry. ANDYL OS does not restrict which registries or images can be used (this is a policy decision enforced by admission controllers, not the OS).
- **CSI drivers:** Container Storage Interface drivers run as DaemonSets and communicate via Unix sockets in `/var/lib/kubelet/plugins/`. No host OS changes are needed beyond ensuring the socket paths are writable.
- **Cloud provider integration:** For cloud deployments, cloud controller managers run as pods in `kube-system` and do not require host OS support beyond standard Kubernetes APIs.

## Open Questions

1. **kubeadm vs. manual bootstrap:** Should we use kubeadm for initial cluster bootstrap (simpler, well-documented) or perform manual bootstrap (more control, fewer hidden assumptions)? kubeadm generates certificates and static pod manifests, which overlaps with Ignition's role.
2. **etcd topology:** Should etcd run on control plane nodes (co-located, simpler) or on dedicated nodes (better isolation, more resources for etcd)? The current design assumes co-located.
3. **Plugin version matrix:** CNI, CSI, and device plugins are upgraded independently of the OS generation. How do we document and test the compatibility matrix between OS generation, Kubernetes version, and plugin versions? Should the health check service verify plugin versions?
4. **Container image caching:** Should we pre-pull critical container images (pause, CoreDNS) into the golden image's `/var/lib/containerd` to speed up first boot? Note that CNI plugin images (Cilium, Calico, etc.) should NOT be pre-pulled since the CNI choice is made at runtime.
5. **Multi-cluster support:** If ANDYL OS needs to support multiple Kubernetes clusters on the same fleet, how do we manage per-cluster kubelet configuration? The current design assumes one cluster per fleet.
6. **GPU/accelerator support:** For ML workloads, GPU drivers and the NVIDIA device plugin need host-level support. How does this interact with the immutable OS model and kernel module management?

## References

- Kubernetes Documentation: https://kubernetes.io/docs/
- containerd CRI Plugin: https://github.com/containerd/containerd/blob/main/docs/cri/config.md
- Cilium Documentation: https://docs.cilium.io/
- Cilium kube-proxy Replacement: https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/
- Kubernetes Pod Security Standards: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubelet TLS Bootstrapping: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/
- etcd Operations Guide: https://etcd.io/docs/v3.5/op-guide/
- Static Pods: https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/
- Kubernetes Version Skew Policy: https://kubernetes.io/docs/setup/release/version-skew-policy/
