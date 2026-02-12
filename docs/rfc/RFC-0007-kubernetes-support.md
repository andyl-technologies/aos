# RFC-0007: Kubernetes Production Support

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS provides first-class Kubernetes support by baking container runtime, node agent binaries, and standard CNI plugin binaries into role-specific golden images while keeping the choice of CNI, CSI, and device plugins fully pluggable at runtime. All mutable Kubernetes state runs on `/var`, and per-machine identity and cluster membership are delivered via Ignition. Kubernetes plugins (CNI such as Cilium, CSI drivers, device plugins) are deployed post-boot as Helm releases or DaemonSets rather than hardcoded into the image. This RFC specifies the containerd CRI setup, the pluggable plugin architecture and its extension points, kubelet adaptation for an immutable OS, static pod manifests for control plane components, node labels and taints via Ignition, and etcd operational considerations.

## Motivation

Running Kubernetes on a general-purpose Linux distribution introduces configuration drift, unaudited package updates, and a large attack surface from unnecessary software. ANDYL OS eliminates these risks by providing a minimal, immutable, purpose-built OS where every binary is traceable through the bootstrap chain (RFC-0002) and the root filesystem is read-only at runtime (RFC-0001). Kubernetes components are included in role-specific image variants (RFC-0004) and machine-specific identity is applied via Ignition (RFC-0006). This separation ensures that every node of the same role boots from an identical image, differing only in network identity and cluster credentials.

## Design

### 1. Role-Based Image Variants

Kubernetes functionality is split across two system variants defined in `systems/`, which extend the common server variant.

**K8s Worker Node (`systems/k8s-worker.nix`):**

```nix
# From systems/k8s-worker.nix
{
  imports = [
    ./server.nix
    ../modules/kubernetes/containerd.nix
    ../modules/kubernetes/kubelet.nix
    ../modules/kubernetes/network.nix
    ../modules/monitoring/node-exporter.nix
  ];

  aos.system.variant = "k8s-worker";
  aos.kubernetes.containerd.enable = true;
  aos.kubernetes.kubelet.enable = true;
  aos.kubernetes.network.enable = true;
  aos.monitoring.nodeExporter.enable = true;

  # Firewall: SSH, kubelet API, kube-proxy health, NodePort range
  aos.firewall.allowedTCP = [ 22 10250 10256 ] ++ (lib.range 30000 32767);
  aos.firewall.allowedUDP = [ 8472 ];  # VXLAN overlay
  aos.firewall.forwardPolicy = "accept";
}
```

**K8s Control Plane (`systems/k8s-control-plane.nix`):**

```nix
# From systems/k8s-control-plane.nix
{
  imports = [
    ./k8s-worker.nix
    ../modules/kubernetes/control-plane.nix
  ];

  aos.system.variant = "k8s-control-plane";
  aos.kubernetes.controlPlane.enable = true;

  # Control plane ports: etcd, apiserver, controller-manager, scheduler
  aos.firewall.allowedTCP = [
    22 2379 2380 6443 10250 10256 10257 10259
  ] ++ (lib.range 30000 32767);
}
```

**Worker node packages:**

| Package | Version | Purpose |
|---------|---------|---------|
| containerd | 1.7.x | Container runtime (CRI implementation) |
| runc | 1.2.x | OCI container runtime |
| kubelet | 1.31.x | Kubernetes node agent |
| kubectl | 1.31.x | CLI tool (included for on-node debugging) |
| cni-plugins | 1.5.x | Standard CNI plugin binaries (bridge, loopback, host-local) |
| crictl | 1.31.x | CRI debugging and inspection tool |
| nerdctl | 1.7.x | containerd-native CLI (debugging) |

**Control plane additions:**

| Package | Version | Purpose |
|---------|---------|---------|
| kubeadm | 1.31.x | Cluster bootstrap and lifecycle management |

All binaries reside in content-addressed store paths under `/nix/store` and are referenced via the system profile symlink tree. They are read-only at runtime.

### 2. Container Runtime Interface (CRI): containerd

containerd is configured via `modules/kubernetes/containerd.nix`, which provides typed options and generates `/etc/containerd/config.toml`:

```nix
# From modules/kubernetes/containerd.nix — key options
aos.kubernetes.containerd = {
  enable = false;
  snapshotter = "overlayfs";        # or "native" for ZFS
  runtimeType = "io.containerd.runc.v2";
  cgroupDriver = "systemd";         # required for cgroup v2
  sandboxImage = "registry.k8s.io/pause:3.10";
  registryMirrors = {};              # { "docker.io" = "https://mirror.internal/v2"; }
};
```

**Generated configuration (`/etc/containerd/config.toml`):**

```toml
version = 2
root = "/var/lib/containerd"
state = "/run/containerd"

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
            SystemdCgroup = true
    [plugins."io.containerd.grpc.v1.cri".cni]
      bin_dir = "/opt/cni/bin"
      conf_dir = "/etc/cni/net.d"
```

**Path mapping for an immutable OS:**

| Path | Location | Type | Purpose |
|------|----------|------|---------|
| `/nix/store/...-containerd/bin/containerd` | Store | Read-only | containerd binary |
| `/nix/store/...-runc/bin/runc` | Store | Read-only | OCI runtime binary |
| `/etc/containerd/config.toml` | /etc overlay | Read-only base, overlayable | Configuration |
| `/var/lib/containerd` | /var | Mutable, persistent | Container images, snapshots, metadata |
| `/run/containerd/containerd.sock` | /run (tmpfs) | Ephemeral | gRPC socket |
| `/opt/cni/bin` | Store symlink | Read-only | Standard CNI plugin binaries |
| `/etc/cni/net.d` | /etc overlay | Mutable | CNI configuration (written at runtime) |

**systemd service (generated by the module):**

```nix
# From modules/kubernetes/containerd.nix
systemd.services."containerd" = {
  wantedBy = [ "multi-user.target" ];
  after = [ "network.target" "local-fs.target" ];
  serviceConfig = {
    Type = "notify";
    ExecStart = "/usr/bin/containerd --config /etc/containerd/config.toml";
    Restart = "always";
    RestartSec = "5s";
    LimitNOFILE = "1048576";
    LimitNPROC = "infinity";
    TasksMax = "infinity";
    OOMScoreAdjust = -999;
    Delegate = true;     # Critical: delegate cgroup management to containerd
    KillMode = "process";
  };
};
```

The `Delegate=yes` directive is critical: it tells systemd to delegate cgroup management to containerd, which in turn delegates to runc. Without this, systemd would interfere with container cgroup hierarchies.

### 3. Pluggable CNI Architecture

ANDYL OS ships standard CNI plugin binaries (bridge, loopback, host-local, portmap) in the base image at `/opt/cni/bin/` and creates the CNI configuration directory at `/etc/cni/net.d/` (on the mutable /etc overlay). The base image does **not** include any specific CNI implementation such as Cilium or Calico. Instead, the CNI plugin is deployed at runtime as a Helm release or DaemonSet after the node boots and joins the cluster.

The networking prerequisites are configured by `modules/kubernetes/network.nix`:

```nix
# From modules/kubernetes/network.nix — key options
aos.kubernetes.network = {
  enable = false;
  podCIDR = "10.244.0.0/16";
  serviceCIDR = "10.96.0.0/12";
  kernelModules = [ "br_netfilter" "overlay" "ip_vs" "ip_vs_rr" "ip_vs_wrr" "ip_vs_sh" "nf_conntrack" ];
  sysctl = {
    "net.bridge.bridge-nf-call-iptables" = "1";
    "net.bridge.bridge-nf-call-ip6tables" = "1";
    "net.ipv4.ip_forward" = "1";
  };
};
```

The module automatically sets the firewall forward policy to "accept" and trusts CNI interfaces (`cni0`, `flannel.1`, `cilium_host`, `cilium_net`, `lxc*`, `veth*`).

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
  kubeProxyReplacement: "true"
  k8sServiceHost: "k8s-api.andyl.internal"
  k8sServicePort: 6443
  bpf:
    masquerade: true
    hostLegacyRouting: false
  ipam:
    mode: "kubernetes"
  hubble:
    enabled: true
    relay:
      enabled: true
    ui:
      enabled: true
  cni:
    binPath: "/opt/cni/bin"
    confPath: "/etc/cni/net.d"
    exclusive: true
  containerRuntime:
    integration: containerd
    socketPath: "/run/containerd/containerd.sock"
```

```bash
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium \
  --namespace kube-system \
  --values cilium-values.yaml
```

**Required kernel features for Cilium (cross-reference RFC-0003):**

All required eBPF kernel features (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_NET_CLS_BPF=y`, `CONFIG_LWTUNNEL_BPF=y`, etc.) are enabled in the ANDYL OS kernel configuration (RFC-0003, Section 3).

### 3a. Kubernetes Plugin Extension Points and Lifecycle

ANDYL OS treats Kubernetes plugins (CNI, CSI, device plugins) as runtime extensions rather than image-time dependencies. The base image provides the scaffolding (directories, standard binaries, kernel features) and operators deploy the specific plugins they need after the node boots.

#### Extension Point: CNI (Container Network Interface)

| Aspect | Detail |
|--------|--------|
| Base image provides | Standard CNI binaries (`bridge`, `loopback`, `host-local`, `portmap`, etc.) at `/opt/cni/bin/` |
| Base image provides | Empty configuration directory at `/etc/cni/net.d/` (mutable /etc overlay) |
| Deployed at runtime | CNI implementation (Cilium, Calico, Flannel, Weave, etc.) via Helm or DaemonSet |
| Plugin writes to | `/etc/cni/net.d/` (mutable) -- CNI config files |
| Plugin writes to | `/opt/cni/bin/` -- Additional CNI binaries if needed (via init containers) |
| Plugin must NOT write to | Immutable root filesystem paths outside of `/var`, `/etc` overlay, `/run`, `/opt/cni/bin` |

#### Extension Point: CSI (Container Storage Interface)

| Aspect | Detail |
|--------|--------|
| Base image provides | Plugin socket directories at `/var/lib/kubelet/plugins/` and `/var/lib/kubelet/plugins_registry/` (mutable /var) |
| Deployed at runtime | CSI driver (e.g., Rook-Ceph, OpenEBS, Longhorn, AWS EBS CSI) via Helm or DaemonSet |
| Plugin writes to | `/var/lib/kubelet/plugins/<driver-name>/csi.sock` -- gRPC socket |
| Plugin writes to | `/var/lib/kubelet/plugins_registry/` -- kubelet plugin registration socket |

#### Extension Point: Device Plugins (GPU, FPGA, SR-IOV)

| Aspect | Detail |
|--------|--------|
| Base image provides | Device plugin socket directory at `/var/lib/kubelet/device-plugins/` (mutable /var) |
| Deployed at runtime | Device plugin (e.g., NVIDIA GPU device plugin, Intel FPGA plugin) via DaemonSet |
| Plugin writes to | `/var/lib/kubelet/device-plugins/` -- registration socket |
| Kernel requirement | Relevant kernel modules must be available |

#### Plugin Interaction with the Immutable Root Filesystem

All Kubernetes plugins must follow these rules on ANDYL OS:

1. **Write only to mutable paths:** `/var/`, `/etc/` overlay, `/run/` (tmpfs), `/opt/cni/bin/`. Never write to `/nix/store/`, `/usr/`, or other read-only paths.
2. **Use DaemonSet or Helm for deployment.** Plugins that require host-level installation scripts will not work.
3. **Host path mounts are restricted.** Plugins may mount specific mutable host paths but cannot assume a writable root filesystem.
4. **Init containers for binary installation.** CNI plugins that install additional binaries should use init containers that copy binaries into the mutable `/opt/cni/bin/` path.

#### Plugin Upgrade Strategy

Kubernetes plugins are upgraded independently of the OS generation:

| Plugin Type | Upgrade Method | Rollback |
|------------|---------------|----------|
| CNI (Cilium) | `helm upgrade cilium cilium/cilium --values ...` | `helm rollback cilium` |
| CSI driver | `helm upgrade <driver>` | `helm rollback` |
| Device plugin | Update DaemonSet image tag | Revert DaemonSet image tag |

### 4. Kubelet on an Immutable OS

The kubelet is configured via `modules/kubernetes/kubelet.nix`, which provides typed options and generates the KubeletConfiguration YAML and systemd service:

```nix
# From modules/kubernetes/kubelet.nix — key options
aos.kubernetes.kubelet = {
  enable = false;
  clusterDNS = [ "10.96.0.10" ];
  clusterDomain = "cluster.local";
  cgroupDriver = "systemd";         # required for cgroup v2
  containerRuntimeEndpoint = "unix:///run/containerd/containerd.sock";
  maxPods = 110;
  serializeImagePulls = false;
  nodeLabels = {};                   # e.g., { "topology.kubernetes.io/zone" = "us-east-1a"; }
  nodeTaints = [];                   # e.g., [ "node-role.kubernetes.io/control-plane:NoSchedule" ]
};
```

**Generated KubeletConfiguration (`/var/lib/kubelet/config.yaml`):**

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: "systemd"
clusterDNS:
  - "10.96.0.10"
clusterDomain: "cluster.local"
containerRuntimeEndpoint: "unix:///run/containerd/containerd.sock"
maxPods: 110
serializeImagePulls: false
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
  x509:
    clientCAFile: "/etc/kubernetes/pki/ca.crt"
authorization:
  mode: Webhook
rotateCertificates: true
serverTLSBootstrap: true
readOnlyPort: 0
protectKernelDefaults: true
shutdownGracePeriod: "30s"
shutdownGracePeriodCriticalPods: "10s"
```

**Mutable paths kubelet requires (all on `/var` or `/run`):**

| Path | Partition | Purpose |
|------|-----------|---------|
| `/var/lib/kubelet` | /var | Kubelet state, pod checkpoints, device plugins |
| `/var/lib/kubelet/config.yaml` | /var | Kubelet configuration (written by Ignition) |
| `/var/lib/kubelet/pki` | /var | Kubelet TLS certificates |
| `/var/lib/kubelet/pods` | /var | Pod volumes and metadata |
| `/var/lib/kubelet/plugins` | /var | CSI and device plugin sockets |
| `/var/lib/containerd` | /var | Container images, snapshots, metadata |
| `/var/log/pods` | /var | Pod log files |
| `/run/containerd` | /run (tmpfs) | containerd gRPC socket |
| `/etc/kubernetes/manifests` | /etc overlay | Static pod manifests |
| `/etc/cni/net.d` | /etc overlay | CNI configuration |

**kubelet systemd service (generated by the module):**

```nix
# From modules/kubernetes/kubelet.nix
systemd.services."kubelet" = {
  wantedBy = [ "multi-user.target" ];
  after = [ "network-online.target" "containerd.service" ];
  requires = [ "containerd.service" ];
  serviceConfig = {
    Type = "notify";
    ExecStart = "/usr/bin/kubelet ${kubeletFlags}";
    Restart = "always";
    RestartSec = "10s";
    LimitNOFILE = "1048576";
    LimitNPROC = "infinity";
    TasksMax = "infinity";
    OOMScoreAdjust = -999;
    Delegate = true;
    CPUAccounting = true;
    MemoryAccounting = true;
  };
};
```

**`protectKernelDefaults: true` implications:**

This setting causes kubelet to verify that the running kernel parameters match Kubernetes-expected values and refuse to start if they do not. The `modules/kubernetes/network.nix` module generates a sysctl configuration that satisfies these requirements:

```ini
# /etc/sysctl.d/90-k8s-networking.conf (generated by modules/kubernetes/network.nix)
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
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
        - --etcd-cafile=/etc/ssl/aos/ca.pem
        - --etcd-certfile=/etc/ssl/aos/etcd-client.pem
        - --etcd-keyfile=/etc/ssl/aos/etcd-client-key.pem
        - --client-ca-file=/etc/ssl/aos/ca.pem
        - --tls-cert-file=/etc/ssl/aos/apiserver.pem
        - --tls-private-key-file=/etc/ssl/aos/apiserver-key.pem
        - --service-account-key-file=/etc/ssl/aos/sa.pub
        - --service-account-signing-key-file=/etc/ssl/aos/sa.key
        - --service-account-issuer=https://k8s-api.andyl.internal:6443
        - --service-cluster-ip-range=10.96.0.0/12
        - --authorization-mode=Node,RBAC
        - --enable-admission-plugins=NodeRestriction
        - --enable-bootstrap-token-auth=true
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
          mountPath: /etc/ssl/aos
          readOnly: true
      livenessProbe:
        httpGet:
          host: 127.0.0.1
          path: /livez
          port: 6443
          scheme: HTTPS
        initialDelaySeconds: 10
        periodSeconds: 10
  volumes:
    - name: ssl-certs
      hostPath:
        path: /etc/ssl/aos
        type: DirectoryOrCreate
```

**Static pod delivery:** Control plane static pod manifests are delivered via Ignition (RFC-0006). The Ignition config for control plane nodes creates the `/etc/kubernetes/manifests/` directory on the /etc overlay and writes each manifest file. Kubelet watches this directory and starts the pods automatically.

### 6. etcd on Control Plane Nodes

etcd stores all Kubernetes cluster state and requires special consideration on an immutable OS.

**etcd data directory:** `/var/lib/etcd` resides on the mutable `/var` partition (ZFS dataset with `recordsize=4K` and `sync=always` as configured in `modules/services/ignition.nix`). This means OS upgrades (new generations) do not affect etcd data. The data directory survives rollbacks as well.

**etcd on ZFS:** The Ignition module creates a dedicated ZFS dataset with optimized properties:

```nix
# From modules/services/ignition.nix — etcd dataset
"var/lib/etcd" = {
  mountpoint = "/var/lib/etcd";
  compression = "zstd-3";
  atime = "off";
  recordsize = "4K";      # matches etcd's small, frequent write pattern
  sync = "always";        # data integrity for etcd WAL
};
```

**etcd upgrade strategy with generational deployment:**

1. etcd supports only one minor version upgrade at a time (e.g., 3.5.x to 3.6.x, not 3.5.x to 3.7.x).
2. Rolling upgrade: update one control plane node at a time, verify etcd cluster health between each.
3. Verify with `etcdctl endpoint health --cluster` after each node update.
4. The previous generation remains available for instant rollback via boot counting (RFC-0005).
5. etcd data on `/var/lib/etcd` persists across generation switches, so rollback does not lose committed data.
6. Before major etcd upgrades, take a snapshot: `etcdctl snapshot save /var/lib/etcd/pre-upgrade.snapshot`.

### 7. Node Labels and Taints via Ignition

Node labels and taints can be configured two ways:

1. **Via kubelet module options** (`aos.kubernetes.kubelet.nodeLabels` and `aos.kubernetes.kubelet.nodeTaints`) -- applied at kubelet registration time.
2. **Via Ignition-delivered systemd units** -- for dynamic labels set from the machine inventory.

**Kubelet module approach (from `modules/kubernetes/kubelet.nix`):**

```nix
# Labels and taints applied at registration time
aos.kubernetes.kubelet.nodeLabels = {
  "topology.kubernetes.io/region" = "us-east-1";
  "topology.kubernetes.io/zone" = "us-east-1a";
  "node.andyl.internal/role" = "worker";
};
aos.kubernetes.kubelet.nodeTaints = [
  "node-role.kubernetes.io/control-plane:NoSchedule"
];
```

**Ignition-delivered systemd unit (for inventory-driven labels):**

```ini
# Delivered via Ignition to /etc/systemd/system/kubelet-node-labels.service
[Unit]
Description=Set Kubernetes Node Labels and Taints
After=kubelet.service
Requires=kubelet.service

[Service]
Type=oneshot
ExecStartPre=/bin/bash -c 'until kubectl \
  --kubeconfig=/var/lib/kubelet/kubeconfig get node ${HOSTNAME}; do sleep 5; done'

ExecStart=kubectl --kubeconfig=/var/lib/kubelet/kubeconfig \
  label node ${HOSTNAME} \
  topology.kubernetes.io/region=REGION \
  topology.kubernetes.io/zone=ZONE \
  node.andyl.internal/role=ROLE \
  node.andyl.internal/rack=RACK \
  node.andyl.internal/os-generation=GENERATION \
  --overwrite

RemainAfterExit=yes
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

The placeholders (`REGION`, `ZONE`, `ROLE`, `RACK`, `GENERATION`) are filled per-machine in each node's Ignition config (RFC-0006).

**Standard labels applied:**

| Label | Source | Example |
|-------|--------|---------|
| `topology.kubernetes.io/region` | Inventory | `us-east-1` |
| `topology.kubernetes.io/zone` | Inventory | `us-east-1a` |
| `node.andyl.internal/role` | Image variant | `worker` or `control-plane` |
| `node.andyl.internal/rack` | Inventory | `rack-07` |
| `node.andyl.internal/os-generation` | Deployment | `42` |

**OS generation label updates:** When a node is updated to a new generation (RFC-0005), the `node.andyl.internal/os-generation` label is updated by the health check service after boot verification succeeds. This enables operators to query which generation each node is running:

```bash
kubectl get nodes -l 'node.andyl.internal/os-generation=42'
```

### 8. TLS Bootstrap and Certificate Rotation

Kubelet uses TLS bootstrapping to obtain its serving certificate from the API server. The kubelet module enables automatic certificate rotation:

```nix
# From modules/kubernetes/kubelet.nix — TLS settings in KubeletConfiguration
rotateCertificates: true
serverTLSBootstrap: true
```

**Bootstrap flow:**

1. Ignition delivers a bootstrap kubeconfig at `/etc/kubernetes/bootstrap-kubelet.conf` containing a bootstrap token.
2. Kubelet starts and presents the bootstrap token to the API server.
3. The API server validates the token and issues a client certificate.
4. Kubelet stores the certificate at `/var/lib/kubelet/pki/`.
5. Automatic rotation renews certificates before expiry.

The bootstrap token is generated per-machine and delivered via Ignition (RFC-0006).

### 9. Health Checks for Kubernetes Roles

The ANDYL OS health check service (RFC-0005, Section 9) includes role-specific checks for Kubernetes nodes:

```bash
# Role-specific health checks
ROLE=$(cat /etc/aos/role 2>/dev/null || echo "base")
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
        check "kubelet healthz"      curl -sf http://localhost:10248/healthz
        check "etcd healthz"         curl -sf --cacert /etc/ssl/aos/ca.pem \
            --cert /etc/ssl/aos/etcd-client.pem \
            --key /etc/ssl/aos/etcd-client-key.pem \
            https://localhost:2379/health
        check "apiserver healthz"    curl -sf --cacert /etc/ssl/aos/ca.pem \
            https://localhost:6443/healthz
        check "scheduler healthz"    curl -sf --cacert /etc/ssl/aos/ca.pem \
            https://localhost:10259/healthz
        check "controller healthz"   curl -sf --cacert /etc/ssl/aos/ca.pem \
            https://localhost:10257/healthz
        ;;
esac
```

If any health check fails after a generation upgrade, the boot counting protocol (RFC-0005) triggers automatic rollback after exhausting boot tries. This ensures that a broken kubelet, containerd, or control plane component does not leave the node in an unrecoverable state.

### 10. Kubernetes Upgrade Strategy

Kubernetes upgrades on ANDYL OS follow the generational deployment model (RFC-0005) with Kubernetes-specific constraints:

**Worker node upgrade:**

1. Build a new image variant with updated K8s packages (new kubelet, containerd versions).
2. Cordon the node: `kubectl cordon <node>`.
3. Drain the node: `kubectl drain <node> --ignore-daemonsets --delete-emptydir-data`.
4. Apply the update (new generation via aos-update agent).
5. Node reboots into the new generation.
6. Health check verifies kubelet, containerd, and CNI functionality.
7. If health check passes, boot is marked as good. Uncordon: `kubectl uncordon <node>`.
8. If health check fails, boot counting triggers rollback. Node reboots into previous generation.

**Control plane upgrade (requires careful ordering):**

1. Upgrade etcd first (one minor version at a time, rolling, verify cluster health).
2. Upgrade kube-apiserver on all control plane nodes (rolling).
3. Upgrade kube-controller-manager and kube-scheduler (rolling).
4. Upgrade kubelet on control plane nodes.
5. Upgrade worker nodes (rolling, respecting PodDisruptionBudgets).

**Version skew policy:** Kubernetes supports kubelet being at most one minor version behind the API server. ANDYL OS enforces this by building control plane and worker image variants from the same Kubernetes version. If a version skew is required during a rolling upgrade, it is temporary and limited to the upgrade window.

## Alternatives Considered

**CRI-O instead of containerd:** CRI-O is a lightweight CRI-only runtime. Rejected because containerd has broader ecosystem support, better tooling (nerdctl, crictl), and is the default runtime for most managed Kubernetes distributions.

**Baking Cilium into the golden image instead of runtime deployment:** Considered for faster time-to-ready on first boot, but rejected because it couples the CNI lifecycle to the OS image lifecycle, prevents operators from choosing alternative CNI plugins, and violates the principle of keeping the base image minimal and plugin-agnostic.

**Flannel instead of Cilium as default recommendation:** Flannel is simpler but uses VXLAN overlays and iptables, which do not scale well and do not provide network policy enforcement. Cilium's eBPF-based approach eliminates iptables overhead and provides built-in network policies and observability. However, with the pluggable architecture, operators can deploy Flannel if it better fits their use case.

**kube-proxy in iptables/IPVS mode:** Rejected in favor of Cilium's kube-proxy replacement. kube-proxy creates O(N) iptables rules per service and requires periodic rule reconciliation. Cilium's eBPF implementation provides O(1) service lookup.

**kubeadm for all cluster lifecycle management:** kubeadm is used for initial cluster bootstrap but not for ongoing management. ANDYL OS's generational deployment model (RFC-0005) handles OS-level upgrades including Kubernetes component binaries.

**Running control plane components as systemd services instead of static pods:** Considered for simplicity, but rejected because static pods provide consistent lifecycle management, health checking, and resource limits through the kubelet.

## Security Considerations

- **Immutable binaries:** All Kubernetes binaries (kubelet, containerd, runc, kubectl) are stored in content-addressed paths under `/nix/store` and are read-only at runtime. Tampering is detectable by comparing store path hashes against the generation manifest (RFC-0004).
- **TLS everywhere:** All Kubernetes component communication is encrypted with mutual TLS. Certificates are delivered via Ignition (RFC-0006) and rotated automatically by kubelet.
- **Read-only root filesystem:** Both the host OS and containers enforce read-only root filesystems.
- **Network policy enforcement:** The deployed CNI plugin is responsible for enforcing Kubernetes NetworkPolicy resources. Cilium (recommended) enforces policies in eBPF at the kernel level.
- **etcd encryption:** etcd communication uses mutual TLS.
- **Bootstrap token security:** Bootstrap tokens used for TLS bootstrapping are short-lived (24h default) and scoped to the `system:bootstrappers` group.

## Compatibility

- **Kubernetes version:** ANDYL OS targets Kubernetes 1.31.x. The generational model allows multiple K8s versions to coexist (different image variants), but a single cluster runs one version at a time (per the version skew policy).
- **containerd version:** containerd 1.7.x is the CRI implementation. It supports the CRI v1 API required by Kubernetes 1.31+.
- **CNI plugins:** Any conformant CNI plugin that deploys as a DaemonSet or Helm release is supported. Cilium 1.16.x is the recommended default and requires Linux kernel 5.10+ (ANDYL OS provides 6.12.x).
- **etcd version:** etcd 3.5.x is the target. It supports the storage backend required by Kubernetes 1.31.
- **Container images:** Workload containers use standard OCI images from any registry.
- **CSI drivers:** Container Storage Interface drivers run as DaemonSets and communicate via Unix sockets in `/var/lib/kubelet/plugins/`. No host OS changes are needed.

## Open Questions

1. **kubeadm vs. manual bootstrap:** Should we use kubeadm for initial cluster bootstrap (simpler, well-documented) or perform manual bootstrap (more control, fewer hidden assumptions)?
2. **etcd topology:** Should etcd run on control plane nodes (co-located, simpler) or on dedicated nodes (better isolation, more resources for etcd)?
3. **Plugin version matrix:** How do we document and test the compatibility matrix between OS generation, Kubernetes version, and plugin versions?
4. **Container image caching:** Should we pre-pull critical container images (pause, CoreDNS) into the golden image's `/var/lib/containerd` to speed up first boot?
5. **Multi-cluster support:** If ANDYL OS needs to support multiple Kubernetes clusters on the same fleet, how do we manage per-cluster kubelet configuration?
6. **GPU/accelerator support:** For ML workloads, GPU drivers and the NVIDIA device plugin need host-level support. How does this interact with the immutable OS model?

## References

- Kubernetes Documentation: https://kubernetes.io/docs/
- containerd CRI Plugin: https://github.com/containerd/containerd/blob/main/docs/cri/config.md
- Cilium Documentation: https://docs.cilium.io/
- Cilium kube-proxy Replacement: https://docs.cilium.io/en/stable/network/kubernetes/kubeproxy-free/
- Kubelet TLS Bootstrapping: https://kubernetes.io/docs/reference/access-authn-authz/kubelet-tls-bootstrapping/
- etcd Operations Guide: https://etcd.io/docs/v3.5/op-guide/
- Static Pods: https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/
- Kubernetes Version Skew Policy: https://kubernetes.io/docs/setup/release/version-skew-policy/
