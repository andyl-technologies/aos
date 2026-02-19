# 6. Kubernetes Activation (k3s)

## 6.1 Why k3s

k3s is a CNCF-certified Kubernetes distribution packaged as a single ~72 MB
binary. It replaces the traditional kubelet + kubeadm + kubectl + etcd +
kube-apiserver + kube-scheduler + kube-controller-manager stack:

| Full K8s | k3s |
|----------|-----|
| kubelet (~120 MB) | Embedded in `k3s` binary |
| kubeadm (~50 MB) | Not needed (k3s self-bootstraps) |
| kubectl (~50 MB) | `k3s kubectl` (embedded) |
| etcd (~30 MB) | Embedded (kine/sqlite or embedded etcd) |
| kube-apiserver (~120 MB) | Embedded in server mode |
| kube-scheduler | Embedded in server mode |
| kube-controller-manager | Embedded in server mode |
| CoreDNS | Auto-deployed as manifest |
| helm | `k3s` ships HelmChart CRD |
| ipvsadm, conntrack-tools | Not needed (Cilium replaces kube-proxy) |

## 6.2 Activation Model

The golden image contains k3s and containerd but Kubernetes is **not
running** by default. Cloud-init determines the role and activates the
correct service chain.

**Role determination**: The `aos.role` key in userdata:
- `k8s-control-plane`: containerd + k3s server (embeds API server, scheduler, controller-manager, etcd)
- `k8s-worker`: containerd + k3s agent (kubelet + kube-proxy replacement via Cilium)
- Any other value or absent: no Kubernetes services

**Service dependency chain when activated**:

```
k3s-modules-load.service (loads br_netfilter, overlay, vxlan, etc.)
  -> containerd.service (CRI runtime, external)
    -> k3s-server.service or k3s-agent.service
```

## 6.3 k3s Server Configuration (Control Plane)

Cloud-init writes `/etc/rancher/k3s/config.yaml`:

```yaml
# Control plane node
cluster-init: true                    # First CP node; omit for joining CPs
token-file: /run/secrets/k3s-token
container-runtime-endpoint: unix:///run/containerd/containerd.sock
data-dir: /var/lib/rancher/k3s

# Disable built-in components replaced by Cilium
flannel-backend: "none"
disable-kube-proxy: true
disable-network-policy: true
disable:
  - servicelb
  - traefik

# TLS SANs for API server certificate
tls-san:
  - k8s-api.internal
  - 10.0.0.10

# Network CIDRs
cluster-cidr: 10.244.0.0/16
service-cidr: 10.96.0.0/12

# Security
protect-kernel-defaults: true
secrets-encryption: true

# Kubelet args
kubelet-arg:
  - "rotate-certificates=true"
  - "read-only-port=0"
```

The `k3s-server.service` runs:

```ini
[Unit]
Description=k3s Server
After=containerd.service k3s-modules-load.service network-online.target
Requires=containerd.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/nix/store/.../bin/k3s server
KillMode=process
Delegate=yes
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Restart=on-failure
RestartSec=5s
EnvironmentFile=-/etc/default/k3s

[Install]
WantedBy=multi-user.target
```

**HA control plane**: First node uses `cluster-init: true`. Subsequent
control plane nodes receive a config with `server: https://k8s-api.internal:6443`
instead of `cluster-init`. k3s uses embedded etcd for HA consensus.

**Embedded etcd**: Uses ZFS dataset at `/var/lib/rancher/k3s/server/db/etcd`
with `recordsize=4K` and `sync=always` for optimal write performance.

## 6.4 k3s Agent Configuration (Worker)

```yaml
# Worker node
server: https://k8s-api.internal:6443
token-file: /run/secrets/k3s-token
container-runtime-endpoint: unix:///run/containerd/containerd.sock
data-dir: /var/lib/rancher/k3s

# Node labels
node-label:
  - "topology.kubernetes.io/zone=us-east-1a"

# Kubelet args
kubelet-arg:
  - "rotate-certificates=true"
  - "read-only-port=0"
```

The `k3s-agent.service` is identical to server but runs `k3s agent`.

## 6.5 Cilium Integration

Cilium serves as the CNI, kube-proxy replacement, ingress controller, and
L2/L3 local IP provisioner. It is installed on the first control plane
boot via `cloud-final`:

```bash
# Installed by aos_cilium cloud-init module (first CP only)
k3s kubectl apply -f /etc/aos/cilium-install.yaml
```

Or via Helm (k3s supports HelmChart CRD):

```yaml
# /var/lib/rancher/k3s/server/manifests/cilium.yaml
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  name: cilium
  namespace: kube-system
spec:
  repo: https://helm.cilium.io/
  chart: cilium
  version: "1.16"
  targetNamespace: kube-system
  valuesContent: |-
    kubeProxyReplacement: true
    k8sServiceHost: k8s-api.internal
    k8sServicePort: 6443
    operator:
      replicas: 1
    hubble:
      enabled: true
      relay:
        enabled: true
      ui:
        enabled: true
    ingressController:
      enabled: true
      default: true
    gatewayAPI:
      enabled: true
    l2announcements:
      enabled: true
    externalIPs:
      enabled: true
    envoy:
      enabled: true
```

**Cilium capabilities used**:

| Feature | Purpose | Replaces |
|---------|---------|----------|
| eBPF datapath | Pod networking, network policy | flannel + kube-proxy + iptables |
| kube-proxy replacement | Service load balancing via eBPF | kube-proxy (ipvs/iptables) |
| Ingress controller | HTTP/gRPC routing to services | nginx-ingress |
| Gateway API | Advanced traffic management | nginx + custom configs |
| L2 announcements | Local IP provisioning (ARP/NDP) | MetalLB |
| Envoy proxy | L7 policy, rate limiting, mTLS | standalone envoyproxy |
| Hubble | Network observability, flow logs | node-exporter (partial) |
| Network policies | Pod-to-pod segmentation | Kubernetes NetworkPolicy |
| WireGuard encryption | Node-to-node pod traffic encryption | Manual WireGuard setup |

## 6.6 Containerd Configuration

Cloud-init writes `/etc/containerd/config.toml` from a template, with
overrides for:
- Registry mirrors (from `aos.kubernetes.containerd.registry_mirrors`)
- Sandbox image (from `aos.kubernetes.containerd.sandbox_image`)
- Snapshotter backend
- Private registry authentication

containerd is built as an AOS package and runs as a separate systemd service
(not k3s's embedded containerd), connected via `--container-runtime-endpoint`.

## 6.7 Day-2 Operations

**Node re-provisioning**: Cordon + drain + switch to new generation
(reboot or `aos system switch --now`) + uncordon. Cloud-init re-applies
role from unchanged userdata. k3s detects existing state on ZFS and
resumes.

**k3s version upgrades**: New generation with updated k3s binary. APM
downloads the generation; `aos system switch` activates it. Control plane
nodes upgraded first (one at a time), then workers (rolling). k3s handles
the upgrade automatically on restart.

**Certificate rotation**: k3s auto-rotates all certificates. No manual
renewal needed (unlike kubeadm which requires periodic `certs renew`).

**etcd backup**: Hourly timer runs `k3s etcd-snapshot save` to
`/var/lib/rancher/k3s/server/db/snapshots/` (ZFS). Pruned after 7 days.
k3s also supports `--etcd-snapshot-schedule-cron` for built-in scheduling.
