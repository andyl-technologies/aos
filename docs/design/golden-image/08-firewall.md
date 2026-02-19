# 8. Firewall

## 8.1 Base Ruleset (Baked Into Image)

```nft
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    tcp dport 22 accept
    log prefix "nft-drop: " flags all counter drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}

include "/etc/nftables.d/*.nft"
```

## 8.2 Role-Specific Rules via Cloud-Init

Cloud-init writes drop-in files to `/etc/nftables.d/`:

**Server** (`20-server.nft`):

```nft
add rule inet filter input tcp dport { 80, 443 } accept comment "HTTP/HTTPS"
```

**K8s Worker** (`20-k8s-worker.nft`):

```nft
add rule inet filter input tcp dport 10250 accept comment "kubelet API"
add rule inet filter input tcp dport 30000-32767 accept comment "NodePort"
add rule inet filter input udp dport 8472 accept comment "Cilium VXLAN"
add rule inet filter input udp dport 51871 accept comment "Cilium WireGuard"
add rule inet filter input tcp dport { 4240, 4244, 4245 } accept comment "Cilium health/Hubble"
add rule inet filter input tcp dport 9962 accept comment "Cilium agent metrics"
add rule inet filter input iifname "cilium_host" accept
add rule inet filter input iifname "cilium_net" accept
add rule inet filter input iifname "lxc*" accept
flush chain inet filter forward
add rule inet filter forward ct state established,related accept
add rule inet filter forward ct state invalid drop
add rule inet filter forward ip daddr 169.254.169.254 iifname "lxc*" drop
add rule inet filter forward accept
```

**K8s Control Plane** (`20-k8s-control-plane.nft`): worker rules plus:

```nft
add rule inet filter input tcp dport 6443 accept comment "kube-apiserver"
add rule inet filter input tcp dport { 2379, 2380 } accept comment "etcd"
add rule inet filter input tcp dport 10257 accept comment "controller-manager"
add rule inet filter input tcp dport 10259 accept comment "kube-scheduler"
```

## 8.3 Kubernetes Network Prerequisites

Only applied when role includes Kubernetes:

**Kernel modules** (`/etc/modules-load.d/k8s.conf`):

```
br_netfilter
overlay
vxlan
geneve
wireguard
```

Note: `ip_vs`, `ip_vs_rr`, `ip_vs_wrr`, `ip_vs_sh` are **not** needed
because Cilium replaces kube-proxy with eBPF-based service load balancing.

**Sysctls** (`/etc/sysctl.d/90-k8s-networking.conf`):

```ini
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.netfilter.nf_conntrack_max = 1048576
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
```

These are **NOT** set in the golden image base (they weaken the default
security posture). Cloud-init applies them only on K8s nodes.
