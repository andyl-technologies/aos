# systems/k8s-worker.nix — Kubernetes worker node variant
#
# Extends the server variant with the container runtime and Kubernetes
# node agent. Suitable for nodes that run Pod workloads but do not host
# the control plane (etcd, kube-apiserver, etc.).
#
# Adds over server:
#   - containerd (CRI-compatible container runtime)
#   - kubelet (Kubernetes node agent)
#   - CNI networking (bridge, VXLAN via Flannel/Cilium)
#   - Prometheus node-exporter for host metrics
#   - Firewall rules for kubelet, kube-proxy, NodePort range, and VXLAN

{
  config,
  pkgs,
  lib,
  ...
}:

{
  imports = [
    ./server.nix
    ../modules/kubernetes/containerd.nix
    ../modules/kubernetes/kubelet.nix
    ../modules/kubernetes/network.nix
    ../modules/kubernetes/node-problem-detector.nix
    ../modules/monitoring/node-exporter.nix
    ../modules/monitoring/hardware.nix
  ];

  aos.system.variant = "k8s-worker";

  # --- Disk image sizing ---
  # Workers need more space for container images and ephemeral pod storage.
  aos.image.diskSize = "32G";
  aos.image.rootSize = "12G";

  # --- Container runtime ---
  aos.kubernetes.containerd.enable = true;

  # --- Kubernetes node agent ---
  aos.kubernetes.kubelet.enable = true;

  # --- Pod networking (CNI) ---
  aos.kubernetes.network.enable = true;

  # --- Monitoring ---
  aos.monitoring.nodeExporter.enable = true;

  # --- Firewall ---
  # Worker ports:
  #   22    — SSH
  #   10250 — kubelet API
  #   10256 — kube-proxy health
  #   30000-32767 — NodePort service range
  aos.firewall.allowedTCP = [
    22
    10250
    10256
  ]
  ++ (lib.range 30000 32767);

  # 8472/UDP — VXLAN overlay traffic (Flannel, Cilium VXLAN mode)
  aos.firewall.allowedUDP = [ 8472 ];

  # Container networking requires forwarding between interfaces.
  aos.firewall.forwardPolicy = "accept";
}
