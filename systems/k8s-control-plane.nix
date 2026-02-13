# systems/k8s-control-plane.nix — Kubernetes control plane variant
#
# Extends the worker variant with control plane components. Nodes running
# this variant host etcd, kube-apiserver, kube-controller-manager, and
# kube-scheduler in addition to the standard kubelet workload.
#
# Adds over k8s-worker:
#   - Control plane services (etcd, apiserver, controller-manager, scheduler)
#   - Firewall rules for control plane ports
#
# Port inventory:
#   22    — SSH
#   2379  — etcd client API
#   2380  — etcd peer communication
#   6443  — kube-apiserver (HTTPS)
#   10250 — kubelet API
#   10256 — kube-proxy health
#   10257 — kube-controller-manager (HTTPS)
#   10259 — kube-scheduler (HTTPS)
#   30000-32767 — NodePort service range

{
  config,
  pkgs,
  lib,
  ...
}:

{
  imports = [
    ./k8s-worker.nix
    ../modules/kubernetes/control-plane.nix
  ];

  aos.system.variant = "k8s-control-plane";

  # --- Disk image sizing ---
  # Control plane needs space for etcd data and control plane binaries.
  aos.image.diskSize = "32G";
  aos.image.rootSize = "12G";

  # --- Control plane ---
  aos.kubernetes.controlPlane.enable = true;

  # --- Firewall ---
  # Control plane needs all worker ports plus etcd and API server ports.
  aos.firewall.allowedTCP = [
    22 # SSH
    2379 # etcd client
    2380 # etcd peer
    6443 # kube-apiserver
    10250 # kubelet API
    10256 # kube-proxy health
    10257 # kube-controller-manager
    10259 # kube-scheduler
  ]
  ++ (lib.range 30000 32767);
}
