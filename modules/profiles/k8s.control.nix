##! modules/profiles/k8s.control.nix — Kubernetes control plane profile
##!
##! Enables the Kubernetes control plane components: API server, etcd,
##! controller manager, scheduler. Implies the kubelet and container runtime.
##! ZFS datasets for etcd/containerd are handled by their respective service
##! modules (control-plane.nix, containerd.nix).
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.profiles.k8s.control;
in {
  options.aos.profiles.k8s.control = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the Kubernetes control plane profile. Enables the API server,
        etcd, controller manager, scheduler, kubelet, containerd, and
        networking prerequisites.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Control plane (also enables kubelet, network)
    aos.kubernetes.controlPlane.enable = lib.mkDefault true;

    # Container runtime
    aos.kubernetes.containerd.enable = lib.mkDefault true;

    # Kubernetes packages
    environment.systemPackages = [
      pkgs.kubectl
      pkgs.crictl
    ];
  };
}
