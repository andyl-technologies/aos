##! modules/profiles/k8s.worker.nix — Kubernetes worker node profile
##!
##! Enables the Kubernetes worker components: kubelet, containerd,
##! and networking prerequisites. No control plane components.
##! ZFS dataset for containerd is handled by containerd.nix.
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.profiles.k8s.worker;
in {
  options.aos.profiles.k8s.worker = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the Kubernetes worker node profile. Enables kubelet,
        containerd, and networking prerequisites without control plane
        components.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Kubelet
    aos.kubernetes.kubelet.enable = lib.mkDefault true;

    # Container runtime
    aos.kubernetes.containerd.enable = lib.mkDefault true;

    # Networking prerequisites
    aos.kubernetes.network.enable = lib.mkDefault true;

    # Kubernetes packages
    environment.systemPackages = [
      pkgs.kubectl
      pkgs.crictl
    ];
  };
}
