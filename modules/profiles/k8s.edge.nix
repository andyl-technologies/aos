##! modules/profiles/k8s.edge.nix — KubeEdge node profile
##!
##! Configures the system as a KubeEdge edge node running edgecore.
##! Designed for lightweight edge devices that connect to a cloud-side
##! CloudCore controller. No full Kubernetes control plane or kubelet.
{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.aos.profiles.k8s.edge;
in
{
  options.aos.profiles.k8s.edge = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the KubeEdge edge node profile. Runs edgecore to connect
        to a CloudCore controller. Includes containerd but not the full
        kubelet or control plane.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Container runtime for edge workloads
    aos.kubernetes.containerd.enable = lib.mkDefault true;

    # KubeEdge edgecore service
    aos.kubernetes.edgecore.enable = lib.mkDefault true;
  };
}
