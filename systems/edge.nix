##! systems/edge.nix — Edge/IoT golden image
##!
##! Builds an edge image for IoT and edge deployments (Jetson Nano,
##! Raspberry Pi, small appliances) with KubeEdge support. Cloud-init
##! configures the system at boot time.
##!
##! Profiles: edge, k8s.edge
##!
##! Buildable with empty config root — all required options have defaults.
{...}: {
  # Enable edge profiles
  aos.profiles.edge.enable = true;
  aos.profiles.k8s.edge.enable = true;

  # No ZFS on edge — override if k8s.edge profile set it
  aos.filesystems.zfs.enable = false;
}
