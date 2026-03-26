##! systems/server.nix — Server golden image
##!
##! Builds a server image suitable for cloud/datacenter deployment with
##! Kubernetes support (both control plane and worker roles). Cloud-init
##! configures the actual role at boot time.
##!
##! Profiles: server, k8s.control, k8s.worker, debug
##!
##! Buildable with empty config root — all required options have defaults.
{ config, pkgs, lib, ... }:
{
  # Enable server profiles — cloud-init selects the active role at boot
  aos.profiles.server.enable = true;
  aos.profiles.k8s.control.enable = true;
  aos.profiles.k8s.worker.enable = true;
  aos.profiles.debug.enable = true;
}
