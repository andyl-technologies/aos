##! systems/server.nix — Server golden image
##!
##! Builds a server image suitable for cloud/datacenter deployment with
##! Kubernetes support (both control plane and worker roles). Ignition
##! configures the actual role at first boot.
##!
##! Profiles: server, k8s.control, k8s.worker, debug
##!
##! Buildable with empty config root — all required options have defaults.
{...}: {
  # Enable server profiles — ignition selects the active role at first boot
  aos.profiles.server.enable = true;
  aos.profiles.k8s.control.enable = true;
  aos.profiles.k8s.worker.enable = true;
  aos.profiles.debug.enable = true;

  # Autologin root on tty1 + ttyS0 for interactive debugging.
  # Temporary — disable before the first real deployment.
  aos.profiles.debug.autologin = true;
}
