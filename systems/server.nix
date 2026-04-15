##! systems/server.nix — Server golden image
##!
##! Builds a server image suitable for cloud/datacenter deployment with
##! Kubernetes support (both control plane and worker roles). Cloud-init
##! configures the actual role at boot time.
##!
##! Profiles: server, k8s.control, k8s.worker, debug
##!
##! Buildable with empty config root — all required options have defaults.
{ ... }:
{
  # Enable server profiles — cloud-init selects the active role at boot
  aos.profiles.server.enable = true;
  aos.profiles.k8s.control.enable = true;
  aos.profiles.k8s.worker.enable = true;
  aos.profiles.debug.enable = true;

  # Autologin root on tty1 + ttyS0 for interactive debugging of the
  # stage-2 service failures (task #15). Temporary — disable before
  # the first real deployment.
  aos.profiles.debug.autologin = true;

  # Print systemctl --failed + short journal tails for the known
  # stage-2 flakies to the serial console on boot. Pairs with task #15.
  aos.tests.stage2Diagnostics.enable = true;
}
