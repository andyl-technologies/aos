##! systems/server.nix — Server golden image
##!
##! Builds a server image suitable for cloud/datacenter deployment.
##! RFC-0011 evaluates signed host configuration at boot; Kubernetes role
##! configuration is applied separately.
##!
##! Profiles: server, debug
##!
##! Buildable with empty config root — all required options have defaults.
{...}: {
  aos.profiles.server.enable = true;
  aos.profiles.debug.enable = true;

  # Autologin root on tty1 + ttyS0 for interactive debugging.
  # Temporary — disable before the first real deployment.
  aos.profiles.debug.autologin = true;
}
