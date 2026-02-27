##! modules/profiles/minimal.nix — Minimal profile
##!
##! Disables all optional security frameworks for a stripped-down system.
##! SELinux, audit logging, and system hardening are all turned off. This
##! profile is suitable for lightweight VMs, CI runners, or environments
##! where the security boundary is provided by an external layer (e.g.,
##! a hypervisor or container runtime).
{
  config,
  pkgs,
  lib,
  ...
}:
{
  aos.security.selinux.enable = false;
  aos.security.audit.enable = false;
  aos.security.hardening.enable = false;
}
