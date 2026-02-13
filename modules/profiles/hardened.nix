# modules/profiles/hardened.nix — Hardened security profile
#
# Activates the maximum security posture for production deployments.
# Enables SELinux in enforcing mode, kernel lockdown at confidentiality
# level, audit logging, system hardening, core dump suppression, and
# the nftables firewall. This profile is intended for nodes handling
# sensitive workloads where security takes precedence over debuggability.

{
  config,
  pkgs,
  lib,
  ...
}:

{
  aos.security.selinux.enable = true;
  aos.security.selinux.mode = "enforcing";
  aos.security.audit.enable = true;
  aos.security.hardening.enable = true;
  aos.security.hardening.kernelLockdown = "confidentiality";
  aos.security.hardening.coreDump.enable = false;
  aos.firewall.enable = true;
}
