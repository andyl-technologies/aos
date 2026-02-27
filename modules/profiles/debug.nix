##! modules/profiles/debug.nix — Debug profile
##!
##! Relaxes security controls to facilitate development and debugging.
##! SELinux runs in permissive mode (logs violations without denying access),
##! core dumps are enabled for crash analysis, and kernel lockdown is
##! disabled to allow kernel debugging tools. This profile should never
##! be used in production environments.
{
  config,
  pkgs,
  lib,
  ...
}:
{
  aos.security.selinux.enable = true;
  aos.security.selinux.mode = "permissive";
  aos.security.hardening.coreDump.enable = true;
  aos.security.hardening.kernelLockdown = "none";
}
