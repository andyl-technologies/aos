# systems/base.nix — Minimal bootable AOS system
#
# The foundation variant: a bootable system with networking, users, and
# first-boot provisioning via Ignition. All other variants import this.
#
# Provides:
#   - System identity (os-release, hostname, locale, timezone)
#   - systemd-boot with kernel and initrd
#   - Root and ESP filesystem layout
#   - Basic networking (systemd-networkd, resolved)
#   - Core user accounts (root + aos service user)
#   - Ignition for first-boot machine provisioning
#
# This variant is suitable for minimal VMs, test environments, and as the
# base layer that server and Kubernetes variants extend.

{
  config,
  pkgs,
  lib,
  ...
}:

{
  imports = [
    ../modules/base/build.nix
    ../modules/base/system.nix
    ../modules/base/boot.nix
    ../modules/base/filesystems.nix
    ../modules/base/networking.nix
    ../modules/base/users.nix
    ../modules/base/journald.nix
    ../modules/base/kernel.nix
    ../modules/base/swap.nix
    ../modules/services/ignition.nix
  ];

  aos.system.variant = "base";

  # Base defaults are defined in the imported modules.
  # This file intentionally sets no additional options — the module
  # defaults produce a minimal, bootable system.
}
