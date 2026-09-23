##! Checks Libvirt's package-owned services in a focused module fixed point.
{
  lib,
  pkgs,
}: let
  evaluateBase = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluate = enabled:
    evaluateBase {
      name = "libvirt";
      module.aos.virtualization.libvirt = {
        enable = enabled;
        allowedUsers = ["operator"];
      };
      packages = [pkgs.libvirt pkgs.systemd pkgs.dbus pkgs.polkit];
    };
  disabled = evaluate false;
  enabled = evaluate true;
  libvirtRequests = config:
    lib.filterAttrs (name: _: lib.hasPrefix "libvirt:" name) config.aos.abilities.requests;
  requests = libvirtRequests enabled.config;
in
  assert libvirtRequests disabled.config == {};
  assert requests ? "libvirt:libvirtd-lifecycle";
  assert requests ? "libvirt:virtlockd-lifecycle";
  assert requests ? "libvirt:virtlogd-lifecycle";
  assert requests ? "libvirt:access-membership";
  assert requests ? "libvirt:authorization-service-availability";
  assert builtins.length (builtins.filter (name: lib.hasPrefix "libvirt:allowed-" name) (builtins.attrNames requests)) == 1;
  assert enabled.config.aos.services."libvirt.libvirtd".enable;
  assert enabled.config.aos.services."libvirt.virtlockd".enable;
  assert enabled.config.aos.services."libvirt.virtlogd".enable; true
