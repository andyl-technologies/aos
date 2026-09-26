##! Checks Libvirt's package-owned services in a focused module fixed point.
{
  lib,
  pkgs,
}: let
  evaluateBase = import ./base-module-evaluation.nix {inherit lib pkgs;};
  packages = [pkgs.libvirt pkgs.systemd pkgs.dbus pkgs.polkit];
  evaluate = enabled:
    evaluateBase {
      name = "libvirt";
      module.aos.virtualization.libvirt = {
        enable = enabled;
        allowedUsers = ["operator"];
      };
      inherit packages;
    };
  disabled = evaluate false;
  enabled = evaluate true;
  disabledServices = evaluateBase {
    name = "libvirt-services-disabled";
    module = {lib, ...}: {
      aos.virtualization.libvirt = {
        enable = true;
        allowedUsers = ["operator"];
      };
      aos.services."libvirt.libvirtd".enable = lib.mkForce false;
      aos.services."libvirt.virtlockd".enable = lib.mkForce false;
      aos.services."libvirt.virtlogd".enable = lib.mkForce false;
    };
    inherit packages;
  };
  libvirtRequests = config:
    lib.filterAttrs (name: _: lib.hasPrefix "libvirt:" name) config.aos.abilities.requests;
  requests = libvirtRequests enabled.config;
in
  assert libvirtRequests disabled.config == {};
  assert libvirtRequests disabledServices.config == {};
  assert disabled.config.aos.abilities.requirementTemplates == enabled.config.aos.abilities.requirementTemplates;
  assert disabledServices.config.aos.abilities.requirementTemplates == enabled.config.aos.abilities.requirementTemplates;
  assert !(disabledServices.config.environment.etc ? libvirt);
  assert !(disabledServices.config.aos.abilities.runtimeChecks ? "libvirt:libvirt");
  assert requests ? "libvirt:libvirtd-lifecycle";
  assert requests ? "libvirt:virtlockd-lifecycle";
  assert requests ? "libvirt:virtlogd-lifecycle";
  assert requests ? "libvirt:access-membership";
  assert requests ? "libvirt:authorization-service-availability";
  assert builtins.length (builtins.filter (name: lib.hasPrefix "libvirt:allowed-" name) (builtins.attrNames requests)) == 1;
  assert enabled.config.aos.services."libvirt.libvirtd".enable;
  assert enabled.config.aos.services."libvirt.virtlockd".enable;
  assert enabled.config.aos.services."libvirt.virtlogd".enable; true
