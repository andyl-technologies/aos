##! Exact system-manager selection shared by current system variants.
{
  config,
  lib,
  pkgs,
  ...
}: let
  manager = lib.abilities.interfaces.systemManager.interfaces.manager;
  configured = config.aos.abilities.environment != null;
in {
  environment.systemPackages =
    [pkgs.systemd]
    ++ lib.optional config.aos.boot.secureBoot.measuredBoot.enable pkgs.aos-systemd-var-policy;

  # The initrd selects systemd's ability module explicitly. Provider
  # resolution may only inspect this authenticated root set; a binding does
  # not grant authority to discover a package through the ambient package set.
  aos.boot.initrd.packageRoots =
    [pkgs.systemd]
    ++ lib.optional (
      config.aos.boot.secureBoot.measuredBoot.enable
      && config.aos.boot.storage.backend != "zfs-zvol"
    )
    pkgs.aos-systemd-var-policy;

  aos.abilities.instances = lib.mkMerge [
    {"systemd:system-manager-provider".implementation = "systemd:system-manager";}
    (lib.mkIf configured {system-manager = {};})
  ];

  aos.abilities.requirementTemplates.system-manager = {
    description = "Requires the system's package-owned manager implementation.";
    interface = manager.identity.name;
    inherit (manager.identity) abi descriptor;
  };
  aos.abilities.requests = lib.mkIf configured {
    system-manager = {
      requirement = "system-manager";
      consumer = "system-manager";
      parameters = true;
    };
  };

  aos.abilities.bindings."system-manager:systemd" = {
    request = "aos:system-manager";
    implementation = "systemd:system-manager";
    providerInstance = "systemd:system-manager-provider";
    slot = "system-manager";
  };

  aos.abilities.bindings."package-store-read-view:systemd" =
    lib.mkIf (
      config.aos.abilities.environment
      != null
      && config.aos.abilities.environment.stage == "host"
    ) {
      request = "aos:package-store-read-view";
      implementation = "systemd:package-store-read-view";
      providerInstance = "systemd:package-store-read-view";
      slot = "boot-image";
    };
}
