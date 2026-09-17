##! Exact system-manager selection shared by current system variants.
{
  config,
  lib,
  pkgs,
  ...
}: {
  environment.systemPackages =
    [pkgs.systemd]
    ++ lib.optional config.aos.boot.secureBoot.measuredBoot.enable pkgs.aos-systemd-var-policy;

  aos.boot.initrd.packageRoots = lib.mkIf (
    config.aos.boot.secureBoot.measuredBoot.enable
    && config.aos.boot.storage.backend != "zfs-zvol"
  ) [pkgs.aos-systemd-var-policy];

  aos.abilities.instances."systemd:system-manager-provider".implementation = "systemd:system-manager";

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
