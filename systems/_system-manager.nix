##! Exact system-manager selection shared by current system variants.
{config, lib, pkgs, ...}: {
  environment.systemPackages =
    [pkgs.systemd]
    ++ lib.optional config.aos.boot.secureBoot.measuredBoot.enable pkgs.aos-systemd-var-policy;

  aos.boot.initrd.packageRoots = lib.mkIf (
    config.aos.boot.secureBoot.measuredBoot.enable
    && config.aos.boot.storage.backend != "zfs-zvol"
  ) [pkgs.aos-systemd-var-policy];

  aos.abilities.instances."systemd:system-manager-provider".implementation =
    "systemd:system-manager";

  aos.abilities.bindings."system-manager:systemd" = {
    request = "system:manager";
    implementation = "systemd:system-manager";
    providerInstance = "systemd:system-manager-provider";
    slot = "system-manager";
  };
}
