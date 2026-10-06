##! Exact system-manager selection shared by current system variants.
{
  config,
  lib,
  pkgs,
  ...
}: {
  imports = [
    ../pkgs/system/_systemd-abilities/manager.nix
    ../pkgs/system/_systemd-abilities/platform/system.nix
    ../pkgs/system/_systemd-abilities/platform/initrd.nix
    ../pkgs/system/_systemd-abilities/platform/initrd-store.nix
    ../pkgs/system/_systemd-abilities/platform/presets.nix
    ../pkgs/system/_systemd-abilities/platform/tmpfiles.nix
    ../pkgs/system/_systemd-abilities/platform/event-log.nix
    ../pkgs/system/_systemd-abilities/platform/crash-dump.nix
    ../pkgs/system/_systemd-abilities/platform/nsswitch.nix
  ];

  environment.systemPackages =
    [pkgs.systemd]
    ++ lib.optional config.aos.boot.secureBoot.measuredBoot.enable pkgs.aos-systemd-var-policy;

  aos.boot.initrd.packageRoots =
    [pkgs.systemd]
    ++ lib.optional (
      config.aos.boot.secureBoot.measuredBoot.enable
      && config.aos.boot.storage.backend != "zfs-zvol"
    )
    pkgs.aos-systemd-var-policy;
}
