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
    ../pkgs/system/_systemd-abilities/platform/presets.nix
    ../pkgs/system/_systemd-abilities/platform/tmpfiles.nix
    ../pkgs/system/_systemd-abilities/platform/event-log.nix
    ../pkgs/system/_systemd-abilities/platform/crash-dump.nix
    ../pkgs/system/_systemd-abilities/platform/nsswitch.nix
  ];

  # Native retention needs a writable initrd Nix database before dispatch.
  boot.initrd.systemd.services.aos-native-store-seed = {
    description = "Register authenticated immutable initrd deployment inputs";
    before = ["aos-ability-initrd-controller.service"];
    requiredBy = ["aos-ability-initrd-controller.service"];
    path = [pkgs.coreutils];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      mkdir -p /nix/var/nix/db /nix/var/nix/gcroots
      expected=$(cat /lib/aos/initrd/registration.sha256)
      actual=$(${pkgs.coreutils}/bin/sha256sum /lib/aos/initrd/registration)
      test "$expected" = "''${actual%% *}"
      ${pkgs.nix}/bin/nix-store --load-db < /lib/aos/initrd/registration
    '';
  };

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
