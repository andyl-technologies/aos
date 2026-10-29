##! Registers immutable and retained store inputs before initrd journal replay.
{
  config,
  lib,
  pkgs,
  ...
}: let
  installerMedia = config.aos.image.installer.media or false;
  # Installer media journals in memory; an installed system journals on its ESP.
  journalStorage = lib.optional (!installerMedia) "aos-boot-transaction-storage.service";
  # Must equal the installer-mode initrdStateDirectory default selected inside
  # the initrd fixed point by the boot-preparations package.
  stateDirectory =
    if installerMedia
    then "/run/aos-installer/initrd-stage-journal"
    else config.aos.boot.substrateServices.initrdStateDirectory;
in {
  # Native retention needs a writable initrd Nix database before dispatch.
  boot.initrd.systemd.services.aos-native-store-seed = {
    description = "Register authenticated immutable initrd deployment inputs";
    before = ["aos-ability-initrd-controller.service"];
    requiredBy = ["aos-ability-initrd-controller.service"];
    after = journalStorage;
    requires = journalStorage;
    # These initrd-local inputs are needed before the early boot transaction.
    unitConfig.DefaultDependencies = false;
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
      ${pkgs.aos-systemd-provider}/bin/aos-systemd-initrd-store \
        --nix-store ${pkgs.nix}/bin/nix-store \
        --state-directory ${lib.escapeShellArg stateDirectory}
    '';
  };
}
