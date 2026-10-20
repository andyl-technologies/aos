##! Registers immutable and retained store inputs before initrd journal replay.
{
  config,
  lib,
  pkgs,
  ...
}: {
  # Native retention needs a writable initrd Nix database before dispatch.
  boot.initrd.systemd.services.aos-native-store-seed = {
    description = "Register authenticated immutable initrd deployment inputs";
    before = ["aos-ability-initrd-controller.service"];
    requiredBy = ["aos-ability-initrd-controller.service"];
    after = ["aos-boot-transaction-storage.service"];
    requires = ["aos-boot-transaction-storage.service"];
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
        --state-directory ${lib.escapeShellArg config.aos.boot.substrateServices.initrdStateDirectory}
    '';
  };
}
