##! modules/image/install-bundle.nix — Guarded ZFS bare-metal installer bundle
##!
##! Produces a self-contained target payload and destructive installer for the
##! zfs-zvol boot-storage backend. The operator supplies stable whole-disk
##! `/dev/disk/by-id` paths at invocation time. The installer creates an ESP
##! and ZFS member on every disk, pairs members into mirror vdevs, enables
##! native encryption, seeds both immutable slots, TPM-seals the pool key onto
##! every ESP, and returns the sole recovery copy to an explicit output path.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.boot.storage;
  image = config.system.build.image.raw;
  zfs = config.aos.filesystems.zfs.package;
  tries = config.aos.boot.bootCountingTries;
  ukiName = "aos-generation-0000000001${lib.optionalString (tries != null) "+${toString tries}"}.efi";
  efiNames = {
    x86_64 = {
      fallback = "BOOTX64.EFI";
      systemd = "systemd-bootx64.efi";
    };
    aarch64 = {
      fallback = "BOOTAA64.EFI";
      systemd = "systemd-bootaa64.efi";
    };
  };
  efiName = efiNames.${lib.platform.constraints.cpu} or (throw "no installer EFI names for ${lib.system}");
  pcrPublicKey = config.aos.boot.secureBoot.measuredBoot._effectivePcrPublicKey;
in {
  options.system.build.installBundle = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    readOnly = true;
    description = "Guarded bare-metal installation bundle for the selected boot-storage backend.";
  };

  config = lib.mkIf (cfg.backend == "zfs-zvol") {
    assertions = [
      {
        assertion = config.aos.boot.secureBoot.measuredBoot.enable;
        message = "zfs-zvol installation requires measured boot so the native ZFS key can be TPM-sealed";
      }
      {
        assertion = builtins.length cfg.espDevices >= 2;
        message = "zfs-zvol installation requires at least two independently bootable ESP devices";
      }
      {
        assertion = lib.all (value: value == null) (builtins.attrValues cfg.devices);
        message = "the zfs-zvol installer does not permit immutable device-path overrides";
      }
      {
        assertion = cfg.zfs.encryptionRoot == cfg.zfs.poolName;
        message = "the zfs-zvol installer requires the pool root to be the native-encryption root";
      }
    ];

    system.build.installBundle = pkgs.mkDerivation {
      pname = "aos-${config.aos.system.name}-zfs-installer";
      version = config.aos.system.version;
      src = null;
      buildDeps =
        [pkgs.coreutils pkgs.findutils config.system.build.checks.image-budget]
        ++ lib.optionals config.aos.boot.secureBoot.enable [pkgs.perl pkgs.sbsigntools];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/payload/esp/EFI/BOOT" \
              "$out/payload/esp/EFI/systemd" "$out/payload/esp/EFI/Linux" \
              "$out/payload/esp/loader"
            ln -s ${image.rootfs}/root.img "$out/payload/root.img"
            ln -s ${image.rootfs}/root.verity "$out/payload/root.verity"
            uki=$(find ${image.ukiA} -maxdepth 1 -type f -name '*.efi' -print)
            [ "$(printf '%s\n' "$uki" | wc -l)" -eq 1 ]
            ln -s "$uki" "$out/payload/esp/EFI/Linux/${ukiName}"
            ${lib.optionalString config.aos.boot.secureBoot.measuredBoot.enable ''
              ln -s ${image.ukiA}/*.measurement "$out/payload/esp/EFI/Linux/${ukiName}.measurement"
              ln -s ${image.ukiA}/*.measurement.sig "$out/payload/esp/EFI/Linux/${ukiName}.measurement.sig"
            ''}
            ${lib.optionalString config.aos.boot.secureBoot.enable ''
              sbsign --key ${config.aos.boot.secureBoot.dbKey} \
                --cert ${config.aos.boot.secureBoot._effectiveDbCert} \
                --output "$out/payload/esp/EFI/BOOT/${efiName.fallback}" \
                ${pkgs.systemd}/lib/systemd/boot/efi/${efiName.systemd}
            ''}
            ${lib.optionalString (!config.aos.boot.secureBoot.enable) ''
              ln -s ${pkgs.systemd}/lib/systemd/boot/efi/${efiName.systemd} \
                "$out/payload/esp/EFI/BOOT/${efiName.fallback}"
            ''}
            ln -s "$out/payload/esp/EFI/BOOT/${efiName.fallback}" \
              "$out/payload/esp/EFI/systemd/${efiName.systemd}"
            cat > "$out/payload/esp/loader/loader.conf" <<'LOADER'
            default aos-*.efi
            timeout 3
            console-mode max
            editor no
            LOADER
            cp ${pcrPublicKey} "$out/payload/pcr-public.pem"
            cp ${./install-zfs.sh.in} "$out/bin/aos-install-zfs"
            substituteInPlace "$out/bin/aos-install-zfs" \
              --replace-fail '@bash@' '${pkgs.bash}/bin/bash' \
              --replace-fail '@coreutils@' '${pkgs.coreutils}' \
              --replace-fail '@dosfstools@' '${pkgs.dosfstools}' \
              --replace-fail '@gptfdisk@' '${pkgs.gptfdisk}' \
              --replace-fail '@mtools@' '${pkgs.mtools}' \
              --replace-fail '@systemd@' '${pkgs.systemd}' \
              --replace-fail '@util_linux@' '${pkgs.util-linux}' \
              --replace-fail '@zfs@' '${zfs}' \
              --replace-fail '@pool@' '${cfg.zfs.poolName}' \
              --replace-fail '@dataset@' '${cfg.zfs.dataset}' \
              --replace-fail '@sealed_key_path@' '${cfg.zfs.sealedKeyPath}' \
              --replace-fail '@signed_pcrs@' '${config.aos.boot.secureBoot.measuredBoot.signedPcrs}' \
              --replace-fail '@pinned_pcrs@' '${config.aos.boot.secureBoot.measuredBoot.pinnedPcrs}' \
              --replace-fail '@esp_devices@' '${lib.concatStringsSep " " cfg.espDevices}' \
              --replace-fail '@esp_count@' '${toString (builtins.length cfg.espDevices)}' \
              --replace-fail '@root_slot_size@' '${toString cfg.zfs.rootSlotSizeMiB}' \
              --replace-fail '@verity_slot_size@' '${toString cfg.zfs.veritySlotSizeMiB}' \
              --replace-fail '@esp_size@' '${toString config.aos.image.budgets.maxEspMiB}'
            ${pkgs.bash}/bin/bash -n "$out/bin/aos-install-zfs"
            chmod 0755 "$out/bin/aos-install-zfs"
          '';
        }
      ];
      meta.description = "Guarded redundant-ESP and encrypted-ZFS installer bundle";
    };
  };
}
