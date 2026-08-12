##! modules/base/boot-storage.nix — Immutable boot-storage addressing
##!
##! Separates the A/B image lifecycle from the block devices that carry its
##! immutable EROFS payloads and dm-verity trees. The stock image uses GPT
##! partition labels. Installed systems may instead address fixed-size ZFS
##! zvols while retaining the same signed UKIs, image generations, counted
##! boots, and rollback protocol.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.boot.storage;
  zvolBase = "/dev/zvol/${cfg.zfs.poolName}/${cfg.zfs.dataset}";
  defaultDevices =
    if cfg.backend == "zfs-zvol"
    then {
      rootA = "${zvolBase}/root-a";
      rootAHash = "${zvolBase}/root-a-hash";
      rootB = "${zvolBase}/root-b";
      rootBHash = "${zvolBase}/root-b-hash";
    }
    else {
      rootA = "/dev/disk/by-partlabel/root-a";
      rootAHash = "/dev/disk/by-partlabel/root-a-hash";
      rootB = "/dev/disk/by-partlabel/root-b";
      rootBHash = "/dev/disk/by-partlabel/root-b-hash";
    };
  resolvedDevices = lib.mapAttrs (
    name: fallback:
      if cfg.devices.${name} == null
      then fallback
      else cfg.devices.${name}
  ) defaultDevices;
  zfsPackage = pkgs.zfsForKernel config.system.build.kernel;
  deviceOption = name:
    lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Override the stable block-device path for the ${name} image artifact.";
    };
in {
  options.aos.boot.storage = {
    backend = lib.mkOption {
      type = lib.types.enum ["gpt-partitions" "zfs-zvol"];
      default = "gpt-partitions";
      description = ''
        Block-storage backend for immutable A/B image payloads. GPT partitions
        preserve the portable raw-image layout. zfs-zvol addresses fixed-size
        zvols in an imported pool without changing image-generation semantics.
      '';
    };

    espDevices = lib.mkOption {
      type = lib.types.nonEmptyListOf lib.types.str;
      default = ["/dev/disk/by-partlabel/ESP"];
      description = ''
        Stable device paths for independently bootable EFI System Partition
        replicas. The first entry is mounted at /boot; update transactions
        replicate bootloader configuration and UKIs to every entry.
      '';
    };

    devices = {
      rootA = deviceOption "slot-A root";
      rootAHash = deviceOption "slot-A dm-verity tree";
      rootB = deviceOption "slot-B root";
      rootBHash = deviceOption "slot-B dm-verity tree";
    };

    resolvedDevices = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      readOnly = true;
      internal = true;
      description = "Resolved immutable image block-device paths.";
    };

    zfs = {
      poolName = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z][A-Za-z0-9_.:-]*";
        default = "rpool";
        description = "Pool containing immutable image zvols.";
      };

      dataset = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)*";
        default = "aos/slots";
        description = "Dataset below the pool containing immutable image zvols.";
      };

      encryptionRoot = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z][A-Za-z0-9_.:-]*(/[A-Za-z0-9_.:-]+)*";
        default = cfg.zfs.poolName;
        description = "Native-encryption root containing immutable zvols and mutable datasets.";
      };

      sealedKeyPath = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.+/-]+";
        default = "aos/zfs-key.cred";
        description = "ESP-relative TPM-sealed native ZFS key path.";
      };
    };
  };

  config = lib.mkMerge [{
    assertions = [
      {
        assertion = lib.all (device: lib.hasPrefix "/dev/" device) cfg.espDevices;
        message = "aos.boot.storage.espDevices entries must be absolute /dev paths";
      }
      {
        assertion = lib.all (device: lib.hasPrefix "/dev/" device) (builtins.attrValues resolvedDevices);
        message = "resolved immutable boot-storage devices must be absolute /dev paths";
      }
    ];

    aos.boot.storage.resolvedDevices = resolvedDevices;
    aos.filesystems.espDevice = lib.mkDefault (builtins.head cfg.espDevices);
  } (lib.mkIf (cfg.backend == "zfs-zvol") {
    aos.kernel.modulePackages = [zfsPackage];
    aos.boot.initrd.extraPackages = [zfsPackage];
    aos.boot.initrd.loadModules = ["zfs"];
    aos.filesystems.zfs = {
      enable = true;
      poolName = cfg.zfs.poolName;
      package = zfsPackage;
    };

    boot.initrd.systemd.services."aos-zfs-unlock" = {
      description = "Import and unlock immutable ZFS boot storage";
      requiredBy = ["initrd-root-device.target"];
      before = ["sysroot.mount" "initrd-root-device.target"];
      after = ["systemd-udev-settle.service" "systemd-modules-load.service"];
      requires = ["systemd-udev-settle.service" "systemd-modules-load.service"];
      unitConfig.DefaultDependencies = "no";
      environment.PATH = lib.concatStringsSep ":" [
        (lib.makeBinPath [pkgs.coreutils pkgs.systemd pkgs.util-linux zfsPackage])
        (lib.makeSearchPath "sbin" [pkgs.coreutils pkgs.systemd pkgs.util-linux zfsPackage])
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        set -euo pipefail
        key=/run/aos-zfs.key
        esp=/run/aos-zfs-esp
        mkdir -p "$esp"
        credential=
        for device in ${lib.concatMapStringsSep " " lib.escapeShellArg cfg.espDevices}; do
          [ -e "$device" ] || continue
          if mount -t vfat -o ro,noatime,fmask=0077,dmask=0077 "$device" "$esp"; then
            if [ -r "$esp/${cfg.zfs.sealedKeyPath}" ]; then
              credential="$esp/${cfg.zfs.sealedKeyPath}"
              break
            fi
            umount "$esp"
          fi
        done
        if [ -z "$credential" ]; then
          echo "aos-zfs-unlock: sealed key is absent from every configured ESP" >&2
          exit 1
        fi

        signature=
        for candidate in /run/systemd/tpm2-pcr-signature.json \
          /.extra/tpm2-pcr-signature.json \
          /run/credentials/@system/tpm2-pcr-signature.json; do
          if [ -r "$candidate" ]; then signature="$candidate"; break; fi
        done
        signature_arg=
        [ -n "$signature" ] && signature_arg="--tpm2-signature=$signature"
        systemd-creds decrypt --name=aos-zfs-key $signature_arg "$credential" "$key"
        chmod 0400 "$key"
        umount "$esp"

        zpool import -N -f ${lib.escapeShellArg cfg.zfs.poolName}
        zfs load-key -L "file://$key" ${lib.escapeShellArg cfg.zfs.encryptionRoot}
        rm -f "$key"
        udevadm settle
        ${lib.concatMapStringsSep "\n" (device: ''
          i=0
          while [ ! -e ${lib.escapeShellArg device} ] && [ "$i" -lt 60 ]; do
            i=$((i + 1))
            sleep 0.5
          done
          [ -e ${lib.escapeShellArg device} ] || {
            echo "aos-zfs-unlock: expected zvol did not appear: ${device}" >&2
            exit 1
          }
        '') (builtins.attrValues resolvedDevices)}
      '';
    };
  })];
}
