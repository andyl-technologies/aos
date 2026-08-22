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
  resolvedDevices =
    lib.mapAttrs (
      name: fallback:
        if cfg.devices.${name} == null
        then fallback
        else cfg.devices.${name}
    )
    defaultDevices;
  zfsPackage = pkgs.zfsForKernel config.system.build.kernel;
  espSync = config.aos.config.artifacts.esp-sync;
  espMount = config.aos.config.artifacts.esp-mount;
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
        replicas. Firmware identifies the ESP that actually booted; it becomes
        the authoritative /boot mount, and successful update transactions
        replicate bootloader configuration and UKIs to every other entry.
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

      rootSlotSizeMiB = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0);
        default = config.aos.image.rootPartitionMiB;
        description = "Fixed capacity of each immutable root zvol in MiB.";
      };

      veritySlotSizeMiB = lib.mkOption {
        type = lib.types.addCheck lib.types.int (value: value > 0);
        default = config.aos.image.budgets.maxVerityMiB;
        description = "Fixed capacity of each dm-verity hash zvol in MiB.";
      };

      sealedKeyPath = lib.mkOption {
        type = lib.types.strMatching "aos/[A-Za-z0-9_.+-]+";
        default = "aos/zfs-key.cred";
        description = "ESP-relative TPM-sealed native ZFS key path.";
      };
    };
  };

  config = lib.mkMerge [
    {
      aos.config._artifactSources = {
        esp-sync =
          if config.aos.config.frozenArtifacts ? "esp-sync"
          then null
          else
            pkgs.runCommand "aos-sync-esps" {
              buildDeps = [pkgs.coreutils pkgs.perl];
            } ''
              mkdir -p "$out/bin"
              cp ${./sync-esps.sh.in} "$out/bin/aos-sync-esps"
              substituteInPlace "$out/bin/aos-sync-esps" \
                --replace-fail '@bash@' '${pkgs.bash}/bin/bash' \
                --replace-fail '@coreutils@' '${pkgs.coreutils}' \
                --replace-fail '@jq@' '${pkgs.jq}' \
                --replace-fail '@rsync@' '${pkgs.rsync}' \
                --replace-fail '@util_linux@' '${pkgs.util-linux}'
              ${pkgs.bash}/bin/bash -n "$out/bin/aos-sync-esps"
              chmod 0755 "$out/bin/aos-sync-esps"
            '';
        esp-mount =
          if config.aos.config.frozenArtifacts ? "esp-mount"
          then null
          else
            pkgs.runCommand "aos-mount-esp" {
              buildDeps = [pkgs.coreutils pkgs.perl];
            } ''
              mkdir -p "$out/bin"
              cp ${./mount-esp.sh.in} "$out/bin/aos-mount-esp"
              substituteInPlace "$out/bin/aos-mount-esp" \
                --replace-fail '@bash@' '${pkgs.bash}/bin/bash' \
                --replace-fail '@coreutils@' '${pkgs.coreutils}' \
                --replace-fail '@jq@' '${pkgs.jq}' \
                --replace-fail '@util_linux@' '${pkgs.util-linux}'
              ${pkgs.bash}/bin/bash -n "$out/bin/aos-mount-esp"
              chmod 0755 "$out/bin/aos-mount-esp"
            '';
      };

      assertions = [
        {
          assertion = lib.all (device: lib.hasPrefix "/dev/" device) cfg.espDevices;
          message = "aos.boot.storage.espDevices entries must be absolute /dev paths";
        }
        {
          assertion = lib.all (device: lib.hasPrefix "/dev/" device) (builtins.attrValues resolvedDevices);
          message = "resolved immutable boot-storage devices must be absolute /dev paths";
        }
        {
          assertion = !lib.hasInfix ".." cfg.zfs.sealedKeyPath;
          message = "aos.boot.storage.zfs.sealedKeyPath must be a normalized path under aos/";
        }
        {
          assertion = cfg.zfs.rootSlotSizeMiB >= config.aos.image.budgets.maxRootMiB;
          message = "ZFS root slot capacity must be at least the image root artifact budget";
        }
        {
          assertion = cfg.zfs.veritySlotSizeMiB >= config.aos.image.budgets.maxVerityMiB;
          message = "ZFS verity slot capacity must be at least the image verity artifact budget";
        }
      ];

      aos.boot.storage.resolvedDevices = resolvedDevices;
      aos.filesystems.espDevice = lib.mkDefault (builtins.head cfg.espDevices);
      environment.systemPackages = [espMount espSync];
      systemd.services.aos-mount-esp = {
        description = "Mount an available booted EFI System Partition";
        wantedBy = ["local-fs.target"];
        before = ["local-fs.target" "aos-image-boot-commit.service"];
        unitConfig = {
          DefaultDependencies = "no";
          ConditionPathExists = "/sys/firmware/efi";
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''${espMount}/bin/aos-mount-esp'';
      };
      systemd.services.aos-sync-esps = {
        description = "Replicate the primary EFI System Partition";
        wantedBy = ["multi-user.target"];
        after = ["aos-image-boot-commit.service"];
        requires = ["aos-image-boot-commit.service"];
        unitConfig.ConditionPathExists = "/sys/firmware/efi";
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          ${espSync}/bin/aos-sync-esps
        '';
      };
    }
    (lib.mkIf (cfg.backend == "zfs-zvol") {
      aos.kernel.modulePackages = [zfsPackage];
      aos.boot.initrd.modulePackages = [zfsPackage];
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
          mounted=false
          cleanup() {
            rm -f "$key"
            if [ "$mounted" = true ]; then umount "$esp" || true; fi
          }
          trap cleanup EXIT INT TERM
          mkdir -p "$esp"
          signature=
          for candidate in /run/systemd/tpm2-pcr-signature.json \
            /.extra/tpm2-pcr-signature.json \
            /run/credentials/@system/tpm2-pcr-signature.json; do
            if [ -r "$candidate" ]; then signature="$candidate"; break; fi
          done
          signature_arg=
          [ -n "$signature" ] && signature_arg="--tpm2-signature=$signature"
          unlocked=false
          for device in ${lib.concatMapStringsSep " " lib.escapeShellArg cfg.espDevices}; do
            [ -e "$device" ] || continue
            if mount -t vfat -o ro,noatime,fmask=0077,dmask=0077 "$device" "$esp"; then
              mounted=true
              if [ -r "$esp/${cfg.zfs.sealedKeyPath}" ]; then
                rm -f "$key"
                if systemd-creds decrypt --name=aos-zfs-key $signature_arg \
                  "$esp/${cfg.zfs.sealedKeyPath}" "$key"; then
                  chmod 0400 "$key"
                  unlocked=true
                  umount "$esp"
                  mounted=false
                  break
                fi
                rm -f "$key"
              fi
              umount "$esp"
              mounted=false
            fi
          done
          if [ "$unlocked" != true ]; then
            echo "aos-zfs-unlock: no configured ESP supplied a usable sealed key" >&2
            exit 1
          fi

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
    })
  ];
}
