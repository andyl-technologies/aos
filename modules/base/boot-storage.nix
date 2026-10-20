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
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.boot.storage;
  resolvedDevices = cfg.resolvedDevices;
  zfsPackage = pkgs.zfsForKernel config.system.build.kernel;
  containerDatasets = dataset: let
    segments = lib.splitString "/" dataset;
  in
    lib.genList (
      depth: lib.concatStringsSep "/" (lib.take (depth + 1) segments)
    ) (builtins.length segments);
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/boot/_aos-boot-storage/options.nix];
  options.aos.boot.storage.zfs = {
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
  };

  config = lib.mkMerge [
    {
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
    }
    (lib.mkIf config.aos.image.enable {
      environment.systemPackages = [
        pkgs.aos-boot-storage
        pkgs.aos-boot-transaction-storage-provider
      ];
      aos.boot.initrd.packageRoots = [
        pkgs.aos-boot-storage
        pkgs.aos-boot-transaction-storage-provider
      ];
    })
    (lib.mkIf (config.aos.image.enable && cfg.backend == "zfs-zvol") {
      aos.boot.initrd.modulePackages = [zfsPackage];
      aos.boot.initrd.packageRoots = [zfsPackage];
      aos.boot.initrd.loadModules = ["zfs"];

      aos.filesystems.zfs = {
        enable = true;
        poolName = cfg.zfs.poolName;
        datasets = lib.genAttrs (containerDatasets cfg.zfs.dataset) (_: {
          mountPoint = null;
          snapshot = false;
        });
      };
    })
  ];
}
