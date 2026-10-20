##! Portable image boot policy used by native initrd replay.
{
  config,
  lib,
  ...
}: {
  options.aos.security.verity = {
    ## Enable dm-verity root anchoring for the immutable erofs root.
    ##
    ## Opt-in. When false (the default, and every ext4/VM-test system) this
    ## module is completely inert: no kernel params, no initrd module, no root
    ## device change, and the build-side hash tree / partition / cmdline append
    ## stay gated off. Enable it only on a measured-boot production variant whose
    ## root filesystem is `erofs` (a writable ext4 root must never be verity-
    ## protected — it would be mutated and break the root hash).
    ##
    ## # See Also
    ## - `aos.security.verity.dataDevice`, `aos.security.verity.hashDevice`
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable dm-verity root anchoring. When enabled, the build
        produces a Merkle hash tree over the read-only erofs root, ships it in a
        dedicated `root-a-hash` GPT partition, and bakes the root hash into the
        measured UKI `.cmdline`. At boot, systemd-veritysetup-generator assembles
        `/dev/mapper/root` and the kernel verifies every block on read. Requires
        an `erofs` root filesystem.
      '';
    };

    ## Block device carrying the read-only root filesystem data (verity lower).
    dataDevice = lib.mkOption {
      type = lib.types.str;
      default = config.aos.boot.storage.resolvedDevices.rootA;
      description = ''
        Block device containing the read-only root filesystem data — the device
        dm-verity verifies on every read. Discovered by GPT partlabel so it is
        stable across disk renaming (vda vs. nvme0n1); matches the `root-a`
        partition the image builder writes.
      '';
    };

    ## Block device carrying the dm-verity Merkle hash tree.
    hashDevice = lib.mkOption {
      type = lib.types.str;
      default = config.aos.boot.storage.resolvedDevices.rootAHash;
      description = ''
        Block device containing the dm-verity hash tree (Merkle tree). This is
        the `root-a-hash` partition the image builder places immediately after
        `root-a`, sized from the build-time `root-verity-size-bytes`.
      '';
    };
  };

  options.aos.boot.secureBoot = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Sign the UKI and sd-boot for UEFI Secure Boot and ship the
        guest-side enrollment tooling. Off by default: the reproducible
        base owns no signing key.
      '';
    };
  };
  options.aos.boot.recovery = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = config.aos.boot.secureBoot.enable && config.aos.security.verity.enable;
      defaultText = "aos.boot.secureBoot.enable && aos.security.verity.enable";
      description = ''
        Build paired, signed recovery UKIs with a dedicated initrd. Enabled by
        default for Secure Boot images with authenticated immutable roots.
      '';
    };
    abi = lib.mkOption {
      type = lib.types.enum [1];
      default = 1;
      description = "Recovery interface and artifact compatibility ABI (currently version 1).";
    };
  };
  options.aos.filesystems = {
    espDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/disk/by-partlabel/ESP";
      description = "Stable block-device path for the EFI System Partition.";
    };
  };
  options.aos.boot.initrd.abilityHandoff.enable = lib.mkEnableOption "the authenticated initrd-to-host native deployment handoff";
}
