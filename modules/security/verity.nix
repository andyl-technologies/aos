##! modules/security/verity.nix — dm-verity root anchoring
##!
##! Anchors the read-only erofs root (carrying the base lib + on-host evaluator
##! closure) to measured boot via dm-verity. The Merkle root hash of the root
##! image is produced at build time (lib/build/rootfs.nix `verity = true`), baked
##! into the UKI `.cmdline` section as `roothash=<hex>` (pkgs/boot/aos-uki.nix),
##! and thereby measured into PCR 11 and covered by the whole-PE Authenticode
##! signature. Tampering the root either fails dm-verity at read time (boot fails
##! closed) or requires a new root hash → a new `.cmdline` → a new PCR 11 the
##! sealed-/var policy will not bless and the db-signed UKI signature will not
##! cover.
##!
##! This module owns the *eval-side* wiring only (kernel params + initrd module +
##! root device retarget). The build-side hash-tree, the `root-a-hash` GPT
##! partition, and the cmdline `roothash=` append are gated on
##! `aos.security.verity.enable` inside lib/build/rootfs.nix,
##! modules/image/_builder.nix, and pkgs/boot/aos-uki.nix respectively.
##!
##! systemd assembles `/dev/mapper/root` from the union of:
##!   * the `roothash=<hex>` token on the kernel command line (build-injected),
##!   * `systemd.verity_root_data=` / `systemd.verity_root_hash=` device hints,
##! via `systemd-veritysetup-generator` (confirmed present + unstripped in the
##! initrd: lib/testing/systemd-verity.nix). `root=` then follows the mapper
##! device through `aos.filesystems.rootDevice`.
##!
##! Options under aos.security.verity:
##!   enable, dataDevice, hashDevice
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.security.verity;
in {
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
      default = "/dev/disk/by-partlabel/root-a";
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
      default = "/dev/disk/by-partlabel/root-a-hash";
      description = ''
        Block device containing the dm-verity hash tree (Merkle tree). This is
        the `root-a-hash` partition the image builder places immediately after
        `root-a`, sized from the build-time `root-verity-size-bytes`.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aos.filesystems.rootFsType == "erofs";
        message = ''
          aos.security.verity.enable requires aos.filesystems.rootFsType = "erofs".

          dm-verity protects an immutable, build-time-hashed root. A writable
          ext4 root is mutated at runtime (grow-root, journal) and would break
          the Merkle root hash on the first write.
        '';
      }
    ];

    # systemd-veritysetup-generator parameters. The generator unions the
    # `roothash=<hex>` token (baked into the measured .cmdline at build time by
    # pkgs/boot/aos-uki.nix) with these device hints to assemble
    # `/dev/mapper/root`. NOTE: the dracut-style verity.data=/verity.hash=
    # /verity.roothash= params are wrong for a systemd initrd and are gone.
    aos.boot.kernelParams = [
      "systemd.verity=yes"
      "systemd.verity_root_data=${cfg.dataDevice}"
      "systemd.verity_root_hash=${cfg.hashDevice}"
    ];

    # Make root= (modules/base/boot.nix) and the fstab `/` entry
    # (modules/base/filesystems.nix) follow the verity-assembled mapper device.
    # Both read aos.filesystems.rootDevice, so this single override retargets
    # them without mkForce list surgery on kernelParams.
    aos.filesystems.rootDevice = "/dev/mapper/root";

    # dm_verity must be loadable before the root is assembled. Appended to the
    # base initrd module manifest (modules/base/boot.nix contributes the base
    # set with mkBefore so this merges rather than clobbering); since dm_verity
    # is not a hardware-autoloaded NIC, boot.nix's loadModules default also
    # force-loads it via /etc/modules-load.d/initrd.conf.
    aos.boot.initrd.modules = ["dm_verity"];

    # libdevmapper sits below systemd in the bootstrap graph and therefore
    # cannot use libudev synchronization. Ensure coldplug is complete before
    # the generated verity unit creates /dev/mapper/root; otherwise an early
    # add event can leave the device conservatively marked not ready forever.
    boot.initrd.systemd.services."systemd-veritysetup@root" = {
      overrideStrategy = "asDropin";
      requires = ["aos-boot-identity-guard.service"];
      wants = ["systemd-udev-settle.service"];
      after = [
        "aos-boot-identity-guard.service"
        # The first-boot storage transaction must finish its partition-table
        # rescan before verity opens root-a. Holding a partition from the disk
        # while systemd-repart applies the remaining layout can leave the
        # rescan blocked after the on-disk update has completed.
        "aos-repart.service"
        "systemd-udev-settle.service"
      ];
      postStart = ''
        # Without libudev synchronization, the initial mapper event may be
        # observed before activation finishes. A change event after the
        # verity command returns lets 10-dm.rules publish the active device.
        ${pkgs.systemd}/bin/udevadm trigger \
          --action=change \
          --subsystem-match=block \
          --sysname-match='dm-*'
        ${pkgs.systemd}/bin/udevadm settle
      '';
    };

    # dm-verity validates blocks when they are read. Scan the complete mapper
    # before exposing persistent state so corruption in an otherwise authentic
    # counted image cannot release /var before the damaged block is touched.
    boot.initrd.systemd.services."aos-verity-root-verify" = {
      description = "Verify the complete dm-verity root before persistent state";
      requiredBy = ["initrd-fs.target"];
      requires = ["aos-boot-identity-guard.service"];
      after = ["aos-boot-identity-guard.service"];
      before = [
        "aos-var-crypt.service"
        "mount-var.service"
        "initrd-fs.target"
      ];
      unitConfig = {
        DefaultDependencies = "no";
        OnFailure = "aos-boot-identity-failure.target";
        OnFailureJobMode = "isolate";
      };
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        # The identity validator publishes the generated verity unit at
        # runtime. Joining its start here keeps this static service in the
        # original initrd-fs transaction while still waiting for the mapper.
        ${pkgs.systemd}/bin/systemctl start systemd-veritysetup@root.service
        ${pkgs.coreutils}/bin/dd \
          if=/dev/mapper/root \
          of=/dev/null \
          bs=4M \
          iflag=fullblock \
          status=none
        ${pkgs.coreutils}/bin/touch /run/aos/verity-root-valid
      '';
    };
  };
}
