##! modules/security/verity.nix — dm-verity root anchoring
##!
##! Anchors the read-only erofs root (carrying the base lib + on-host evaluator
##! closure) to measured boot via dm-verity. The Merkle root hash of the root
##! image is produced at build time (lib/build/rootfs.nix `verity = true`), baked
##! into the UKI `.cmdline` section as `roothash=<hex>` (pkgs/system/_systemd-abilities/platform/_uki-builder.nix),
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
##! the selected package image builder, and the selected boot-artifact tool.
##!
##! systemd assembles `/dev/mapper/root` from the union of:
##!   * the `roothash=<hex>` token on the kernel command line (build-injected),
##!   * `systemd.verity_root_data=` / `systemd.verity_root_hash=` device hints,
##! via `systemd-veritysetup-generator` (confirmed present + unstripped in the
##! initrd: tests/abilities/systemd-verity.nix). `root=` then follows the mapper
##! device through `aos.filesystems.rootDevice`.
##!
##! Options under aos.security.verity:
##!   enable, dataDevice, hashDevice
{
  config,
  packageModulesAvailable ? false,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.security.verity;
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/boot/_aos-boot-storage/policy-options.nix];

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
    # pkgs/system/_systemd-abilities/platform/_uki-builder.nix) with these device hints to assemble
    # `/dev/mapper/root`. NOTE: the dracut-style verity.data=/verity.hash=
    # /verity.roothash= params are wrong for a systemd initrd and are gone.
    aos.boot.kernelParams = [
      # aos-var-crypt is the sole /var unlocker. Disable the initrd's generic
      # LUKS discovery so it cannot race the authenticated storage path.
      "rd.luks=0"
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

    # The package-owned initrd module joins the generated verity activation,
    # republishes the completed mapper event, and reads the complete mapper
    # before persistent state becomes available.
    environment.systemPackages = [pkgs.aos-boot-identity pkgs.aos-verity-root-guard];
    aos.boot.initrd.packageRoots = [pkgs.aos-boot-identity pkgs.aos-verity-root-guard];
  };
}
