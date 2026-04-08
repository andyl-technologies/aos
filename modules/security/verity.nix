##! modules/security/verity.nix — dm-verity integrity verification module
##!
##! Configures dm-verity for transparent block-level integrity verification
##! of the root filesystem. dm-verity provides tamper-evident protection by
##! computing a Merkle hash tree over the data device and verifying each
##! block on read against the hash device.
##!
##! Options under aos.security.verity:
##!   enable, dataDevice, hashDevice, rootHash
{
  config,
  pkgs,
  lib,
  ...
}:
let
  cfg = config.aos.security.verity;
in
{
  options.aos.security.verity = {
    ## Enable dm-verity for root filesystem integrity verification.
    ##
    ## # See Also
    ## - `aos.security.verity.dataDevice`, `aos.security.verity.rootHash`
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable dm-verity for root filesystem integrity verification. When
        enabled, the kernel verifies each block read from the data device
        against a Merkle hash tree stored on the hash device. Any tampering
        with the root filesystem will be detected and the read will fail.
      '';
    };

    ## Block device containing the read-only root filesystem data.
    dataDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/vda2";
      description = ''
        Block device containing the read-only root filesystem data.
        This is the device that dm-verity will verify on every read.
      '';
    };

    ## Block device containing the dm-verity Merkle hash tree.
    hashDevice = lib.mkOption {
      type = lib.types.str;
      default = "/dev/vda3";
      description = ''
        Block device containing the dm-verity hash tree (Merkle tree).
        This device stores the pre-computed hashes used to verify the
        integrity of the data device. Typically a small dedicated
        partition.
      '';
    };

    ## Root hash of the dm-verity Merkle tree.
    rootHash = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = ''
        Root hash of the dm-verity Merkle tree. This is the single hash
        value at the top of the tree that anchors the chain of trust.
        It must be passed to the kernel at boot time (typically embedded
        in the kernel command line or UKI). An empty string disables
        verity hash verification at boot.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Add dm-verity kernel command line parameters.
    # The kernel's dm-verity target uses these to set up the verified
    # root device before mounting the root filesystem.
    aos.boot.kernelParams = [
      "verity.data=${cfg.dataDevice}"
      "verity.hash=${cfg.hashDevice}"
    ] ++ lib.optional (cfg.rootHash != "") "verity.roothash=${cfg.rootHash}";

    # Include dm-verity kernel module in the initrd so the verified
    # root device can be assembled before the root filesystem is mounted.
    aos.boot.initrd.modules = [
      "virtio_blk"
      "virtio_pci"
      "ext4"
      "overlay"
      "dm_verity"
    ];
  };
}
