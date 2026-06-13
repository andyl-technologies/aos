# lib/testing/metadata.nix — Per-test metadata ISO (ISO9660, volume
# label aos-metadata).
#
# Produces a small ISO9660 image with one file — config.json — that the
# initrd-side aos-platform-detect.service mounts at /run/aos-metadata and
# reads via IGNITION_CONFIG_FILE. Same developer ergonomics as the old
# ext4 + HTTP channel, zero guest-side daemons, and the transport matches
# what bare-metal operators attach over IPMI virtual media.
#
# Serialisation and `ignition-validate` both live in
# `lib/formats/ignition.nix`, so this derivation only has to package
# an already-validated `config.json` into an ISO image.
#
# Shared by the single-VM Firecracker harness (vm.nix) and the
# multi-VM QEMU harness (fleet.nix). The two harnesses attach the
# resulting ISO differently — Firecracker via virtio-blk read-only,
# QEMU via SCSI CD-ROM — but the image bytes are identical.
{
  pkgs,
  lib,
}: let
  ignitionTestFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = false;
  };

  # Full-profile variant for install-from-image tests: accepts
  # storage.disks / storage.filesystems (partitioning is the point of
  # those tests). Everything else keeps the restrictive default —
  # checks.ignition-format pins both behaviors.
  ignitionFullFormat = lib.formats.ignition {
    inherit lib pkgs;
    allowStorageHardware = true;
  };

  # Validated Ignition config.json as a derivation, selectable profile.
  # Used directly (fw_cfg delivery in fleet.nix image-boot machines)
  # and by mkMetadataIso below (ISO delivery).
  mkIgnitionConfig = {
    name,
    ignitionConfig,
    allowStorageHardware ? false,
  }: let
    format =
      if allowStorageHardware
      then ignitionFullFormat
      else ignitionTestFormat;
  in
    format.generate "config.json" ignitionConfig;

  mkMetadataIso = {
    name,
    ignitionConfig,
    allowStorageHardware ? false,
  }: let
    configDrv = mkIgnitionConfig {
      inherit name ignitionConfig allowStorageHardware;
    };
  in
    pkgs.mkDerivation {
      pname = "vm-metadata-${name}";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.libisoburn # provides xorriso
      ];

      # `configDrv` is a directory (AOS `mkDerivation` convention) —
      # the JSON file sits at `${configDrv}/config.json`.
      CONFIG_JSON = "${configDrv}/config.json";

      phases = [
        {
          name = "build-metadata";
          script = ''
            mkdir staging
            cp "$CONFIG_JSON" staging/config.json

            mkdir -p $out
            # Volume label `aos-metadata` is what blkid picks up via
            # ISO9660's volume descriptor; the guest-side detector
            # gates on /dev/disk/by-label/aos-metadata.
            xorriso -as mkisofs \
              -volid aos-metadata \
              -output $out/metadata.iso \
              -r staging/
          '';
        }
      ];
    };
in {
  inherit mkIgnitionConfig mkMetadataIso;
}
