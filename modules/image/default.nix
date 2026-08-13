##! modules/image/default.nix — Disk image format module
##!
##! Provides aos.image options and wires system.build.image.{format} to
##! image builder derivations. The raw GPT image is the base format;
##! all others are converted from it via qemu-img.
##!
##! Supported formats:
##!   raw   — raw GPT disk image (base, bootable via dd or losetup)
##!   qcow2 — QEMU copy-on-write (KVM, OpenStack, Proxmox)
##!   vmdk  — VMware/vSphere
##!   vhd   — Azure/Hyper-V
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.image;
  positiveMiB = default: description:
    lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0);
      inherit default description;
    };
  maxLogicalDiskMiB = 8192;
  verityStorageMiB =
    if config.aos.security.verity.enable
    then 2 * cfg.budgets.maxVerityMiB
    else 0;
  logicalDiskContractMiB =
    2
    + cfg.budgets.maxEspMiB
    + 2 * cfg.budgets.maxRootMiB
    + verityStorageMiB;
  buildImage = import ./_builder.nix;

  rawImage = buildImage {
    inherit pkgs lib;
    system = {inherit config;};
    name = config.aos.system.name;
  };
  imageBudgetCheck = import ./_budget-check.nix {
    inherit config lib pkgs;
    image = rawImage;
    name = config.aos.system.name;
    rootfs = rawImage.rootfs;
    uki = "${rawImage.ukiA}/${rawImage.ukiAStoreFilename}";
  };

  # Convert a raw image to another format via qemu-img and emit a per-format
  # manifest. The manifest retains the canonical boot/partition facts from
  # the raw image while binding the converted bytes and delivery contract.
  convertImage = {
    format,
    formatFlag,
    mediaType,
    targets,
  }:
    pkgs.mkDerivation {
      name = "aos-image-${config.aos.system.name}-${format}";
      src = null;
      buildDeps = [pkgs.qemu pkgs.coreutils pkgs.jq pkgs.zstd];
      IMAGE_FORMAT = format;
      IMAGE_FILENAME = "aos-${config.aos.system.name}.${format}";
      IMAGE_MEDIA_TYPE = mediaType;
      IMAGE_TARGETS_JSON = builtins.toJSON targets;
      phases = [
        {
          name = "convert";
          script = ''
            mkdir -p $out
            zstd -d --no-progress \
              ${rawImage}/aos-${config.aos.system.name}.img.zst \
              -o image.raw
            qemu-img convert -f raw -O ${formatFlag} \
              image.raw \
              $out/aos-${config.aos.system.name}.${format}

            filename="$IMAGE_FILENAME"
            byte_size=$(stat -c %s "$out/$filename")
            max_download_mib=$(${pkgs.jq}/bin/jq -er '.artifactBudgetsMiB.download' ${rawImage}/image-info.json)
            if [ "$byte_size" -gt $(( max_download_mib * 1048576 )) ]; then
              echo "$IMAGE_FORMAT image exceeds its $max_download_mib MiB download contract" >&2
              exit 1
            fi
            sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
            virtual_size=$(${pkgs.qemu}/bin/qemu-img info --output=json "$out/$filename" \
              | ${pkgs.jq}/bin/jq -er '.["virtual-size"]')
            expected_virtual_size=$(${pkgs.jq}/bin/jq -er '.virtualSizeBytes' ${rawImage}/image-info.json)
            if [ "$virtual_size" -ne "$expected_virtual_size" ]; then
              echo "converted image virtual size does not match the raw logical disk" >&2
              exit 1
            fi
            ${pkgs.jq}/bin/jq -S \
              --arg format "$IMAGE_FORMAT" \
              --arg filename "$filename" \
              --arg mediaType "$IMAGE_MEDIA_TYPE" \
              --arg sha256 "$sha256" \
              --arg objectKey "images/sha256/$sha256/$filename" \
              --argjson byteSize "$byte_size" \
              --argjson expectedVirtualSize "$expected_virtual_size" \
              --argjson compatibleTargets "$IMAGE_TARGETS_JSON" \
              '.format = $format
               | .filename = $filename
               | .objectKey = $objectKey
               | .mediaType = $mediaType
               | .compression = "none"
               | .byteSize = $byteSize
               | .sha256 = $sha256
               | .compatibleTargets = $compatibleTargets
               | .virtualSizeBytes = $expectedVirtualSize' \
              ${rawImage}/image-info.json > $out/image-info.json
          '';
        }
      ];
      meta = {
        description = "AOS ${config.aos.system.name} image (${format})";
      };
    };
in {
  options.aos.image = {
    ## Whether to build disk images for this system variant.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to build disk images for this system variant.";
    };

    erofsCompressionLevel = lib.mkOption {
      type = lib.types.int;
      default = 19;
      description = ''
        Zstandard compression level used for EROFS root images. Production
        keeps level 19 for distribution size; VM-test variants may select a
        faster level without changing the filesystem or boot semantics.
      '';
    };

    hostConfigClosures = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      internal = true;
      description = ''
        Package closures retained in the immutable image for authenticated
        host configuration to select at runtime. These packages are not added
        to the generation-zero manifest or the interactive command path.
      '';
    };

    budgets = {
      maxRootMiB = positiveMiB 512 "Maximum immutable root payload size and capacity of each A/B root partition.";
      maxVerityMiB = positiveMiB 16 "Maximum dm-verity tree size and capacity of each A/B hash partition.";
      maxInitrdMiB = positiveMiB 128 "Maximum initrd artifact size before it is embedded in a UKI.";
      maxUkiMiB = positiveMiB 160 "Maximum signed Unified Kernel Image size.";
      maxEspMiB = positiveMiB 384 "EFI System Partition capacity, including two UKIs and update headroom.";
      maxRuntimeClosureMiB = positiveMiB 768 "Maximum NAR size of the system toplevel runtime closure.";
      maxDownloadMiB = positiveMiB 640 "Maximum directly downloadable disk-image object size.";
    };
  };

  options.system.build.image = {
    raw = lib.mkOption {
      type = lib.types.package;
      description = "Zstandard-compressed raw GPT disk image (bootable after decompression).";
    };
    qcow2 = lib.mkOption {
      type = lib.types.package;
      description = "QCOW2 image (QEMU/KVM, OpenStack, Proxmox).";
    };
    vmdk = lib.mkOption {
      type = lib.types.package;
      description = "VMDK image (VMware/vSphere).";
    };
    vhd = lib.mkOption {
      type = lib.types.package;
      description = "VHD image (Azure/Hyper-V).";
    };
  };

  options.system.build.uki = lib.mkOption {
    type = lib.types.package;
    description = ''
      The assembled Unified Kernel Image (`.efi`) written to the image's
      ESP. Secure Boot signed when `aos.boot.secureBoot.enable` is set.
      Exposed so it can be published (`apr publish --image`) and have its
      Secure Boot facts cataloged (RFC-0006 phase 4).
    '';
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.budgets.maxEspMiB >= 2 * cfg.budgets.maxUkiMiB + 32;
        message = "aos.image.budgets.maxEspMiB must hold two maximum-sized UKIs plus 32 MiB of bootloader and FAT headroom";
      }
      {
        assertion = logicalDiskContractMiB <= maxLogicalDiskMiB;
        message = "aos.image storage budgets produce a logical disk larger than the 8192 MiB publication safety limit";
      }
    ];
    system.build.image = {
      raw = rawImage;
      qcow2 = convertImage {
        format = "qcow2";
        formatFlag = "qcow2";
        mediaType = "application/vnd.aos.disk-image.qcow2";
        targets = ["qemu-kvm" "openstack"];
      };
      vmdk = convertImage {
        format = "vmdk";
        formatFlag = "vmdk";
        mediaType = "application/x-vmdk";
        targets = ["vmware"];
      };
      vhd = convertImage {
        format = "vhd";
        formatFlag = "vpc";
        mediaType = "application/vnd.aos.disk-image.vhd";
        targets = ["hyper-v"];
      };
    };
    system.build.checks.image-budget = imageBudgetCheck;
    system.build.uki = rawImage.uki;
  };
}
