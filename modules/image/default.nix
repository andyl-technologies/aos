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
    + 2 * cfg.rootPartitionMiB
    + verityStorageMiB;
  buildImage = import ./_builder.nix;
  runtimeRoots =
    [config.system.build.toplevel config.system.build.kernel]
    ++ cfg.hostConfigClosures;
  runtimeClosureAudit = import ../../lib/build/runtime-closure-audit.nix {
    inherit pkgs lib;
    roots = runtimeRoots;
    name = config.aos.system.name;
    maxClosureMiB = cfg.budgets.maxRuntimeClosureMiB;
    maxDevelopmentPayloadMiB = cfg.budgets.maxDevelopmentPayloadMiB;
    allowTestArtifacts = cfg.allowTestArtifacts;
  };

  rawImage = buildImage {
    inherit pkgs lib runtimeClosureAudit;
    system = {inherit config;};
    name = config.aos.system.name;
  };
  imageBudgetCheck = import ./_budget-check.nix {
    inherit config lib pkgs runtimeClosureAudit;
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
      buildDeps = [pkgs.qemu pkgs.coreutils pkgs.jq pkgs.openssl pkgs.zstd];
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
              --argjson byteSize "$byte_size" \
              --argjson expectedVirtualSize "$expected_virtual_size" \
              --argjson compatibleTargets "$IMAGE_TARGETS_JSON" \
              '.format = $format
               | .filename = $filename
               | .schemaVersion = 2
               | .mediaType = $mediaType
               | .compression = "none"
               | .byteSize = $byteSize
               | .sha256 = $sha256
               | .compatibleTargets = $compatibleTargets
               | .virtualSizeBytes = $expectedVirtualSize' \
              ${rawImage}/image-info.json > $out/image-info.json

            ${lib.optionalString config.aos.boot.recovery.enable ''
              for component in \
                root.img root.verity root.roothash root.roothash.p7s \
                uki-a.efi uki-b.efi \
                recovery-a.efi recovery-b.efi \
                recovery-a.conf recovery-b.conf; do
                cp "${rawImage}/$component" "$out/$component"
              done

              component() {
                id=$1
                path=$2
                size=$(stat -c %s "$out/$path")
                digest=$(sha256sum "$out/$path" | cut -d ' ' -f1)
                ${pkgs.jq}/bin/jq -n \
                  --arg id "$id" --arg path "$path" \
                  --argjson byteSize "$size" --arg sha256 "$digest" \
                  '{id: $id, path: $path, byte_size: $byteSize, sha256: $sha256}'
              }
              components=$(
                {
                  component root-image root.img
                  component root-verity root.verity
                  component root-hash root.roothash
                  component normal-uki-a uki-a.efi
                  component normal-uki-b uki-b.efi
                  component recovery-uki-a recovery-a.efi
                  component recovery-uki-b recovery-b.efi
                  component recovery-entry-a recovery-a.conf
                  component recovery-entry-b recovery-b.conf
                  component image-metadata image-info.json
                } | ${pkgs.jq}/bin/jq -s .
              )
              ${pkgs.jq}/bin/jq -S -n \
                --arg schema aos.recovery-bundle/v1 \
                --arg release ${lib.escapeShellArg config.aos.system.version} \
                --arg architecture ${lib.escapeShellArg lib.platform.constraints.cpu} \
                --arg platform ${lib.escapeShellArg lib.system} \
                --argjson module_abi ${toString config.aos.system.moduleAbi} \
                --argjson recovery_abi ${toString config.aos.boot.recovery.abi} \
                --argjson components "$components" \
                '{schema: $schema, release: $release, architecture: $architecture,
                  platform: $platform, module_abi: $module_abi,
                  recovery_abi: $recovery_abi, components: $components}' \
                > "$out/recovery-bundle.json"
              ${pkgs.openssl}/bin/openssl dgst -sha256 \
                -sign ${config.aos.boot.secureBoot.dbKey} \
                -out "$out/recovery-bundle.json.sig" \
                "$out/recovery-bundle.json"
            ''}
          '';
        }
      ];
      meta = {
        description = "AOS ${config.aos.system.name} image (${format})";
      };
    };

  # Project one immutable file from a compatibility bundle into a canonical
  # file-valued store output. Nix serializes this output as a root regular
  # file, so registry consumers never have to enumerate a directory to find
  # the artifact they authenticated.
  projectFile = {
    name,
    source,
    description,
  }:
    pkgs.mkDerivation {
      inherit name;
      src = null;
      buildDeps = [pkgs.coreutils];
      outputChecks.out = {};
      unsafeDiscardReferences.out = true;
      phases = [
        {
          name = "install";
          script = ''
            rmdir "$out"
            cp --reflink=auto ${source} "$out"
          '';
        }
      ];
      meta = {inherit description;};
    };

  convertedImages = {
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

  artifactFor = format: bundle: filename: {
    disk = projectFile {
      name = "aos-image-${config.aos.system.name}-${format}-disk";
      source = "${bundle}/${filename}";
      description = "AOS ${config.aos.system.name} ${format} disk artifact";
    };
    info = projectFile {
      name = "aos-image-${config.aos.system.name}-${format}-info";
      source = "${bundle}/image-info.json";
      description = "AOS ${config.aos.system.name} ${format} image metadata";
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

    espExtraFreeMiB = lib.mkOption {
      type = lib.types.int;
      default = 0;
      internal = true;
      description = ''
        Additional free space reserved on the ESP for tests that exercise
        temporary boot artifacts outside the production publication
        transaction.
      '';
    };

    rootPartitionMiB = positiveMiB 1024 ''
      Fixed capacity in MiB of each immutable A/B root partition. This is
      independent of budgets.maxRootMiB so devices retain update headroom
      without weakening the root artifact growth gate.
    '';

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

    allowTestArtifacts = lib.mkOption {
      type = lib.types.bool;
      default = false;
      internal = true;
      description = ''
        Whether this explicitly test-only image may retain guest agents and
        development Secure Boot keys in its runtime closure.
      '';
    };

    budgets = {
      maxRootMiB = positiveMiB 512 "Maximum immutable root payload size.";
      maxVerityMiB = positiveMiB 16 "Maximum dm-verity tree size and capacity of each A/B hash partition.";
      maxInitrdMiB = positiveMiB 128 "Maximum initrd artifact size before it is embedded in a UKI.";
      maxUkiMiB = positiveMiB 160 "Maximum signed Unified Kernel Image size.";
      maxEspMiB = positiveMiB 384 "EFI System Partition capacity, including two UKIs and update headroom.";
      maxRuntimeClosureMiB = positiveMiB 768 "Maximum NAR size of the system toplevel runtime closure.";
      maxDevelopmentPayloadMiB = positiveMiB 48 "Maximum headers, static archives, and build metadata retained in the image runtime closure.";
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

  options.system.build.imageArtifacts = lib.mkOption {
    type = lib.types.attrsOf (lib.types.attrsOf lib.types.package);
    description = ''
      Canonical file-valued disk and metadata outputs for each image format.
      Compatibility bundles remain under system.build.image while callers
      migrate to these unambiguous publication inputs.
    '';
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

  options.system.build.recoveryUkiA = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = "Signed, uncounted recovery UKI paired with immutable slot A.";
  };

  options.system.build.recoveryUkiB = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = "Signed, uncounted recovery UKI paired with immutable slot B.";
  };

  options.system.build.recoveryBundle = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = "Authenticated fixed-layout payload for removable recovery media.";
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
      {
        assertion = cfg.rootPartitionMiB >= cfg.budgets.maxRootMiB;
        message = "aos.image.rootPartitionMiB must be at least aos.image.budgets.maxRootMiB";
      }
      {
        assertion = cfg.espExtraFreeMiB >= 0;
        message = "aos.image.espExtraFreeMiB must not be negative";
      }
    ];
    system.build.image = {
      raw = rawImage;
      inherit (convertedImages) qcow2 vmdk vhd;
    };
    system.build.imageArtifacts = {
      raw = artifactFor "raw" rawImage "aos-${config.aos.system.name}.img.zst";
      qcow2 = artifactFor "qcow2" convertedImages.qcow2 "aos-${config.aos.system.name}.qcow2";
      vmdk = artifactFor "vmdk" convertedImages.vmdk "aos-${config.aos.system.name}.vmdk";
      vhd = artifactFor "vhd" convertedImages.vhd "aos-${config.aos.system.name}.vhd";
    };
    system.build.checks.image-budget = imageBudgetCheck;
    system.build.checks.runtime-closure = runtimeClosureAudit;
    system.build.uki = rawImage.uki;
    system.build.recoveryInitrd = lib.mkIf config.aos.boot.recovery.enable rawImage.recoveryInitrdA;
    system.build.recoverySlotManifest = lib.mkIf config.aos.boot.recovery.enable rawImage.recoverySlotManifest;
    system.build.recoveryUkiA = lib.mkIf config.aos.boot.recovery.enable rawImage.recoveryUkiA;
    system.build.recoveryUkiB = lib.mkIf config.aos.boot.recovery.enable rawImage.recoveryUkiB;
    system.build.recoveryBundle = lib.mkIf config.aos.boot.recovery.enable rawImage.recoveryBundle;
  };
}
