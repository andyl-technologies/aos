##! Provider-neutral immutable disk image policy and format assembly.
##!
##! The exact checked image-builder binding produces the raw image plan. This
##! module builds the manager-neutral root filesystem and converts the selected
##! raw artifact into delivery formats without interpreting bootloader layout.
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
  externalFinalization = config.aos.boot.secureBoot.externalFinalization.enable;
  positiveMiB = default: description:
    lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0);
      inherit default description;
    };
  rootfsArtifacts = import ./_rootfs.nix {
    inherit pkgs lib;
    system = {inherit config;};
    name = config.aos.system.name;
  };
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
    testArtifactRoots = cfg.testArtifactRoots;
  };

  platform = cfg.platform;
  plan = cfg.plan;
  rawImage = plan.rawImage;

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
              ${rawImage}/${plan.rawDiskFilename} \
              -o image.raw
            qemu-img convert -f raw -O ${formatFlag} \
              image.raw \
              $out/aos-${config.aos.system.name}.${format}

            filename="$IMAGE_FILENAME"
            byte_size=$(stat -c %s "$out/$filename")
            max_download_mib=$(${pkgs.jq}/bin/jq -er '.artifactBudgetsMiB.download' ${rawImage}/${plan.rawMetadataFilename})
            if [ "$byte_size" -gt $(( max_download_mib * 1048576 )) ]; then
              echo "$IMAGE_FORMAT image exceeds its $max_download_mib MiB download contract" >&2
              exit 1
            fi
            sha256=$(sha256sum "$out/$filename" | cut -d ' ' -f1)
            virtual_size=$(${pkgs.qemu}/bin/qemu-img info --output=json "$out/$filename" \
              | ${pkgs.jq}/bin/jq -er '.["virtual-size"]')
            expected_virtual_size=$(${pkgs.jq}/bin/jq -er '.virtualSizeBytes' ${rawImage}/${plan.rawMetadataFilename})
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
              ${rawImage}/${plan.rawMetadataFilename} > $out/image-info.json

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

  convertedImages = let
    finish = baseImage: plan.finishConvertedImage {inherit baseImage;};
  in {
    qcow2 = finish (convertImage {
      format = "qcow2";
      formatFlag = "qcow2";
      mediaType = "application/vnd.aos.disk-image.qcow2";
      targets = ["qemu-kvm" "openstack"];
    });
    vmdk = finish (convertImage {
      format = "vmdk";
      formatFlag = "vmdk";
      mediaType = "application/x-vmdk";
      targets = ["vmware"];
    });
    vhd = finish (convertImage {
      format = "vhd";
      formatFlag = "vpc";
      mediaType = "application/vnd.aos.disk-image.vhd";
      targets = ["hyper-v"];
    });
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
  imports = [./_platform.nix];

  options.aos.image = {
    ## Whether to build disk images for this system variant.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
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

    extraFirmwareFreeMiB = lib.mkOption {
      type = lib.types.int;
      default = 0;
      internal = true;
      description = ''
        Additional free space reserved in the firmware partition for tests that exercise
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

    testArtifactRoots = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [];
      internal = true;
      description = ''
        Explicit package closures permitted to contain otherwise forbidden
        runtime artifacts in an image with allowTestArtifacts enabled. The
        artifacts remain included in all closure and development-size budgets.
      '';
    };

    budgets = {
      maxRootMiB = positiveMiB 512 "Maximum immutable root payload size.";
      maxVerityMiB = positiveMiB 16 "Maximum dm-verity tree size and capacity of each A/B hash partition.";
      maxInitrdMiB = positiveMiB 128 "Maximum selected early-boot artifact size.";
      maxBootExecutableMiB = positiveMiB 160 "Maximum selected boot executable size.";
      maxFirmwarePartitionMiB = positiveMiB 384 "Firmware partition capacity, including two boot executables and update headroom.";
      maxRuntimeClosureMiB = positiveMiB 768 "Maximum NAR size of the system toplevel runtime closure.";
      maxDevelopmentPayloadMiB = positiveMiB 48 "Maximum headers, static archives, and build metadata retained in the image runtime closure.";
      maxDownloadMiB = positiveMiB 640 "Maximum directly downloadable disk-image object size.";
    };
  };

  options.system.build.image = {
    raw = lib.mkOption {
      type = lib.types.package;
      description = "Selected provider's compressed raw disk image.";
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

  options.system.build.unsignedImageAssembly = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    readOnly = true;
    description = ''
      Deterministic public-only inputs for external production image
      finalization. Final image outputs remain absent until the coordinator
      has completed and independently verified every signing operation.
    '';
  };

  options.system.build.imageArtifacts = lib.mkOption {
    type = lib.types.attrsOf (lib.types.attrsOf lib.types.package);
    description = ''
      Canonical file-valued disk and metadata outputs for each image format.
      Compatibility bundles remain under system.build.image while callers
      migrate to these unambiguous publication inputs.
    '';
  };

  options.system.build.initialBootExecutable = lib.mkOption {
    type = lib.types.package;
    description = "Selected provider's initial immutable boot executable.";
  };

  options.system.build.recoveryBootExecutableA = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = "Selected provider's recovery boot executable for slot A.";
  };

  options.system.build.recoveryBootExecutableB = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = "Selected provider's recovery boot executable for slot B.";
  };

  options.system.build.recoveryBundle = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = "Authenticated fixed-layout payload for removable recovery media.";
  };

  options.system.build.installBundle = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    readOnly = true;
    description = "Selected image builder's guarded bare-metal installation bundle.";
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !cfg.enable || platform != null;
          message = "aos.image.enable requires exactly one checked image-builder binding";
        }
        {
          assertion = cfg.allowTestArtifacts || cfg.testArtifactRoots == [];
          message = "aos.image.testArtifactRoots requires aos.image.allowTestArtifacts = true";
        }
        {
          assertion = cfg.rootPartitionMiB >= cfg.budgets.maxRootMiB;
          message = "aos.image.rootPartitionMiB must be at least aos.image.budgets.maxRootMiB";
        }
        {
          assertion = cfg.extraFirmwareFreeMiB >= 0;
          message = "aos.image.extraFirmwareFreeMiB must not be negative";
        }
      ];
    }
    (lib.mkIf (cfg.enable && platform != null) {
      aos.image.plan = platform.build {
        inherit (pkgs) mkDerivation writeTextFile;
        targetPlatform = {
          system = lib.system;
          cpu = lib.platform.constraints.cpu;
        };
        inputs = {
          name = config.aos.system.name;
          rootfs = rootfsArtifacts.rootfs;
          trustBundle = rootfsArtifacts.activeImageDbCerts;
          inherit runtimeClosureAudit;
        };
      };
      system.build.unsignedImageAssembly =
        if externalFinalization
        then plan.unsignedAssembly
        else null;
      system.build.checks.runtime-closure = runtimeClosureAudit;
      system.build.installBundle = plan.installBundle;
    })
    (lib.mkIf (cfg.enable && platform != null && !externalFinalization) {
      system.build.image = {
        raw = rawImage;
        inherit (convertedImages) qcow2 vmdk vhd;
      };
      system.build.imageArtifacts = {
        raw = artifactFor "raw" rawImage plan.rawDiskFilename;
        qcow2 = artifactFor "qcow2" convertedImages.qcow2 "aos-${config.aos.system.name}.qcow2";
        vmdk = artifactFor "vmdk" convertedImages.vmdk "aos-${config.aos.system.name}.vmdk";
        vhd = artifactFor "vhd" convertedImages.vhd "aos-${config.aos.system.name}.vhd";
      };
      system.build.checks.image-budget = plan.budgetCheck;
      system.build.initialBootExecutable = plan.initialBootExecutable;
      system.build.recoveryInitrd = lib.mkIf config.aos.boot.recovery.enable plan.recoveryInitrd;
      system.build.recoverySlotManifest = lib.mkIf config.aos.boot.recovery.enable plan.recoverySlotManifest;
      system.build.recoveryBootExecutableA = lib.mkIf config.aos.boot.recovery.enable plan.recoveryBootExecutableA;
      system.build.recoveryBootExecutableB = lib.mkIf config.aos.boot.recovery.enable plan.recoveryBootExecutableB;
      system.build.recoveryBundle = lib.mkIf config.aos.boot.recovery.enable plan.recoveryBundle;
    })
  ];
}
