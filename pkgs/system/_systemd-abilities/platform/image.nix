##! Package-owned immutable image planning through the systemd boot stack.
{
  abilitySelection ? null,
  config,
  lib,
  packageArtifactFor,
  ...
}: let
  builderInterface = lib.abilities.interfaces.imageBuilder.interfaces.builder;
  builderArtifact = lib.abilities.packageOutput {};
  packageOutput = package: lib.abilities.packageOutput {inherit package;};
  systemdToolsOutput = lib.abilities.packageOutput {output = "tools";};
  dependencyNames = [
    "bash"
    "binutils"
    "coreutils"
    "cpio"
    "cryptsetup"
    "dosfstools"
    "e2fsprogs"
    "erofs-utils"
    "fakeroot"
    "findutils"
    "gcc-libs"
    "gawk"
    "gptfdisk"
    "grep"
    "jq"
    "kmod"
    "mtools"
    "openssl"
    "qemu"
    "sbsigntools"
    "tar"
    "util-linux"
    "zstd"
    "zfs"
  ];
  dependencyOutputs = builtins.map packageOutput dependencyNames;
  artifactFor = name: packageArtifactFor (packageOutput name);
  systemdPackage = packageArtifactFor builderArtifact;
  systemdTools = packageArtifactFor systemdToolsOutput;
  builderBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "image-builder";
  selected =
    builtins.length builderBindings == 1;
  selectedBinding =
    if selected
    then builtins.head builderBindings
    else null;
  providerReady =
    selected
    && selectedBinding.implementation.value.provide != null;
  selectedRequest =
    if selected
    then selectedBinding.binding.request
    else null;
  selectedBuilderOutput =
    if selected
    then config.aos.abilities.compositionOutputs.${selectedRequest}."selected-builder".value or null
    else null;

  normalArtifactPath = let
    tries = config.aos.boot.bootAttemptLimit;
  in "EFI/Linux/aos-generation-0000000001${lib.optionalString (tries != null) "+${toString tries}"}.efi";

  buildImage = {
    closureInfoFor,
    mkDerivation,
    writeTextFile,
    targetPlatform,
    inputs,
  }: let
    imagePackages = {
      inherit mkDerivation writeTextFile;
      aos-uki = import ./_uki-builder.nix {
        inherit mkDerivation;
        stdenv.binutils = artifactFor "binutils";
        systemd = imagePackages.systemd;
        sbsigntools = imagePackages.sbsigntools;
        openssl = imagePackages.openssl;
      };
      bash = artifactFor "bash";
      binutils = artifactFor "binutils";
      coreutils = artifactFor "coreutils";
      cpio = artifactFor "cpio";
      cryptsetup = artifactFor "cryptsetup";
      dosfstools = artifactFor "dosfstools";
      e2fsprogs = artifactFor "e2fsprogs";
      erofs-utils = artifactFor "erofs-utils";
      fakeroot = artifactFor "fakeroot";
      findutils = artifactFor "findutils";
      gcc-libs = artifactFor "gcc-libs";
      gawk = artifactFor "gawk";
      gptfdisk = artifactFor "gptfdisk";
      grep = artifactFor "grep";
      jq = artifactFor "jq";
      kmod = artifactFor "kmod";
      mtools = artifactFor "mtools";
      openssl = artifactFor "openssl";
      qemu = artifactFor "qemu";
      sbsigntools = artifactFor "sbsigntools";
      systemd = {
        outPath = systemdPackage;
        tools = systemdTools;
      };
      tar = artifactFor "tar";
      util-linux = artifactFor "util-linux";
      zstd = artifactFor "zstd";
    };
    inherit (inputs) kernel managerConfiguration managerRootfsPlan name runtimeClosureAudit;
    rootfsArtifacts = import ./_rootfs.nix {
      pkgs = imagePackages;
      inherit closureInfoFor kernel lib managerConfiguration managerRootfsPlan name;
      system = {inherit config;};
    };
    inherit (rootfsArtifacts) rootfs;
    trustBundle = rootfsArtifacts.activeImageDbCerts;
    rawDiskFilename = "aos-${name}.img.zst";
    rawMetadataFilename = "image-info.json";
    bootArtifacts = import ./_boot-artifacts.nix {
      pkgs = imagePackages;
      inherit kernel lib name rootfs normalArtifactPath targetPlatform;
      system = {inherit config;};
      activeImageDbCerts = trustBundle;
    };
    rawImage = import ./_image-builder.nix {
      pkgs = imagePackages;
      inherit kernel lib bootArtifacts rawDiskFilename rawMetadataFilename rootfs runtimeClosureAudit targetPlatform;
      system = {inherit config;};
      inherit name;
    };
    budgetCheck = import ./_image-budget-check.nix {
      pkgs = imagePackages;
      inherit config lib runtimeClosureAudit;
      image = rawImage;
      metadataFilename = rawMetadataFilename;
      inherit name rootfs;
      uki = "${rawImage.ukiA}/${rawImage.ukiAStoreFilename}";
    };
    installBundle =
      if config.aos.boot.storage.backend == "zfs-zvol"
      then
        import ./install-bundle.nix {
          pkgs = imagePackages;
          inherit config lib bootArtifacts budgetCheck;
          image = rawImage;
          zfs = artifactFor "zfs";
        }
      else null;
  in {
    _type = "aos-image-build-plan";
    inherit budgetCheck installBundle rawDiskFilename rawImage rawMetadataFilename;
    finishConvertedImage = {
      baseImage,
      metadataFilename,
    }:
      import ./_converted-image.nix {
        pkgs = imagePackages;
        inherit baseImage config lib metadataFilename rawImage targetPlatform;
      };
    unsignedAssembly = rawImage.unsignedAssembly;
    initialBootExecutable = rawImage.uki;
    recoveryInitrd = rawImage.recoveryInitrdA;
    recoverySlotManifest = rawImage.recoverySlotManifest;
    recoveryBootExecutableA = rawImage.recoveryUkiA;
    recoveryBootExecutableB = rawImage.recoveryUkiB;
    recoveryBundle = rawImage.recoveryBundle;
  };

  authoredPlatform = {
    _type = "aos-image-builder";
    artifact = selectedBuilderOutput;
    identity = {
      schema = "aos.image.identity/v1";
      builder = {
        name = "systemd-boot";
        artifact = selectedBuilderOutput;
      };
      target = {
        system = lib.system;
        cpu = lib.platform.constraints.cpu;
      };
      release = {
        name = config.aos.system.name;
        version = config.aos.system.version;
        "state-version" = config.aos.system.stateVersion;
        "module-abi" = config.aos.system.moduleAbi;
        "config-input-abi" = config.aos.system.configInputAbi;
      };
      kernel = config.aos.kernel.selected.identity;
      boot."normal-artifact-path" = normalArtifactPath;
    };
    name = "systemd-boot";
    package = systemdPackage;
    inherit normalArtifactPath;
    build = buildImage;
  };
  builderProjectionReady =
    selectedBuilderOutput
    != null
    && selectedBuilderOutput == builderArtifact;
  checkedProviderReady =
    providerReady
    && (
      if builderProjectionReady
      then true
      else throw "selected image builder projection differs from its checked planning output"
    );
in {
  config = {
    aos.abilities.implementations.image-builder = {
      description = "Builds immutable disk images through the package-owned systemd boot stack.";
      interface = builderInterface.alias;
      artifact = builderArtifact;
      artifacts = [systemdToolsOutput] ++ dependencyOutputs;
      methods = [];
      guarantees = [];
      providerModule = {
        artifact = lib.abilities.packageOutput {output = "module";};
        path = "provider/systemd.nix";
      };
    };

    aos.image.platform = lib.mkIf checkedProviderReady authoredPlatform;

    assertions =
      lib.optionals (selected && config.aos.boot.storage.backend == "zfs-zvol") [
        {
          assertion = config.aos.boot.secureBoot.measuredBoot.enable;
          message = "zfs-zvol installation requires measured boot so the native ZFS key can be sealed";
        }
        {
          assertion = builtins.length config.aos.boot.storage.espDevices >= 2;
          message = "zfs-zvol installation requires at least two independently bootable firmware partitions";
        }
        {
          assertion = lib.all (value: value == null) (builtins.attrValues config.aos.boot.storage.devices);
          message = "the zfs-zvol installer does not permit immutable device-path overrides";
        }
        {
          assertion = config.aos.boot.storage.zfs.encryptionRoot == config.aos.boot.storage.zfs.poolName;
          message = "the zfs-zvol installer requires the pool root to be the native-encryption root";
        }
      ]
      ++ lib.optionals selected [
        {
          assertion =
            config.aos.image.budgets.maxFirmwarePartitionMiB
            >= 2 * config.aos.image.budgets.maxBootExecutableMiB + 32;
          message = "the selected systemd firmware partition must hold two maximum-sized boot executables plus 32 MiB of loader and filesystem headroom";
        }
        {
          assertion =
            2
            + config.aos.image.budgets.maxFirmwarePartitionMiB
            + 2 * config.aos.image.rootPartitionMiB
            + (
              if config.aos.security.verity.enable
              then 2 * config.aos.image.budgets.maxVerityMiB
              else 0
            )
            <= 8192;
          message = "the selected systemd disk layout exceeds the 8192 MiB publication safety limit";
        }
      ];
  };
}
