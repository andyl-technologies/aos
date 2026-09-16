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
    "findutils"
    "gcc-libs"
    "gptfdisk"
    "jq"
    "mtools"
    "openssl"
    "qemu"
    "sbsigntools"
    "tar"
    "util-linux"
    "zstd"
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
    builtins.length builderBindings == 1
    && (builtins.head builderBindings).binding.request == "image:builder";
  selectedBuilderOutput =
    config.aos.abilities.compositionOutputs."image:builder"."selected-builder".value or null;

  normalArtifactPath = let
    tries = config.aos.boot.bootCountingTries;
  in "EFI/Linux/aos-generation-0000000001${lib.optionalString (tries != null) "+${toString tries}"}.efi";

  buildImage = {
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
      findutils = artifactFor "findutils";
      gcc-libs = artifactFor "gcc-libs";
      gptfdisk = artifactFor "gptfdisk";
      jq = artifactFor "jq";
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
    inherit (inputs) name rootfs runtimeClosureAudit trustBundle;
    rawDiskFilename = "aos-${name}.img.zst";
    rawMetadataFilename = "image-info.json";
    bootArtifacts = import ./_boot-artifacts.nix {
      pkgs = imagePackages;
      inherit lib name rootfs normalArtifactPath targetPlatform;
      system = {inherit config;};
      activeImageDbCerts = trustBundle;
    };
    rawImage = import ./_image-builder.nix {
      pkgs = imagePackages;
      inherit lib bootArtifacts rawDiskFilename rootfs runtimeClosureAudit targetPlatform;
      system = {inherit config;};
      inherit name;
    };
    budgetCheck = import ./_image-budget-check.nix {
      pkgs = imagePackages;
      inherit config lib runtimeClosureAudit;
      image = rawImage;
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
          zfs = config.aos.filesystems.zfs.package;
        }
      else null;
  in {
    _type = "aos-image-build-plan";
    inherit budgetCheck installBundle rawDiskFilename rawImage rawMetadataFilename;
    finishConvertedImage = {baseImage}:
      import ./_converted-image.nix {
        pkgs = imagePackages;
        inherit baseImage config lib rawImage targetPlatform;
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
    name = "systemd-boot";
    package = systemdPackage;
    inherit normalArtifactPath;
    build = buildImage;
  };
  platform =
    if
      selectedBuilderOutput != null
      && selectedBuilderOutput._type == "aos-artifact-reference"
      && selectedBuilderOutput.store_path == builtins.toString systemdPackage
    then authoredPlatform
    else throw "selected image builder projection differs from its checked planning output";
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
        artifact = builderArtifact;
        path = "share/aos/providers/systemd.nix";
      };
    };

    aos.image.platform = lib.mkIf selected platform;

    assertions = lib.optionals (selected && config.aos.boot.storage.backend == "zfs-zvol") [
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
    ] ++ lib.optionals selected [
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
