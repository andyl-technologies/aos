##! Package-owned immutable image planning through the systemd boot stack.
{
  abilitySelection ? null,
  config,
  lib,
  packageArtifactFor,
  pkgs,
  ...
}: let
  builderInterface = lib.abilities.interfaces.imageBuilder.interfaces.builder;
  builderArtifact = lib.abilities.packageOutput {};
  selected =
    config.aos.abilities.environment != null
    && abilitySelection != null
    && abilitySelection.isImplementationSelected "image-builder";
  normalArtifactPath = let
    tries = config.aos.boot.bootCountingTries;
  in "EFI/Linux/aos-generation-0000000001${lib.optionalString (tries != null) "+${toString tries}"}.efi";

  buildPlan = {
    name,
    rootfs,
    runtimeClosureAudit,
    trustBundle,
  }: let
    bootArtifacts = import ./_boot-artifacts.nix {
      inherit pkgs lib name rootfs normalArtifactPath;
      system = {inherit config;};
      activeImageDbCerts = trustBundle;
    };
    rawImage = import ./_image-builder.nix {
      inherit pkgs lib bootArtifacts rootfs runtimeClosureAudit;
      system = {inherit config;};
      inherit name;
    };
    budgetCheck = import ./_image-budget-check.nix {
      inherit config lib pkgs runtimeClosureAudit;
      image = rawImage;
      inherit name rootfs;
      uki = "${rawImage.ukiA}/${rawImage.ukiAStoreFilename}";
    };
    installBundle =
      if config.aos.boot.storage.backend == "zfs-zvol"
      then
        import ./install-bundle.nix {
          inherit config lib pkgs bootArtifacts budgetCheck;
          image = rawImage;
        }
      else null;
  in {
    _type = "aos-image-build-plan";
    inherit budgetCheck installBundle rawImage;
    finishConvertedImage = {baseImage}:
      import ./_converted-image.nix {
        inherit baseImage config lib pkgs rawImage;
      };
    unsignedAssembly = rawImage.unsignedAssembly;
    initialBootExecutable = rawImage.uki;
    recoveryInitrd = rawImage.recoveryInitrdA;
    recoverySlotManifest = rawImage.recoverySlotManifest;
    recoveryBootExecutableA = rawImage.recoveryUkiA;
    recoveryBootExecutableB = rawImage.recoveryUkiB;
    recoveryBundle = rawImage.recoveryBundle;
  };

  platform = {
    _type = "aos-image-builder";
    name = "systemd-boot";
    package = packageArtifactFor builderArtifact;
    inherit normalArtifactPath;
    plan = buildPlan;
  };
in {
  config = {
    aos.abilities = {
      implementations.image-builder = {
        description = "Builds immutable disk images through the package-owned systemd boot stack.";
        interface = builderInterface.alias;
        artifact = builderArtifact;
        methods = [];
        guarantees = [];
      };
      instances = lib.mkIf selected {
        image-builder-provider.implementation = "image-builder";
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
