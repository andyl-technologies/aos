##! Keeps direct-kernel image and native boot verification policy consistent.
{
  lib,
  pkgs,
}: let
  machineModule = import ../../pkgs/system/_systemd-abilities/testing/fleet-module.nix {
    inherit lib;
    packages = {inherit (pkgs) bash coreutils systemd;};
  };
  machine = bootMode:
    (machineModule {
      inherit bootMode;
      varProvisioning = "baked";
      varSizeMiB = 2048;
      bakeAgentUnit = false;
      debugMac = "52:54:00:12:34:57";
      mac = "52:54:00:12:34:56";
      ip = "192.0.2.5";
      defaultAgentPackage = pkgs.aos-test-agent;
      inherit (pkgs) writeTextFile;
    }) {config.aos.packages = {};};
  evaluate = stage: bootMode: authored:
    (lib.evalPackageModules {
      packages = [pkgs.aos-host-policy pkgs.systemd pkgs.aos-boot-preparations pkgs.aos-boot-identity pkgs.aos-boot-storage pkgs.aos-storage-provisioning-provider];
      scope = ["test" "fleet-policy" stage];
      operatorModules =
        [../../pkgs/system/_aos-host-policy/baseline/boot-policy.nix {aos.boot.stage = stage;}]
        ++ (machine bootMode).aos.activation.stages.${stage}.configuration
        ++ authored;
    }).config;
  kernelInitrd = evaluate "initrd" "kernel" [];
  kernelHost = evaluate "host" "kernel" [];
  imageInitrd = evaluate "initrd" "image" [];
  imageHost = evaluate "host" "image" [];
  unsignedImage = evaluate "initrd" "image" [{aos.security.verity.enable = false;}];
  absentSchema = lib.evalModules {
    modules = [
      ../../pkgs/system/_systemd-abilities/testing/fleet-kernel-policy.nix
      {_module.strict = true;}
    ];
  };
  guard = "aos-boot-identity-guard.service";
  hostStoreSeed = config: config.aos.services."boot-preparations.aos-host-store-seed";
  hostReceiver = kernelHost.aos.services."boot-preparations.aos-ability-host-receiver";
  mountVar = config: config.aos.services."boot-preparations.mount-var";
in {
  hostDatabaseBootstrapPrecedesReceiver =
    (hostStoreSeed kernelHost).enable
    && (hostStoreSeed kernelHost).activationOwner == "image"
    && builtins.elem "local-fs.target" (hostStoreSeed kernelHost).dependencies.after
    && builtins.elem "local-fs.target" (hostStoreSeed kernelHost).dependencies.requires
    && builtins.elem "aos-ability-host-receiver.service" (hostStoreSeed kernelHost).dependencies.before;
  hostReceiverRequiresDatabaseBootstrap =
    builtins.elem "aos-host-store-seed.service" hostReceiver.dependencies.requires
    && builtins.elem "aos-host-store-seed.service" hostReceiver.dependencies.after;
  databaseBootstrapIsHostOnly = !(hostStoreSeed kernelInitrd).enable;
  databaseBootstrapRunsPackageOwnedScript = lib.hasSuffix "/bin/aos-host-store-seed" (builtins.head (hostStoreSeed kernelHost).lifecycle.start).executable.path;
  absentVerificationSchemaIsSafe = !(absentSchema.config ? aos);
  directKernelInitrdMatchesImage = !kernelInitrd.aos.security.verity.enable && !kernelInitrd.aos.boot.substrateServices.verityEnabled;
  directKernelHostMatchesImage = !kernelHost.aos.security.verity.enable && !kernelHost.aos.boot.substrateServices.verityEnabled;
  varMountWaitsWithoutDeviceCondition = (mountVar kernelInitrd).conditions == null;
  directKernelGuardDisabled = !kernelInitrd.aos.services."boot-identity.aos-boot-identity-guard".enable;
  directKernelNoMissingGuardRequirement = !(builtins.elem guard (mountVar kernelInitrd).dependencies.requires);
  directKernelNoMissingGuardOrdering = !(builtins.elem guard (mountVar kernelInitrd).dependencies.after);
  imageVerificationRetained = imageInitrd.aos.security.verity.enable && imageHost.aos.security.verity.enable;
  imageGuardEnabled = imageInitrd.aos.services."boot-identity.aos-boot-identity-guard".enable;
  imageGuardRequired = builtins.elem guard (mountVar imageInitrd).dependencies.requires;
  imageGuardOrdered = builtins.elem guard (mountVar imageInitrd).dependencies.after;
  imageAuthoredVerificationPreserved = !unsignedImage.aos.security.verity.enable && !(builtins.elem guard (mountVar unsignedImage).dependencies.requires);
  imageHasNoKernelPolicyImport = (machine "image").imports == [];
  imagePolicyAndRetainedKernelPolicyShareSource = (machine "kernel").imports == [(builtins.head (machine "kernel").aos.activation.stages.initrd.configuration)];
}
