##! Immutable native deployment bundles retained by host and initrd images.
{
  config,
  pkgs,
  lib,
  hostPackages ? [],
  hostPackageArtifacts ? lib.packageModules.payloads hostPackages,
  hostConfigurationSources ? [],
  initrdPackages ? [],
  initrdPackageArtifacts ? lib.packageModules.payloads initrdPackages,
  initrdConfigurationSources ? [],
  initrdAbilityEvaluation ? null,
  evaluationInput ? null,
  initrdEvaluationInput ? null,
  provenance,
  ...
}: let
  buildBundle = import ../../pkgs/containers/_aos-oci-backend/deployment-bundle.nix;
  system = pkgs.stdenv.hostPlatform.system;
  osRelease = {inherit (config.aos.system) name version;};
  bootstrapInputs =
    [config.system.build.bootArtifactContract]
    ++ lib.optional ((config.system.build.bootMetadataBinding or null) != null) config.system.build.bootMetadataBinding;
  hostBundle = buildBundle {
    inherit lib pkgs system osRelease;
    packages = hostPackages;
    packageArtifacts = hostPackageArtifacts;
    withProfileRecords = true;
    inherit evaluationInput;
    configuration = hostConfigurationSources;
    inputs = bootstrapInputs;
    graph = provenance.withoutAnnotations config.aos.activation.graph;
    retire = config.aos.activation.retire;
    scope = config.aos.activation.scope;
  };
  initrdBundle =
    if initrdAbilityEvaluation == null
    then throw "the initrd deployment requires its completed native module evaluation"
    else
      buildBundle {
        inherit lib pkgs system osRelease;
        packages = initrdPackages;
        packageArtifacts = initrdPackageArtifacts;
        evaluationInput = initrdEvaluationInput;
        configuration = initrdConfigurationSources;
        inputs = [config.system.build.bootArtifactContract];
        graph = initrdAbilityEvaluation._withoutProvenance initrdAbilityEvaluation.config.aos.activation.graph;
        retire = initrdAbilityEvaluation.config.aos.activation.retire;
        scope = initrdAbilityEvaluation.config.aos.activation.scope;
      };
in {
  options = {
    system.build.hostDeploymentBundle = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      description = "Host transaction, resolved packages, module library, and image-authenticated admission receipt.";
    };

    system.build.initrdDeploymentBundle = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      description = "Initrd transaction and exact retained native deployment inputs.";
    };
  };

  config.system.build = {
    hostDeploymentBundle = hostBundle;
    initrdDeploymentBundle = initrdBundle;
  };
}
