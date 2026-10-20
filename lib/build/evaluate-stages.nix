##! Evaluates each deployment stage with ordinary authenticated package modules.
{
  lib,
  pkgs,
  modules,
  moduleList,
  selectionEvaluation,
  packageModules,
  operatorModules,
  runtimeModules,
  moduleSpecialArgs,
  systemName,
  stageSpecialArgsFor ? (_: {}),
}: let
  packageModuleLib = import ./package-modules.nix {};
  callerModules = packageModuleLib.canonicalize packageModules;
  declaredPackages =
    builtins.map (selection: selection.package)
    (builtins.attrValues (lib.filterAttrs (_: selection: selection.enable || selection.bundle)
        selectionEvaluation.config.aos.packages));
  initialHostPackages = selectionEvaluation.config.environment.systemPackages ++ declaredPackages;
  initialHostArtifacts = packageModuleLib.payloads selectionEvaluation.config.environment.systemPackages;
  initialInitrdPackages = selectionEvaluation.config.aos.boot.initrd.packageRoots;
  recordsFor = packages:
    packageModuleLib.canonicalize (
      builtins.map (record: let
        matching = builtins.filter (candidate: candidate.name == record.name) callerModules;
      in
        if matching == []
        then record
        else if builtins.head matching == record
        then record
        else throw "Caller module differs from selected package '${record.name}'.")
      (packageModuleLib.closure packages)
    );
  hostNames = builtins.map packageModuleLib.nameFor hostPackages;
  finalPackageModules = packageModuleLib.canonicalize (
    recordsFor hostPackages ++ builtins.filter (record: !(builtins.elem record.name hostNames)) callerModules
  );
  initrdPackageModules = recordsFor initrdPackages;
  # Image activation seeds the same profile later changed by package management.
  osRelease = {inherit (selectionEvaluation.config.aos.system) name version;};
  compatibility = import ../packages/release-compatibility.nix {inherit lib;};
  hostScope = ["profile" "system"];
  initrdScope = [systemName "initrd"];
  buildStage = stage: packages: packageArtifacts: scope: let
    authored = selectionEvaluation.config.aos.activation.stages.${stage}.configuration or [];
    builders = selectionEvaluation.config.aos.activation.stages.${stage}.configurationBuilders or [];
  in
    builtins.foldl' (prior: build: let
      additions = build {
        inherit scope;
        inherit (prior) packages packageArtifacts configuration supplementalInputs;
      };
    in {
      packages = prior.packages ++ additions.packages;
      packageArtifacts = lib.packageArtifacts.unique (prior.packageArtifacts ++ (additions.packageArtifacts or (packageModuleLib.payloads additions.packages)));
      configuration = prior.configuration ++ additions.configuration;
      supplementalInputs = prior.supplementalInputs ++ (additions.supplementalInputs or []);
    }) {
      inherit packages packageArtifacts;
      configuration = authored;
      supplementalInputs = selectionEvaluation.config.aos.activation.stages.${stage}.supplementalInputs or [];
    }
    builders;
  hostStage = buildStage "host" initialHostPackages initialHostArtifacts hostScope;
  initrdStage = buildStage "initrd" initialInitrdPackages (packageModuleLib.payloads initialInitrdPackages) initrdScope;
  hostPackages = hostStage.packages;
  initrdPackages = initrdStage.packages;
  hostPackageArtifacts = hostStage.packageArtifacts;
  initrdPackageArtifacts = initrdStage.packageArtifacts;
  hostConfigurationSources = hostStage.configuration;
  initrdConfigurationSources = initrdStage.configuration;
  hostStageSpecialArgs = stageSpecialArgsFor {
    inherit osRelease;
    packages = hostPackages;
    packageArtifacts = hostPackageArtifacts;
    scope = hostScope;
    configuration = hostConfigurationSources;
    inherit (hostStage) supplementalInputs;
    runtimeConfiguration = runtimeModules;
  };
  initrdStageSpecialArgs = stageSpecialArgsFor {
    inherit osRelease;
    packages = initrdPackages;
    packageArtifacts = initrdPackageArtifacts;
    scope = initrdScope;
    configuration = initrdConfigurationSources;
    inherit (initrdStage) supplementalInputs;
    runtimeConfiguration = [];
  };
  evaluate = scope: packages: configurationSources: stageSpecialArgs:
    lib.evalModules {
      modules = modules ++ moduleList ++ [{aos.activation.scope = scope;}];
      inherit pkgs lib runtimeModules;
      operatorModules = operatorModules ++ configurationSources;
      packageModules = packages;
      specialArgs =
        moduleSpecialArgs
        // stageSpecialArgs
        // {
          packageModulesAvailable = true;
          inherit hostPackages hostPackageArtifacts initrdPackages initrdPackageArtifacts initrdPackageModules hostConfigurationSources initrdConfigurationSources;
          hostPackageModules = finalPackageModules;
        };
    };
  hostAbilityEvaluation = assert compatibility.checkOsRequirements (compatibility.osRequirements hostPackages) osRelease; evaluate hostScope finalPackageModules hostConfigurationSources hostStageSpecialArgs;
  # Initrd admits its native scope directly. Importing the complete image
  # module list here would also import host-only effects and package selectors.
  initrdAbilityEvaluation = lib.evalPackageModules {
    inherit osRelease;
    enforceOsRequirements = true;
    packages = initrdPackages;
    packageArtifacts = initrdPackageArtifacts;
    packageModules = initrdPackageModules;
    scope = initrdScope;
    operatorModules = initrdConfigurationSources;
    evaluationInput = initrdStageSpecialArgs.evaluationInput or null;
  };
in {
  inherit
    finalPackageModules
    hostPackages
    hostPackageArtifacts
    hostStageSpecialArgs
    initrdStageSpecialArgs
    initrdPackages
    initrdPackageArtifacts
    initrdPackageModules
    hostScope
    initrdScope
    hostConfigurationSources
    initrdConfigurationSources
    hostAbilityEvaluation
    initrdAbilityEvaluation
    ;
  qualificationProjection = {
    packages = hostPackages;
    operations = hostAbilityEvaluation.config.aos.abilities;
    graph = hostAbilityEvaluation.config.aos.activation.graph;
  };
}
