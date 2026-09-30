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
  hostScope = ["profile" "system"];
  initrdScope = [systemName "initrd"];
  buildStage = stage: packages: scope: let
    authored = selectionEvaluation.config.aos.activation.stages.${stage}.configuration or [];
    builders = selectionEvaluation.config.aos.activation.stages.${stage}.configurationBuilders or [];
  in
    builtins.foldl' (prior: build: let
      additions = build {
        inherit scope;
        inherit (prior) packages configuration supplementalInputs;
      };
    in {
      packages = prior.packages ++ additions.packages;
      configuration = prior.configuration ++ additions.configuration;
      supplementalInputs = prior.supplementalInputs ++ (additions.supplementalInputs or []);
    }) {
      inherit packages;
      configuration = authored;
      supplementalInputs = selectionEvaluation.config.aos.activation.stages.${stage}.supplementalInputs or [];
    }
    builders;
  hostStage = buildStage "host" initialHostPackages hostScope;
  initrdStage = buildStage "initrd" initialInitrdPackages initrdScope;
  hostPackages = hostStage.packages;
  initrdPackages = initrdStage.packages;
  hostConfigurationSources = hostStage.configuration;
  initrdConfigurationSources = initrdStage.configuration;
  hostStageSpecialArgs = stageSpecialArgsFor {
    packages = hostPackages;
    scope = hostScope;
    configuration = hostConfigurationSources;
    inherit (hostStage) supplementalInputs;
    runtimeConfiguration = runtimeModules;
  };
  initrdStageSpecialArgs = stageSpecialArgsFor {
    packages = initrdPackages;
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
          inherit hostPackages initrdPackages initrdPackageModules hostConfigurationSources initrdConfigurationSources;
          hostPackageModules = finalPackageModules;
        };
    };
  hostAbilityEvaluation = evaluate hostScope finalPackageModules hostConfigurationSources hostStageSpecialArgs;
  # Initrd admits its native scope directly. Importing the complete image
  # module list here would also import host-only effects and package selectors.
  initrdAbilityEvaluation = lib.evalPackageModules {
    packages = initrdPackages;
    packageModules = initrdPackageModules;
    scope = initrdScope;
    operatorModules = initrdConfigurationSources;
    evaluationInput = initrdStageSpecialArgs.evaluationInput or null;
  };
in {
  inherit
    finalPackageModules
    hostPackages
    hostStageSpecialArgs
    initrdStageSpecialArgs
    initrdPackages
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
