##! Derives authenticated package/provider inputs for complete stage evaluations.
{
  lib,
  pkgs,
  modules,
  moduleList,
  baseLibProbe,
  selectionEvaluation,
  packageModules,
  operatorModules,
  runtimeModules,
  moduleSpecialArgs,
  systemName,
}: let
  selectedAbilityPackagesFrom = packages: let
    candidates =
      builtins.filter
      (package:
        builtins.isAttrs package
        && package ? abilities
        && package ? contract
        && package ? module
        && (
          if package.contract.value.package_module != null
          then true
          else
            throw
            "selected package '${package.pname or package.name or "<unnamed>"}' has no package module locator"
        ))
      packages;
  in
    lib.abilities.canonicalizeAuthenticatedPackages candidates;

  hostSelectedAbilityPackages = selectedAbilityPackagesFrom selectionEvaluation.config.environment.systemPackages;
  initrdSelectedAbilityPackages = selectedAbilityPackagesFrom selectionEvaluation.config.aos.boot.initrd.packageRoots;
  callerPackageModules = lib.abilities.canonicalizeAuthenticatedModuleRecords packageModules;
  authenticatedModuleRecordFor = package: let
    name = package.contract.value.package.name;
    callerRecords = builtins.filter (record: record.name == name) callerPackageModules;
  in
    if callerRecords == []
    then lib.abilities.authenticatedPackageModuleRecordFor package
    else builtins.head (lib.abilities.selectAuthenticatedPackageModuleRecords [package] callerRecords);
  authenticatedModuleRecordsFor = selectedPackages:
    lib.abilities.canonicalizeAuthenticatedModuleRecords (
      builtins.map authenticatedModuleRecordFor selectedPackages
    );
  withSelectedPackageRecords = selectedPackages: let
    selectedNames = builtins.map (package: package.contract.value.package.name) selectedPackages;
    unrelatedCallerRecords =
      builtins.filter
      (record: !(builtins.elem record.name selectedNames))
      callerPackageModules;
  in
    lib.abilities.canonicalizeAuthenticatedModuleRecords (
      unrelatedCallerRecords ++ authenticatedModuleRecordsFor selectedPackages
    );
  abilityEnvironment = stage: {
    authority = "system-image";
    key = systemName;
    inherit stage;
  };
  evaluateCompleteConfiguration = {
    environment,
    authenticatedPackageModules,
    authenticatedProviderModules ? [],
    configurationModules ? [],
    selectionModule ? {
      module = {};
      requests = {};
      requirements = {};
    },
  }:
    lib.evalModules {
      modules =
        modules
        ++ moduleList
        ++ [baseLibProbe {aos.abilities.environment = environment;}]
        ++ configurationModules
        ++ [selectionModule.module];
      inherit pkgs lib operatorModules runtimeModules;
      packageModules = authenticatedPackageModules;
      selectedProviderModules = authenticatedProviderModules;
      enableAbilitySelection = true;
      specialArgs =
        moduleSpecialArgs
        // {
          abilityResolution = {
            requests = selectionModule.requests;
            requirements = selectionModule.requirements;
          };
        };
    };
  forceBindings = bindings: builtins.deepSeq (builtins.attrValues bindings) bindings;
  resolveStage = {
    environment,
    configurationModules,
    initialPackages,
  }: let
    selectedPackages = selectedAbilityPackagesFrom initialPackages;
    resolution = import ./resolve-ability-configuration.nix {
      inherit lib;
      initialPackageModules = withSelectedPackageRecords selectedPackages;
      evaluate = {
        packageModules,
        providerModules,
        selectionModule,
      }:
        evaluateCompleteConfiguration {
          inherit environment configurationModules selectionModule;
          authenticatedPackageModules = packageModules;
          authenticatedProviderModules = providerModules;
        };
      discoverPackageModules = {evaluation, ...}: let
        stagePackages =
          if environment.stage == "host"
          then evaluation.config.environment.systemPackages
          else evaluation.config.aos.boot.initrd.packageRoots;
      in
        authenticatedModuleRecordsFor (selectedAbilityPackagesFrom stagePackages);
    };
    evaluatedStagePackages =
      if environment.stage == "host"
      then resolution.evaluation.config.environment.systemPackages
      else resolution.evaluation.config.aos.boot.initrd.packageRoots;
  in
    resolution // {packages = selectedAbilityPackagesFrom evaluatedStagePackages;};
  hostEnvironment = abilityEnvironment "host";
  hostResolution = resolveStage {
    environment = hostEnvironment;
    configurationModules = [];
    initialPackages = hostSelectedAbilityPackages;
  };
  finalPackageModules = hostResolution.packageModules;
  hostPackageEvaluation = hostResolution.packageEvaluation;
  hostAbilityInstances = hostResolution.selection.instances;
  hostAbilityBindings = hostResolution.bindings;
  hostAbilityRequests = hostResolution.selection.requests;
  hostAbilityRequirements = hostResolution.selection.requirements;
  hostProviderModules = hostResolution.providerModules;
  # Provider-backed build projections are needed while assembling the base
  # library, before that library can be injected into the final host graph.
  # This checked probe carries the inert base-library locator; the system
  # constructor's final host evaluation remains authoritative.
  hostAbilityEvaluation = builtins.seq hostResolution.checked hostResolution.evaluation;
  initrdEnvironment = abilityEnvironment "initrd";
  initrdConfigurationModules = selectionEvaluation.config.aos.abilities.stages.initrd.modules;
  selectionBindings = forceBindings selectionEvaluation.config.aos.abilities.bindings;
  initrdResolution = resolveStage {
    environment = initrdEnvironment;
    configurationModules = initrdConfigurationModules;
    initialPackages =
      initrdSelectedAbilityPackages
      ++ builtins.map
      (binding: let
        packageName = builtins.head (lib.splitString ":" binding.implementation);
      in
        pkgs.${packageName}
        or (throw "explicit binding selects unavailable package '${packageName}'"))
      (builtins.attrValues selectionBindings);
  };
  initrdPackageModules = initrdResolution.packageModules;
  initrdProviderModules = initrdResolution.providerModules;
  initrdAbilityInstances = initrdResolution.selection.instances;
  initrdAbilityBindings = initrdResolution.bindings;
  initrdAbilityRequests = initrdResolution.selection.requests;
  initrdAbilityRequirements = initrdResolution.selection.requirements;
  initrdAbilityEvaluation = builtins.seq initrdResolution.checked initrdResolution.evaluation;
in {
  inherit
    finalPackageModules
    hostPackageEvaluation
    hostAbilityEvaluation
    hostAbilityInstances
    hostAbilityBindings
    hostAbilityRequests
    hostAbilityRequirements
    hostProviderModules
    hostEnvironment
    initrdPackageModules
    initrdProviderModules
    initrdAbilityInstances
    initrdAbilityBindings
    initrdAbilityRequests
    initrdAbilityRequirements
    initrdEnvironment
    initrdAbilityEvaluation
    ;

  qualificationProjection = {
    packages = hostResolution.packages;
    bindings = hostAbilityBindings;
  };
}
