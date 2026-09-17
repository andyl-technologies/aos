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
    candidates = builtins.filter
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
    grouped = builtins.groupBy
      (package: package.contract.value.package.name)
      candidates;
    conflicting = builtins.filter
      (name:
        builtins.length (lib.unique (builtins.map
            (package: builtins.toJSON package.contract.value)
            grouped.${name}))
        != 1)
      (builtins.attrNames grouped);
  in
    if conflicting != []
    then throw "selected package identities have conflicting authenticated contracts: ${builtins.concatStringsSep ", " conflicting}"
    else builtins.map (name: builtins.head grouped.${name}) (builtins.attrNames grouped);

  hostSelectedAbilityPackages = selectedAbilityPackagesFrom selectionEvaluation.config.environment.systemPackages;
  initrdSelectedAbilityPackages = selectedAbilityPackagesFrom selectionEvaluation.config.aos.boot.initrd.packageRoots;
  allSelectedAbilityPackages = selectedAbilityPackagesFrom (
    hostSelectedAbilityPackages ++ initrdSelectedAbilityPackages
  );
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
  selectedPackageNamesFor = packages:
    builtins.map (package: package.contract.value.package.name) packages;
  withSelectedPackageRecords = selectedPackages: let
    selectedNames = selectedPackageNamesFor selectedPackages;
    unrelatedCallerRecords = builtins.filter
      (record: !(builtins.elem record.name selectedNames))
      callerPackageModules;
  in
    lib.abilities.canonicalizeAuthenticatedModuleRecords (
      unrelatedCallerRecords ++ authenticatedModuleRecordsFor selectedPackages
    );
  finalPackageModules = withSelectedPackageRecords hostSelectedAbilityPackages;
  allPackageModules = withSelectedPackageRecords allSelectedAbilityPackages;
  selectedImplementations = builtins.listToAttrs (builtins.concatMap (package: let
      packageName = package.contract.value.package.name;
    in
      builtins.map (localKey: {
        name = "${packageName}:${localKey}";
        value = {
          inherit package packageName localKey;
          implementation = package.abilities.implementations.${localKey};
        };
      })
      (builtins.attrNames package.abilities.implementations))
    allSelectedAbilityPackages);
  selectedProviderModulesFor = bindings:
    lib.unique (builtins.concatMap (binding: let
        selected =
          selectedImplementations.${binding.implementation}
          or (throw "binding selects implementation '${binding.implementation}' outside the authenticated package set");
        locator = selected.implementation.provider_module or null;
      in
        lib.optional (locator != null) (let
          configRoot = builtins.toString (lib.abilities.authenticatedPackageOutputFor {
            package = selected.package;
            selector = locator.artifact;
          });
          components = lib.splitString "/" locator.path;
        in
          if builtins.any (component: component == "" || component == "." || component == "..") components
          then throw "provider module '${binding.implementation}' has a non-normalized authenticated path"
          else {
            name = selected.packageName;
            version = selected.package.version or "0";
            inherit configRoot;
            module = "${configRoot}/${locator.path}";
            outputs = lib.abilities.authenticatedPackageOutputsFor selected.package;
          }))
      (builtins.attrValues bindings));
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
  }:
    lib.evalModules {
      modules =
        modules
        ++ moduleList
        ++ [baseLibProbe {aos.abilities.environment = environment;}]
        ++ configurationModules;
      inherit pkgs lib operatorModules runtimeModules;
      packageModules = authenticatedPackageModules;
      selectedProviderModules = authenticatedProviderModules;
      enableAbilitySelection = true;
      specialArgs = moduleSpecialArgs;
    };
  forceBindings = bindings: builtins.deepSeq (builtins.attrValues bindings) bindings;
  selectedPackagesForBindings = bindings:
    selectedAbilityPackagesFrom (builtins.map
      (binding:
        (selectedImplementations.${binding.implementation}
          or (throw "binding selects implementation '${binding.implementation}' outside the authenticated package set")).package)
      (builtins.attrValues bindings));
  selectStagePackageModules = {
    environment,
    configurationModules,
    initialPackages,
    round ? 0,
  }: let
    selectedPackages = selectedAbilityPackagesFrom initialPackages;
    selectedModules = lib.abilities.selectAuthenticatedPackageModuleRecords
      selectedPackages
      allPackageModules;
    evaluation = evaluateCompleteConfiguration {
      inherit environment configurationModules;
      authenticatedPackageModules = selectedModules;
    };
    bindings = forceBindings evaluation.config.aos.abilities.bindings;
    nextPackages = selectedAbilityPackagesFrom (
      selectedPackages ++ selectedPackagesForBindings bindings
    );
    selectedNames = selectedPackageNamesFor selectedPackages;
    nextNames = selectedPackageNamesFor nextPackages;
  in
    if selectedNames == nextNames
    then {
      inherit evaluation bindings;
      packageModules = selectedModules;
    }
    else if round >= 15
    then throw "stage package selection did not converge within 16 authenticated provider expansions"
    else
      selectStagePackageModules {
        inherit environment configurationModules;
        initialPackages = nextPackages;
        round = round + 1;
      };
  hostEnvironment = abilityEnvironment "host";
  hostPackageEvaluation = evaluateCompleteConfiguration {
    environment = hostEnvironment;
    authenticatedPackageModules = finalPackageModules;
  };
  hostAbilityBindings = forceBindings hostPackageEvaluation.config.aos.abilities.bindings;
  hostProviderModules = selectedProviderModulesFor hostAbilityBindings;
  # Provider-backed build projections are needed while assembling the base
  # library, before that library can be injected into the final host graph.
  # This checked probe carries the inert base-library locator; the system
  # constructor's final host evaluation remains authoritative.
  uncheckedHostAbilityEvaluation = evaluateCompleteConfiguration {
    environment = hostEnvironment;
    authenticatedPackageModules = finalPackageModules;
    authenticatedProviderModules = hostProviderModules;
  };
  hostAbilityEvaluation = builtins.seq
    (lib.abilities.checkedProviderModuleEvaluation {
      before = hostPackageEvaluation.config.aos.abilities;
      after = uncheckedHostAbilityEvaluation.config.aos.abilities;
    })
    uncheckedHostAbilityEvaluation;
  initrdEnvironment = abilityEnvironment "initrd";
  initrdConfigurationModules = selectionEvaluation.config.aos.abilities.stages.initrd.modules;
  selectionBindings = forceBindings selectionEvaluation.config.aos.abilities.bindings;
  initrdPackageSelection = selectStagePackageModules {
    environment = initrdEnvironment;
    configurationModules = initrdConfigurationModules;
    initialPackages =
      initrdSelectedAbilityPackages
      ++ selectedPackagesForBindings selectionBindings;
  };
  initrdPackageModules = initrdPackageSelection.packageModules;
  initrdPackageEvaluation = initrdPackageSelection.evaluation;
  initrdAbilityBindings = initrdPackageSelection.bindings;
  initrdProviderModules = selectedProviderModulesFor initrdAbilityBindings;
  uncheckedInitrdAbilityEvaluation = evaluateCompleteConfiguration {
    environment = initrdEnvironment;
    authenticatedPackageModules = initrdPackageModules;
    authenticatedProviderModules = initrdProviderModules;
    configurationModules = initrdConfigurationModules;
  };
  providerCheckedInitrdAbilityEvaluation = builtins.seq
    (lib.abilities.checkedProviderModuleEvaluation {
      before = initrdPackageEvaluation.config.aos.abilities;
      after = uncheckedInitrdAbilityEvaluation.config.aos.abilities;
    })
    uncheckedInitrdAbilityEvaluation;
  initrdAbilityEvaluation = let
    abilities = providerCheckedInitrdAbilityEvaluation.config.aos.abilities;
    pending = abilities.compositionPendingRequests;
  in
    if builtins.deepSeq (builtins.attrValues pending) pending != {}
    then throw "complete initrd ability evaluation has unresolved provider requests"
    else builtins.deepSeq (builtins.attrValues abilities.bindings) providerCheckedInitrdAbilityEvaluation;
in {
  inherit
    finalPackageModules
    hostPackageEvaluation
    hostAbilityEvaluation
    hostAbilityBindings
    hostProviderModules
    hostEnvironment
    initrdPackageModules
    initrdProviderModules
    initrdAbilityBindings
    initrdEnvironment
    initrdAbilityEvaluation
    ;

  qualificationProjection = {
    packages = hostSelectedAbilityPackages;
    bindings = hostAbilityBindings;
  };
}
