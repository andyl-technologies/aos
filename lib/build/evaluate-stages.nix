##! Evaluates each deployment stage with ordinary authenticated package modules.
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
  packageModuleLib = import ./package-modules.nix {};
  callerModules = packageModuleLib.canonicalize packageModules;
  selectedPackages = packages:
    builtins.filter (package: builtins.isAttrs package && package ? module) packages;
  declaredPackages =
    builtins.map (selection: selection.package)
    (builtins.attrValues (lib.filterAttrs (_: selection: selection.enable || selection.bundle)
        selectionEvaluation.config.aos.packages));
  hostPackages = selectedPackages (selectionEvaluation.config.environment.systemPackages ++ declaredPackages);
  initrdPackages = selectedPackages selectionEvaluation.config.aos.boot.initrd.packageRoots;
  recordFor = package: let
    matching = builtins.filter (record: record.name == (package.pname or package.name)) callerModules;
  in
    if matching == []
    then packageModuleLib.recordFor package
    else builtins.head (packageModuleLib.select [package] matching);
  recordsFor = packages: packageModuleLib.canonicalize (builtins.map recordFor packages);
  hostNames = builtins.map (package: package.pname or package.name) hostPackages;
  finalPackageModules = packageModuleLib.canonicalize (
    recordsFor hostPackages ++ builtins.filter (record: !(builtins.elem record.name hostNames)) callerModules
  );
  initrdPackageModules = recordsFor initrdPackages;
  hostScope = [systemName "host"];
  initrdScope = [systemName "initrd"];
  hostConfigurationModules = selectionEvaluation.config.aos.activation.stages.host.modules;
  initrdConfigurationModules = selectionEvaluation.config.aos.activation.stages.initrd.modules;
  evaluate = scope: packages: configurationModules:
    lib.evalModules {
      modules = modules ++ moduleList ++ [baseLibProbe {aos.activation.scope = scope;}] ++ configurationModules;
      inherit pkgs lib operatorModules runtimeModules;
      packageModules = packages;
      specialArgs = moduleSpecialArgs;
    };
  hostAbilityEvaluation = evaluate hostScope finalPackageModules hostConfigurationModules;
  initrdAbilityEvaluation = evaluate initrdScope initrdPackageModules initrdConfigurationModules;
in {
  inherit
    finalPackageModules
    initrdPackageModules
    hostScope
    initrdScope
    hostConfigurationModules
    initrdConfigurationModules
    hostAbilityEvaluation
    initrdAbilityEvaluation
    ;
  qualificationProjection = {
    packages = hostPackages;
    graph = hostAbilityEvaluation.config.aos.activation.graph;
  };
}
