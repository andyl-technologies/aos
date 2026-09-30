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
  declaredPackages =
    builtins.map (selection: selection.package)
    (builtins.attrValues (lib.filterAttrs (_: selection: selection.enable || selection.bundle)
        selectionEvaluation.config.aos.packages));
  hostPackages = selectionEvaluation.config.environment.systemPackages ++ declaredPackages;
  initrdPackages = selectionEvaluation.config.aos.boot.initrd.packageRoots;
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
  hostScope = [systemName "host"];
  initrdScope = [systemName "initrd"];
  hostConfigurationModules = selectionEvaluation.config.aos.activation.stages.host.modules or [];
  initrdConfigurationModules = selectionEvaluation.config.aos.activation.stages.initrd.modules or [];
  evaluate = scope: packages: configurationModules:
    lib.evalModules {
      modules = modules ++ moduleList ++ [baseLibProbe {aos.activation.scope = scope;}] ++ configurationModules;
      inherit pkgs lib operatorModules runtimeModules;
      packageModules = packages;
      specialArgs =
        moduleSpecialArgs
        // {
          inherit hostPackages initrdPackages initrdPackageModules;
          hostPackageModules = finalPackageModules;
        };
    };
  hostAbilityEvaluation = evaluate hostScope finalPackageModules hostConfigurationModules;
  initrdAbilityEvaluation = evaluate initrdScope initrdPackageModules initrdConfigurationModules;
in {
  inherit
    finalPackageModules
    hostPackages
    initrdPackages
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
