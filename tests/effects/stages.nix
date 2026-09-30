##! Stage isolation and exact authenticated package inputs without system builds.
let
  lib = import ../../lib {system = "x86_64-linux";};
  moduleRoot = builtins.path {
    path = ./package-module;
    name = "stage-module";
  };
  package = {
    pname = "upstream-name";
    catalogName = "fixture";
    version = "1";
    outPath = moduleRoot;
    module = moduleRoot;
  };
  payload = {
    pname = "payload-only";
    version = "1";
    outPath = "/nix/store/00000000000000000000000000000000-payload-only";
  };
  packageModuleLib = import ../../lib/build/package-modules.nix {};
  record = packageModuleLib.recordFor package;
  base = {lib, ...}: {
    imports = [../../lib/effects/module.nix ../../modules/base/activation-stages.nix];
    options.marker = lib.mkOption {type = lib.types.str;};
    aos.activation.stages = {
      host.modules = [{marker = "host";}];
      initrd.modules = [{marker = "initrd";}];
    };
  };
  selectionEvaluation.config = {
    aos.packages.fixture = {
      enable = true;
      bundle = false;
      inherit package;
    };
    aos.boot.initrd.packageRoots = [];
    aos.activation.stages = {
      host.modules = [{marker = "host";}];
      initrd.modules = [{marker = "initrd";}];
    };
    environment.systemPackages = [package payload];
  };
  evaluate = packageModules:
    import ../../lib/build/evaluate-stages.nix {
      inherit lib selectionEvaluation packageModules;
      pkgs = {};
      modules = [base];
      moduleList = [];
      baseLibProbe = {};
      operatorModules = [];
      runtimeModules = [];
      moduleSpecialArgs = {};
      systemName = "fixture";
    };
  result = evaluate [];
  rejected = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
in {
  stageIsolation = assert result.hostAbilityEvaluation.config.marker == "host";
  assert result.initrdAbilityEvaluation.config.marker == "initrd"; true;
  identityScopes = assert result.hostAbilityEvaluation.config.aos.activation.scope == ["fixture" "host"];
  assert result.initrdAbilityEvaluation.config.aos.activation.scope == ["fixture" "initrd"]; true;
  retainsPayloadOnly = assert builtins.elem payload result.hostPackages; true;
  packageDeduplication = assert result.finalPackageModules == [record]; true;
  initrdExcludesHostPackages = assert result.initrdPackageModules == []; true;
  callerIdentity = assert (evaluate [record]).finalPackageModules == [record]; true;
  conflictingCaller = assert rejected (evaluate [(record // {version = "2";})]).finalPackageModules; true;
  conflictingModules = assert rejected (packageModuleLib.canonicalize [record (record // {version = "2";})]); true;
}
