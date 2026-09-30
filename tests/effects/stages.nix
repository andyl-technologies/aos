##! Stage isolation and exact authenticated package inputs without system builds.
let
  lib = import ../../lib {system = "x86_64-linux";};
  fixturePayload = import ./_fixture-payload.nix;
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
    outPath = fixturePayload "payload-only";
  };
  packageModuleLib = import ../../lib/build/package-modules.nix {};
  record = packageModuleLib.recordFor package;
  base = {lib, ...}: {
    imports = [../../lib/effects/module.nix ../../modules/base/activation-stages.nix];
    options.marker = lib.mkOption {type = lib.types.str;};
    options.hostOnly = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    aos.activation.stages = {
      host.modules = [{marker = "host";}];
      initrd.modules = [
        {
          options.marker = lib.mkOption {type = lib.types.str;};
          marker = "initrd";
        }
      ];
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
      initrd.modules = [
        {
          options.marker = lib.mkOption {type = lib.types.str;};
          marker = "initrd";
        }
      ];
    };
    environment.systemPackages = [package payload];
  };
  evaluateSelection = selected: packageModules:
    import ../../lib/build/evaluate-stages.nix {
      inherit lib packageModules;
      selectionEvaluation = selected;
      pkgs = {};
      modules = [base];
      moduleList = [];
      operatorModules = [];
      runtimeModules = [];
      moduleSpecialArgs = {};
      systemName = "fixture";
    };
  evaluate = evaluateSelection selectionEvaluation;
  result = evaluate [];
  builtStage = evaluateSelection {
    config =
      selectionEvaluation.config
      // {
        aos =
          selectionEvaluation.config.aos
          // {
            activation.stages = {
              host = {
                modules = [{marker = "host";}];
                configurationBuilders = [
                  (_: {
                    packages = [payload];
                    configuration = [];
                  })
                  (prior:
                    assert builtins.elem payload prior.packages; {
                      packages = [];
                      configuration = [];
                    })
                ];
              };
              initrd.modules = [
                {
                  options.marker = lib.mkOption {type = lib.types.str;};
                  marker = "initrd";
                }
              ];
            };
          };
        environment.systemPackages = [package];
      };
  } [];
  rejected = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
in {
  stageIsolation = assert result.hostAbilityEvaluation.config.marker == "host";
  assert result.initrdAbilityEvaluation.config.marker == "initrd"; true;
  identityScopes = assert result.hostAbilityEvaluation.config.aos.activation.scope == ["profile" "system"];
  assert result.initrdAbilityEvaluation.config.aos.activation.scope == ["fixture" "initrd"]; true;
  retainsPayloadOnly = assert builtins.elem payload result.hostPackages; true;
  builderRetainsNativeArtifact = assert builtins.elem payload builtStage.hostPackages;
  assert builtStage.finalPackageModules == [record]; true;
  packageDeduplication = assert result.finalPackageModules == [record]; true;
  initrdExcludesHostPackages = assert result.initrdPackageModules == []; true;
  initrdExcludesHostModuleDeclarations = assert !(result.initrdAbilityEvaluation.options ? hostOnly); true;
  callerIdentity = assert (evaluate [record]).finalPackageModules == [record]; true;
  conflictingCaller = assert rejected (evaluate [(record // {version = "2";})]).finalPackageModules; true;
  conflictingModules = assert rejected (packageModuleLib.canonicalize [record (record // {version = "2";})]); true;
}
