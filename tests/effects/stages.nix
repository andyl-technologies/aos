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
  hostSource = builtins.path {
    path = ./stage-host.nix;
    name = "host-stage-policy.nix";
  };
  initrdSource = builtins.path {
    path = ./stage-initrd.nix;
    name = "initrd-stage-policy.nix";
  };
  custodySource = builtins.toFile "stage-custody.nix" ''
    throw "Supplemental inputs must never be imported."
  '';
  stageConfiguration = {
    host.configuration = [hostSource];
    host.supplementalInputs = [custodySource];
    initrd.configuration = [initrdSource];
  };
  base = {lib, ...}: {
    imports = [../../lib/effects/module.nix ../../modules/base/activation-stages.nix];
    options.marker = lib.mkOption {type = lib.types.str;};
    options.hostOnly = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    aos.activation.stages = stageConfiguration;
  };
  selectionEvaluation.config = {
    aos.packages.fixture = {
      enable = true;
      bundle = false;
      inherit package;
    };
    aos.boot.initrd.packageRoots = [];
    aos.activation.stages = stageConfiguration;
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
      stageSpecialArgsFor = stage: {
        retainedStageInputs = stage.supplementalInputs;
        selectedStageArtifacts = stage.packageArtifacts;
      };
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
                configuration = [hostSource];
                configurationBuilders = [
                  (_: {
                    packages = [payload];
                    configuration = [];
                    supplementalInputs = [custodySource];
                  })
                  (prior:
                    assert builtins.elem payload prior.packages;
                    assert prior.supplementalInputs == [custodySource]; {
                      packages = [];
                      configuration = [];
                    })
                ];
              };
              initrd.configuration = [initrdSource];
            };
          };
        environment.systemPackages = [package];
      };
  } [];
  enabledOnly = evaluateSelection {
    config = selectionEvaluation.config // {environment.systemPackages = [];};
  } [];
  sourceOnlyBuilder = evaluateSelection {
    config =
      selectionEvaluation.config
      // {
        environment.systemPackages = [];
        aos =
          selectionEvaluation.config.aos
          // {
            packages = {};
            activation.stages =
              stageConfiguration
              // {
                host =
                  stageConfiguration.host
                  // {
                    configurationBuilders = [
                      (prior:
                        assert prior.packages == [];
                        assert prior.packageArtifacts == []; {
                          packages = [package];
                          packageArtifacts = [];
                          configuration = [];
                        })
                    ];
                  };
              };
          };
      };
  } [];
  rejected = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
in {
  enabledOnlyRetainsSources = assert enabledOnly.hostPackages == [package];
  assert enabledOnly.finalPackageModules == [record];
  assert enabledOnly.hostPackageArtifacts == [];
  assert enabledOnly.hostStageSpecialArgs.selectedStageArtifacts == []; true;
  builderCanAdmitSourcesOnly = assert sourceOnlyBuilder.hostPackages == [package];
  assert sourceOnlyBuilder.finalPackageModules == [record];
  assert sourceOnlyBuilder.hostPackageArtifacts == [];
  assert sourceOnlyBuilder.hostStageSpecialArgs.selectedStageArtifacts == []; true;
  explicitPayloadSelection = assert builtins.length result.hostPackageArtifacts == 2;
  assert result.initrdPackageArtifacts == []; true;
  stageIsolation = assert result.hostAbilityEvaluation.config.marker == "host";
  assert result.initrdAbilityEvaluation.config.marker == "initrd"; true;
  supplementalInputsAreNotImported = assert result.hostStageSpecialArgs.retainedStageInputs == [custodySource];
  assert result.hostAbilityEvaluation.config.marker == "host";
  assert result.initrdStageSpecialArgs.retainedStageInputs == []; true;
  supplementalBuilderInputs = assert builtStage.hostStageSpecialArgs.retainedStageInputs == [custodySource]; true;
  retainedStageSources = assert result.hostConfigurationSources == [hostSource];
  assert result.initrdConfigurationSources == [initrdSource]; true;
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
