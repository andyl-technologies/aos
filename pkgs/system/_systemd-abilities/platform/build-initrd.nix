##! Builds the selected systemd initrd from a bounded generic build context.
{
  config,
  initrdAbilityEvaluation,
  initrdStaticContract,
  lib,
  artifacts,
  systemdArtifact,
}: buildContext: let
  runtimePackages = {
    inherit
      (artifacts)
      bash
      coreutils
      cpio
      cryptsetup
      e2fsprogs
      findutils
      gawk
      gptfdisk
      grep
      iproute2
      jq
      kmod
      less
      util-linux
      zstd
      ;
    systemd = systemdArtifact;
    nix = buildContext.packageSet.nix;
  };
  providerPackage = artifacts.aos-systemd-provider;
  rendererPackages =
    runtimePackages
    // {
      inherit (buildContext) runCommand writeTextFile;
      inherit (artifacts) sed;
    };
  systemdLib = import ./render.nix {
    inherit lib;
    pkgs = rendererPackages;
  };
  plan = config.system.build.systemdInitrdPlan;
  baseUnits = systemdLib.materializeUnits {
    type = "initrd";
    inherit (plan) etc jobScripts;
  };
  renderProviderPlan = import ./render-provider-plan.nix {
    inherit providerPackage;
    runCommand = buildContext.runCommand;
  };
  providerArtifacts = builtins.map renderProviderPlan plan.providerPlans;
  providerArtifactsJson = builtins.toJSON providerArtifacts;
  initrdUnits =
    if providerArtifacts == []
    then baseUnits
    else
      buildContext.runCommand "systemd-initrd-units-with-provider-artifacts" {
        inherit baseUnits providerArtifactsJson;
        passAsFile = ["providerArtifactsJson"];
      } ''
        providerArtifactsPath="$providerArtifactsJsonPath" \
            ${providerPackage}/bin/aos-systemd-provider assemble
      '';
  providerNetworkArtifacts = builtins.map renderProviderPlan plan.providerNetworkPlans;
  initrdNetworkDir =
    if providerNetworkArtifacts == []
    then null
    else if builtins.length providerNetworkArtifacts == 1
    then "${builtins.head providerNetworkArtifacts}/etc/systemd/network"
    else throw "systemd initrd requires at most one selected network-configuration resource";
  selectedArtifactBackend = config.aos.artifacts.backend;
  artifactBackend =
    if
      builtins.isAttrs selectedArtifactBackend
      && (selectedArtifactBackend._type or null) == "aos-package-artifact-backend"
    then selectedArtifactBackend
    else throw "systemd initrd requires one selected package-owned artifact backend";
  staticContractBuild = artifactBackend.buildStaticContract {
    inherit lib;
    inherit (buildContext) targetPlatform;
    inherit (buildContext) ociTools;
    pname = "aos-initrd-static-abilities";
    artifactClass = "bootable";
    executionStage = "initrd";
    packageRoots = config.aos.boot.initrd.packageRoots;
  };
  abilityGraph =
    if initrdAbilityEvaluation == null
    then throw "systemd initrd requires the completed initrd ability fixed point"
    else initrdAbilityEvaluation.config.aos.abilities;
  sourceGraph = lib.abilities.sourceStageFixedPoint abilityGraph;
  sourceSelectors = lib.abilities.collectPackageOutputSelectors sourceGraph;
  sourceArtifactFor = selector: let
    package = buildContext.packageSet.${selector.package}
      or (throw "source-stage selector names unavailable package '${selector.package}'");
  in
    if selector.output == (package.outputName or "out")
    then package
    else package.${selector.output}
      or (throw "source-stage selector names unavailable output '${selector.package}.${selector.output}'");
  sourceArtifactOutputs =
    builtins.map (selector: {
      inherit selector;
      path = builtins.toString (sourceArtifactFor selector);
    })
    sourceSelectors;
  sourceArtifactRoots = lib.uniqueBy builtins.toString (builtins.map sourceArtifactFor sourceSelectors);
  sourceFixedPoint = buildContext.writeTextFile {
    name = "aos-initrd-source-fixed-point";
    destination = "/fixed-point.json";
    text = builtins.toJSON sourceGraph;
  };
  expectedContractIdentity = "${staticContractBuild.artifact}/contract.json";
  checkedStaticContract =
    if initrdStaticContract == null
    then throw "systemd initrd requires its checked static contract"
    else if initrdStaticContract.identity == expectedContractIdentity
    then initrdStaticContract
    else
      throw
      "systemd initrd static contract '${initrdStaticContract.identity}' differs from completed fixed point '${expectedContractIdentity}'";
  specification = buildContext.writeTextFile {
    name = "aos-initrd-source-stage-materialization";
    destination = "/specification.json";
    text = builtins.toJSON {
      schema = "aos.ability.source-stage-materialization/v1";
      stage = "initrd";
      authority = abilityGraph.environment.authority;
      key = abilityGraph.environment.key;
      platform = {
        system = buildContext.targetPlatform.os;
        architecture = buildContext.targetPlatform.cpu;
      };
      staticContract = checkedStaticContract;
      fixedPoint = "${sourceFixedPoint}/fixed-point.json";
      baseLib =
        if buildContext.initrdEvaluationLib == null
        then throw "systemd initrd requires the frozen initrd evaluation library"
        else builtins.toString buildContext.initrdEvaluationLib;
      artifactOutputs = sourceArtifactOutputs;
    };
  };
  sourceStageBundle =
    buildContext.runCommand "aos-initrd-source-stage-bundle" {
      outputChecks = {};
      exportReferencesGraph.sourceStageArtifacts = sourceArtifactRoots;
      dontNukeRefs = true;
    } ''
      export AOS_ABILITY_EVALUATOR_CACHE="$TMPDIR/aos-ability-evaluator"
      # runCommand prepares $out as a directory; consumers install this file.
      ${buildContext.buildTools.packageRuntime}/bin/aos-package-runtime \
        __ability-materialize-source-stage \
        --spec ${specification}/specification.json \
        --exported-graph "$NIX_ATTRS_JSON_FILE" \
        --out "$out/source-stage-bundle.json"
    '';
  handoff = let
    stageConfig = initrdAbilityEvaluation.config;
    parameters = stageConfig.aos.boot.handoffParameters;
    realization = stageConfig.aos.systemd.initrdHandoffRealization;
  in
    if parameters == null || realization == null
    then throw "systemd initrd requires the typed boot handoff plan and its selected realization"
    else {
      value = parameters;
      inherit realization;
      paths = stageConfig.aos.boot.stageInputPaths;
    };
  selectedKernel =
    if config.aos.kernel.selected == null
    then throw "systemd initrd requires the exact selected kernel projection"
    else config.aos.kernel.selected;
  artifact = import ./_initrd-builder.nix {
    inherit lib runtimePackages handoff initrdNetworkDir initrdUnits;
    inherit (buildContext) mkDerivation;
    kernel = selectedKernel;
    kernelModulePackages = config.aos.boot.initrd.modulePackages;
    firmwarePackages = config.aos.boot.initrd.firmwarePackages;
    loadModules = config.aos.boot.initrd.loadModules;
    initrdRuntimeRoots = lib.unique (
      config.aos.boot.initrd.runtimeRoots
      ++ [
        buildContext.packageSet.nix
        buildContext.initrdEvaluationLib
      ]
    );
    initrdEvaluationLib = buildContext.initrdEvaluationLib;
    renderedUnits = plan.renderedUnits;
    initrdStaticContract = checkedStaticContract;
    initrdSourceStageBundle = sourceStageBundle;
    maskedUnits =
      config.boot.initrd.systemd.maskedUnits
      ++ lib.optionals config.aos.security.verity.enable [
        "emergency.target"
        "rescue.target"
      ];
    validateBootIdentity = config.aos.security.verity.enable;
    keepBinutils = config.aos.boot.recovery.enable;
  };
in {
  inherit artifact sourceStageBundle;
  staticAbilityContract = staticContractBuild.artifact;
}
