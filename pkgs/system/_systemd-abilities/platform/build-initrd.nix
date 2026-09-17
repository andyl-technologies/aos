##! Builds the selected systemd initrd from a bounded generic build context.
{
  config,
  initrdAbilityEvaluation,
  initrdStaticContract,
  lib,
  packageArtifactFor,
}: buildContext: let
  packageOutput = package: lib.abilities.packageOutput {inherit package;};
  artifactFor = package: packageArtifactFor (packageOutput package);
  runtimePackages = {
    bash = artifactFor "bash";
    coreutils = artifactFor "coreutils";
    cpio = artifactFor "cpio";
    cryptsetup = artifactFor "cryptsetup";
    e2fsprogs = artifactFor "e2fsprogs";
    findutils = artifactFor "findutils";
    gawk = artifactFor "gawk";
    gptfdisk = artifactFor "gptfdisk";
    grep = artifactFor "grep";
    iproute2 = artifactFor "iproute2";
    jq = artifactFor "jq";
    kmod = artifactFor "kmod";
    less = artifactFor "less";
    systemd = packageArtifactFor (lib.abilities.packageOutput {});
    util-linux = artifactFor "util-linux";
    zstd = artifactFor "zstd";
  };
  providerPackage = artifactFor "aos-systemd-provider";
  rendererPackages =
    runtimePackages
    // {
      inherit (buildContext) runCommand writeTextFile;
      sed = artifactFor "sed";
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
  renderProviderPlan = providerPlan:
    buildContext.runCommand providerPlan.name {
      realization = providerPlan.input;
      passAsFile = ["realization"];
    } ''
      ${providerPackage}/bin/aos-systemd-provider render
    '';
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
  networkFiles = lib.mapAttrs (name: text:
    buildContext.writeTextFile {
      name = "systemd-initrd-network-${name}";
      destination = "/${name}.network";
      inherit text;
    })
  plan.networkFiles;
  initrdNetworkDir = buildContext.runCommand "initrd-systemd-networks" {} (
    ''mkdir -p "$out"''
    + lib.concatStringsSep "\n" (lib.mapAttrsToList (
        name: source: "cp ${source}/${name}.network $out/${name}.network"
      )
      networkFiles)
  );
  selectedArtifactBackend = config.aos.artifacts.backend;
  artifactBackend =
    if
      builtins.isAttrs selectedArtifactBackend
      && (selectedArtifactBackend._type or null) == "aos-package-artifact-backend"
    then selectedArtifactBackend
    else throw "systemd initrd requires one selected package-owned artifact backend";
  mkReferenceGraph = lib.build.referenceGraph {
    inherit (buildContext) mkDerivation;
    inherit (buildContext.buildTools) coreutils jq;
  };
  staticContractBuild = artifactBackend.buildStaticContract {
    inherit lib mkReferenceGraph;
    inherit (buildContext) targetPlatform;
    buildPackages = buildContext.buildTools;
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
    else throw "systemd initrd static contract differs from the completed initrd fixed point";
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
    };
  };
  sourceStageBundle = buildContext.runCommand "aos-initrd-source-stage-bundle.json" {} ''
    ${buildContext.buildTools.packageRuntime}/bin/.aos-package-runtime-unwrapped \
      __ability-materialize-source-stage \
      --spec ${specification}/specification.json \
      --out "$out"
  '';
  handoff =
    if config.aos.boot.preparationHandoff == null
    then throw "systemd initrd requires the exact selected boot preparation handoff"
    else config.aos.boot.preparationHandoff;
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
    initrdRuntimeRoots = config.aos.boot.initrd.runtimeRoots;
    renderedUnits = plan.renderedUnits;
    renderedNetworks = plan.renderedNetworks;
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
