##! Packages evaluated native transactions and exact immutable inputs for OCI.
{
  lib,
  runArtifact,
  jq,
  common,
  deploymentChecker,
}: {
  pkgs ? null,
  packages ? [],
  packageArtifacts ? lib.packageModules.payloads packages,
  evaluated ? null,
  platform ? null,
  targetPlatform ? null,
  scope ? [],
  operatorModules ? [],
  configuration ? [],
  runtimeConfiguration ? [],
  evaluationInput ? null,
  osRelease ? null,
  runtimeRoots ? [],
  contracts ? [],
  pname ? "aos-oci-deployment-artifact",
  artifactClass ? "container",
  executionStage ? null,
}: let
  aggregate = contracts != [];
  checkedPlatform =
    if aggregate
    then null
    else common.validatePlatform platform;
  preparedInput =
    if aggregate
    then null
    else if evaluationInput != null
    then evaluationInput
    else
      lib.build.evaluationInput {
        inherit lib pkgs packages packageArtifacts scope configuration runtimeConfiguration osRelease;
        system = lib.platform.system;
      };
  nativeEvaluation =
    if aggregate
    then null
    else if evaluated != null
    then evaluated
    else
      lib.evalPackageModules {
        inherit packages packageArtifacts scope osRelease;
        enforceOsRequirements = true;
        operatorModules = operatorModules ++ configuration;
        runtimeModules = runtimeConfiguration;
        evaluationInput = preparedInput;
        evaluationInputs = [lib.packageModuleLibrary preparedInput];
      };
  evaluatedTransaction =
    if aggregate
    then null
    else nativeEvaluation.deployment;
  bundle =
    if aggregate
    then null
    else
      import ../deployment-bundle.nix {
        inherit lib pkgs packages packageArtifacts scope configuration runtimeConfiguration osRelease;
        evaluationInput = preparedInput;
        inherit (evaluatedTransaction) graph system inputs retire;
      };
  transaction =
    if aggregate
    then null
    else bundle.nativeTransaction;
  platformValue = builtins.removeAttrs checkedPlatform (lib.optional ((checkedPlatform.variant or null) == null) "variant");
  platforms =
    if aggregate
    then lib.sort (left: right: builtins.toJSON [left.platform.os left.platform.architecture (left.platform.variant or "")] < builtins.toJSON [right.platform.os right.platform.architecture (right.platform.variant or "")]) (lib.concatMap (contract: contract.platforms) contracts)
    else [
      {
        platform = platformValue;
        inherit transaction;
        packages = {
          inherit (transaction) system artifacts;
          modules = transaction.packages;
        };
        documentation = nativeEvaluation.documentation;
      }
    ];
  envelope = {
    schema = "aos.artifact.deployment/v1";
    inherit artifactClass executionStage platforms;
  };
  # Available output locators must not become references through a compiler's
  # build closure. This document uses only its explicitly selected tools.
  artifact =
    runArtifact "${pname}-1" {
      inherit pname;
      version = "1";
      deploymentInput = builtins.toJSON envelope;
      passAsFile = ["deploymentInput"];
    } ''
      set -eu
      export PATH="${jq}/bin:$PATH"
      mkdir -p "$out"
      ${common.jsonScript}
      cp "$deploymentInputPath" deployment.input.json
      write_compact_json deployment.input.json "$out/deployment.json"
      ${lib.optionalString (!aggregate) ''
        for name in transaction.json packages.json admission.json admission-sha256 module-library registration evaluation.json; do
          cp -P ${bundle}/"$name" "$out/$name"
        done
      ''}
      ${builtins.readFile ./deployment-validation.sh}
      validate_deployment_artifact "$out/deployment.json" \
        ${deploymentChecker}/bin/aos-deployment-check ${jq}/bin/jq
      digest=$(sha256sum "$out/deployment.json")
      size=$(stat -c %s "$out/deployment.json")
      jq -nc --arg digest "sha256:''${digest%% *}" --argjson size "$size" \
        --arg mediaType 'application/vnd.aos.artifact.deployment.v1+json' \
        '{mediaType:$mediaType,digest:$digest,size:$size}' > "$out/descriptor.json"
    '';
  evidence =
    if aggregate
    then {
      catalog = lib.concatMap (contract: contract.evidence.catalog) contracts;
      sourcePaths = lib.uniqueBy builtins.toString (lib.concatMap (contract: contract.evidence.sourcePaths) contracts);
    }
    else
      import ./deployment-evidence.nix {
        inherit lib packages bundle artifact;
      };
in {
  inherit evidence;
  _type = "aos-oci-deployment-artifact";
  inherit artifact checkedPlatform targetPlatform artifactClass executionStage platforms;
  mediaType = "application/vnd.aos.artifact.deployment.v1+json";
  inputContractPaths = map (contract: builtins.toString contract.artifact) contracts;
  retainedDeploymentArtifacts =
    if aggregate
    then lib.concatMap (contract: contract.retainedDeploymentArtifacts) contracts
    else [bundle];
}
