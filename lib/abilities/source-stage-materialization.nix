##! Builds a source-stage bundle from one completed ability fixed point.
{
  lib,
  stage,
  abilityGraph,
  staticContract,
  baseLib,
  targetPlatform,
  selectedOutputArtifacts,
  packageSet,
  packageRuntime,
  retainedPackageContractArtifacts,
  runCommand,
  writeTextFile,
  sourceStageFixedPoint,
  collectPackageOutputSelectors,
}: let
  sourceGraph = sourceStageFixedPoint abilityGraph;
  selectors = collectPackageOutputSelectors sourceGraph;
  unselectedArtifactFor = selector: let
    package = packageSet.${selector.package}
      or (throw "${stage} source-stage selector names unavailable package '${selector.package}'");
  in
    if selector.output == (package.outputName or "out")
    then package
    else package.${selector.output}
      or (throw "${stage} source-stage selector names unavailable output '${selector.package}.${selector.output}'");
  artifactFor = selector: let
    selected =
      builtins.filter (
        output:
          output.package
          == selector.package
          && output.output == selector.output
      )
      selectedOutputArtifacts;
    selectedPackage = builtins.any (output: output.package == selector.package) selectedOutputArtifacts;
  in
    if builtins.length selected == 1
    then (builtins.head selected).artifact
    else if builtins.length selected != 0 || selectedPackage
    then throw "${stage} source-stage selector '${selector.package}.${selector.output}' must resolve to one selected static-contract output"
    # The fixed point may also name an image-built tool that is not a provider
    # package. Its exact artifact is inventoried in the source bundle.
    else unselectedArtifactFor selector;
  artifactOutputs =
    builtins.map (selector: {
      inherit selector;
      path = builtins.toString (artifactFor selector);
    })
    selectors;
  artifactRoots = lib.uniqueBy builtins.toString (builtins.map artifactFor selectors);
  fixedPoint = writeTextFile {
    name = "aos-${stage}-source-fixed-point";
    destination = "/fixed-point.json";
    text = builtins.toJSON sourceGraph;
  };
  specification = writeTextFile {
    name = "aos-${stage}-source-stage-materialization";
    destination = "/specification.json";
    text = builtins.toJSON {
      schema = "aos.ability.source-stage-materialization/v1";
      inherit stage;
      inherit (abilityGraph.environment) authority key;
      platform = {
        system = targetPlatform.os;
        architecture = targetPlatform.cpu;
      };
      inherit staticContract;
      fixedPoint = "${fixedPoint}/fixed-point.json";
      baseLib = builtins.toString baseLib;
      inherit artifactOutputs;
    };
  };
  bundle =
    runCommand "aos-${stage}-source-stage-bundle" {
      # Contract companions are read for validation, but the result records
      # their identities without retaining their build-time derivation closures.
      buildDeps = retainedPackageContractArtifacts;
      outputChecks = {};
      exportReferencesGraph.sourceStageArtifacts = artifactRoots;
      unsafeDiscardReferences.out = true;
      dontNukeRefs = true;
    } ''
      export AOS_ABILITY_EVALUATOR_CACHE="$TMPDIR/aos-ability-evaluator"
      ${packageRuntime}/bin/aos-package-runtime \
        __ability-materialize-source-stage \
        --spec ${specification}/specification.json \
        --exported-graph "$NIX_ATTRS_JSON_FILE" \
        --out "$out/source-stage-bundle.json"
    '';
in
  assert abilityGraph.environment.stage == stage;
  assert staticContract != null;
  assert baseLib != null; {
    inherit bundle fixedPoint specification artifactRoots;
  }
