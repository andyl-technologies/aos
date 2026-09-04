##! lib/containers/multi-platform.nix -- Production container coordinator
##!
##! Combines independently evaluated x86_64 and aarch64 production container
##! images into one canonical OCI index. A second, equivalent pipeline proves
##! that platform images, the coordinated index, unsigned evidence, and the
##! external-signing input bundle are byte reproducible.
{
  lib,
  pkgs,
  oci,
  name,
  platformBuilds,
}: let
  discard = value:
    builtins.unsafeDiscardStringContext (builtins.toString value);
  uniqueByPath = values: let
    step = state: value: let
      path = discard value;
    in
      if builtins.elem path state.seen
      then state
      else {
        seen = state.seen ++ [path];
        result = state.result ++ [value];
      };
  in
    (builtins.foldl' step {
        seen = [];
        result = [];
      }
      values).result;

  sortedBuilds =
    builtins.sort (
      left: right: left.coordination.aosSystem < right.coordination.aosSystem
    )
    platformBuilds;
  first = builtins.head sortedBuilds;
  expectedSystems = ["aarch64-linux" "x86_64-linux"];
  expectedArchitectures = ["arm64" "amd64"];
  schedulerSystem = pkgs.stdenv.buildPlatform.system;
  executionMode = system:
    if schedulerSystem == system
    then "native"
    else "qemu-binfmt";
  systems = map (build: build.coordination.aosSystem) sortedBuilds;
  architectures = map (build: build.coordination.architecture) sortedBuilds;
  sameCoordination = field:
    lib.all
    (build: build.coordination.${field} == first.coordination.${field})
    sortedBuilds;
  validated =
    if !builtins.isList platformBuilds
    then throw "container multi-platform coordinator: platformBuilds must be a list"
    else if systems != expectedSystems
    then
      throw
      "container multi-platform coordinator: exact production systems must be aarch64-linux and x86_64-linux"
    else if architectures != expectedArchitectures
    then
      throw
      "container multi-platform coordinator: production systems do not map to the expected arm64 and amd64 platforms"
    else if !lib.all (build: build.coordination.name == name) sortedBuilds
    then throw "container multi-platform coordinator: container names differ"
    else if
      !lib.all sameCoordination [
        "repository"
        "referenceTag"
        "releaseIdentity"
        "packageName"
        "packageVersion"
        "definitionAttribute"
        "indexAnnotations"
      ]
    then throw "container multi-platform coordinator: platform publication identities differ"
    else true;

  primaryImages = map (build: build.qualification.primaryImage) sortedBuilds;
  repeatImages = map (build: build.qualification.repeatImage) sortedBuilds;
  referenceName = "${first.coordination.repository}:${first.coordination.referenceTag}";
  primaryIndex = oci.mkMultiPlatformIndex {
    pname = "aos-container-${name}-production-index";
    images = primaryImages;
    inherit referenceName;
    annotations = first.coordination.indexAnnotations;
  };
  # Reversing the equivalent inputs proves the builder's canonical ordering in
  # addition to proving that independently named platform derivations converge.
  repeatIndex = oci.mkMultiPlatformIndex {
    pname = "aos-container-${name}-production-index-repeat";
    images = builtins.reverseList repeatImages;
    inherit referenceName;
    annotations = first.coordination.indexAnnotations;
  };

  evidenceInputs = map (build: build.qualification.evidenceInputs) sortedBuilds;
  auditRoots = uniqueByPath (builtins.concatMap (inputs: inputs.auditRoots) evidenceInputs);
  packageCatalog = builtins.concatMap (inputs: inputs.packageCatalog) evidenceInputs;
  candidateSources = uniqueByPath (
    builtins.concatMap (inputs: inputs.candidateSources) evidenceInputs
  );
  primaryClosureLayers =
    builtins.concatMap (
      inputs: inputs.primaryClosureLayers
    )
    evidenceInputs;
  repeatClosureLayers =
    builtins.concatMap (
      inputs: inputs.repeatClosureLayers
    )
    evidenceInputs;

  mkEvidenceGraphs = suffix: let
    suffixPart =
      if suffix == ""
      then ""
      else "-${suffix}";
    referenceGraph = oci.mkReferenceGraph {
      pname = "aos-container-${name}-production-reference-graph${suffixPart}";
      rootPaths = auditRoots;
    };
    sourceGraph = oci.mkEvidenceSourceGraph {
      pname = "aos-container-${name}-production-source-graph${suffixPart}";
      inherit referenceGraph packageCatalog candidateSources;
    };
  in {
    inherit referenceGraph sourceGraph;
  };
  primaryGraphs = mkEvidenceGraphs "";
  repeatGraphs = mkEvidenceGraphs "repeat";

  mkEvidence = {
    pname,
    graphs,
    closureLayers,
  }:
    oci.mkEvidenceLayout {
      inherit pname closureLayers packageCatalog;
      # Both evidence builds bind the exact publishable subject. The repeat
      # graph independently rebuilds every evidence input around those stable
      # subject bytes instead of claiming a different release identity.
      image = primaryIndex;
      inherit (graphs) referenceGraph sourceGraph;
      definitionAttribute = first.coordination.definitionAttribute;
      releaseIdentity = first.coordination.releaseIdentity;
      packageName = first.coordination.packageName;
      packageVersion = first.coordination.packageVersion;
      imageName = name;
    };
  evidence = mkEvidence {
    pname = "aos-container-${name}-production-evidence";
    graphs = primaryGraphs;
    closureLayers = primaryClosureLayers;
  };
  evidenceRepeat = mkEvidence {
    pname = "aos-container-${name}-production-evidence-repeat";
    graphs = repeatGraphs;
    closureLayers = repeatClosureLayers;
  };

  publicationInputs = import ./publication-inputs.nix {
    inherit pkgs;
    pname = "aos-container-${name}-publication-inputs";
    index = primaryIndex;
    evidenceLayout = evidence;
  };
  publicationInputsRepeat = import ./publication-inputs.nix {
    inherit pkgs;
    pname = "aos-container-${name}-publication-inputs-repeat";
    index = repeatIndex;
    evidenceLayout = evidenceRepeat;
  };

  check = import ../../tests/containers/production-multi-platform.nix {
    inherit
      lib
      pkgs
      name
      primaryIndex
      repeatIndex
      evidence
      evidenceRepeat
      publicationInputs
      publicationInputsRepeat
      ;
    inherit schedulerSystem;
    armExecution = executionMode "aarch64-linux";
    amdExecution = executionMode "x86_64-linux";
    platformChecks = map (build: build.qualification.reproducibility) sortedBuilds;
  };
in
  builtins.deepSeq validated {
    ociIndex = primaryIndex;
    inherit evidence publicationInputs check;
    qualification = {
      inherit
        primaryIndex
        repeatIndex
        evidence
        evidenceRepeat
        publicationInputs
        publicationInputsRepeat
        check
        ;
    };
    coordination = {
      inherit systems architectures referenceName;
      annotations = first.coordination.indexAnnotations;
      execution = {
        inherit schedulerSystem;
        targetSystems = expectedSystems;
        targetExecution = {
          "aarch64-linux" = executionMode "aarch64-linux";
          "x86_64-linux" = executionMode "x86_64-linux";
        };
        requiresConfiguredBinfmt = builtins.filter (system: system != schedulerSystem) expectedSystems;
        nativeTargetBuilderRequired = false;
      };
    };
  }
