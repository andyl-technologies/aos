##! Package-owned production OCI artifact coordinator.
##!
##! Combines independently evaluated x86_64 and aarch64 production container
##! images into one canonical OCI index. A second, equivalent pipeline proves
##! that platform images, the coordinated index, unsigned evidence, and the
##! external-signing input bundle are byte reproducible.
##!
##! A Linux platform deferred by the release contract
##! (`qualification/deferred-platforms.nix`) is omitted from the index: the
##! release ships nothing on it and no container claim could qualify it. The
##! remaining platforms keep the exact-set checks below.
{
  lib,
  pkgs,
  oci,
  name,
  platformBuilds,
  releaseTargets,
  qualificationCheck,
  deferredPlatforms ? [],
}: let
  discard = value:
    builtins.unsafeDiscardStringContext (builtins.toString value);
  uniqueByPath = lib.uniqueBy discard;

  sortedBuilds =
    builtins.sort (
      left: right: left.coordination.aosSystem < right.coordination.aosSystem
    )
    platformBuilds;
  first = builtins.head sortedBuilds;
  sortedTargets = builtins.sort (left: right: left.system < right.system) releaseTargets;
  releaseSystems = map (target: target.system) sortedTargets;
  releasedTargets = builtins.filter (target: !(builtins.elem target.system deferredPlatforms)) sortedTargets;
  expectedSystems = map (target: target.system) releasedTargets;
  expectedArchitectures = map (target: target.architecture) releasedTargets;
  expectedNames = values: lib.concatStringsSep " and " values;
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
    else if !lib.all (system: builtins.elem system releaseSystems) deferredPlatforms
    then throw "container multi-platform coordinator: only caller-selected release systems can be deferred"
    else if expectedSystems == []
    then throw "container multi-platform coordinator: every production system is deferred"
    else if systems != expectedSystems
    then throw "container multi-platform coordinator: builds do not match the caller-selected release targets"
    else if architectures != expectedArchitectures
    then
      throw
      "container multi-platform coordinator: production systems do not map to the expected ${expectedNames expectedArchitectures} platforms"
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
  deploymentArtifact = oci.mkDeploymentArtifact {
    pname = "aos-container-${name}-production-deployment";
    contracts = map (build: build.coordination.deploymentArtifact) sortedBuilds;
  };
  referenceName = "${first.coordination.repository}:${first.coordination.referenceTag}";
  primaryIndex = oci.mkMultiPlatformIndex {
    pname = "aos-container-${name}-production-index";
    images = primaryImages;
    deploymentArtifact = deploymentArtifact;
    inherit referenceName;
    annotations = first.coordination.indexAnnotations;
  };
  # Reversing the equivalent inputs proves the builder's canonical ordering in
  # addition to proving that independently named platform derivations converge.
  repeatIndex = oci.mkMultiPlatformIndex {
    pname = "aos-container-${name}-production-index-repeat";
    images = lib.reverseList repeatImages;
    deploymentArtifact = deploymentArtifact;
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
      deploymentArtifact = deploymentArtifact;
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

  check = qualificationCheck {
    inherit
      lib
      pkgs
      name
      referenceName
      primaryIndex
      repeatIndex
      evidence
      evidenceRepeat
      publicationInputs
      publicationInputsRepeat
      ;
    inherit schedulerSystem;
    platforms =
      map (target: {
        inherit (target) system architecture;
        execution = executionMode target.system;
      })
      releasedTargets;
    platformChecks = map (build: build.qualification.reproducibility) sortedBuilds;
  };
in
  builtins.deepSeq validated {
    ociIndex = primaryIndex;
    inherit evidence publicationInputs check deploymentArtifact;
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
        targetExecution = lib.genAttrs expectedSystems executionMode;
        requiresConfiguredBinfmt = builtins.filter (system: system != schedulerSystem) expectedSystems;
        nativeTargetBuilderRequired = false;
      };
    };
  }
