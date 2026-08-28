##! lib/build/oci/evidence-layout.nix -- Unsigned container evidence graph
##!
##! Produces deterministic OCI artifact manifests for the realized Nix closure,
##! SPDX SBOM, corresponding-source inventory, license report, and in-toto
##! provenance. Signing is deliberately outside Nix: this builder emits exact
##! signing-input and signing-request bytes but never accepts a private key or
##! claims that an unsigned release is verified.
{
  lib,
  mkDerivation,
  coreutils,
  findutils,
  gzip,
  jq,
  tar,
  common,
}: {
  image,
  referenceGraph,
  sourceGraph,
  closureLayers,
  packageCatalog,
  definitionAttribute,
  releaseIdentity,
  packageName,
  packageVersion,
  imageName,
  pname ? "aos-container-evidence",
}: let
  validateIdentity = context: value:
    if
      builtins.isString value
      && value != ""
      && builtins.stringLength value <= 255
      && builtins.match "[ -~]+" value != null
    then value
    else common.fail "${context} must be non-empty bounded printable ASCII";
  checkedAttribute =
    if
      builtins.isString definitionAttribute
      && builtins.match "[A-Za-z_][A-Za-z0-9_-]*(\\.[A-Za-z_][A-Za-z0-9_-]*)*" definitionAttribute
      != null
    then definitionAttribute
    else common.fail "definitionAttribute is not a canonical dotted Nix attribute";
  checkedImage =
    if builtins.isAttrs image && (image.passthru.ociImageIndex or false)
    then image
    else common.fail "image must be produced by mkMultiPlatformIndex";
  checkedReferenceGraph =
    if builtins.isAttrs referenceGraph && (referenceGraph.passthru.referenceGraph or false)
    then referenceGraph
    else common.fail "referenceGraph must be produced by mkReferenceGraph";
  checkedSourceGraph =
    if builtins.isAttrs sourceGraph && (sourceGraph.passthru.referenceGraph or false)
    then sourceGraph
    else common.fail "sourceGraph must be produced by mkReferenceGraph";
  checkedLayers =
    if
      builtins.isList closureLayers
      && closureLayers != []
      && lib.all (layer: builtins.isAttrs layer && (layer.passthru.ociClosureLayer or false)) closureLayers
    then closureLayers
    else common.fail "closureLayers must contain AOS closure-layer derivations";
  checkedCatalog =
    if builtins.isList packageCatalog
    then packageCatalog
    else common.fail "packageCatalog must be a list";
  evidenceSpec = {
    identity = {
      release = validateIdentity "releaseIdentity" releaseIdentity;
      package = validateIdentity "packageName" packageName;
      packageVersion = validateIdentity "packageVersion" packageVersion;
      image = validateIdentity "imageName" imageName;
    };
    nix = {
      attribute = checkedAttribute;
      derivationPath = builtins.unsafeDiscardStringContext checkedImage.drvPath;
      outputName = "out";
      outputPath = builtins.unsafeDiscardStringContext (builtins.toString checkedImage);
    };
    packageCatalog = checkedCatalog;
  };
  layerArguments =
    lib.concatMapStringsSep " "
    (layer: lib.escapeShellArg (builtins.toString layer))
    checkedLayers;
in
  builtins.deepSeq [checkedImage checkedReferenceGraph checkedSourceGraph checkedLayers evidenceSpec] (mkDerivation {
    inherit pname;
    version = "1";
    src = null;
    buildDeps = [coreutils findutils gzip jq tar checkedImage checkedReferenceGraph checkedSourceGraph] ++ checkedLayers;

    outputChecks.out = {};
    inherit evidenceSpec;
    unsafeDiscardReferences.out = true;
    dontStrip = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "assemble";
        script = ''
          export AOS_EVIDENCE_IMAGE=${lib.escapeShellArg (builtins.toString checkedImage)}
          export AOS_EVIDENCE_REFERENCE_GRAPH=${lib.escapeShellArg (builtins.toString checkedReferenceGraph)}
          export AOS_EVIDENCE_SOURCE_GRAPH=${lib.escapeShellArg (builtins.toString checkedSourceGraph)}
          printf '%s\n' ${layerArguments} > evidence-layer-paths
          export AOS_EVIDENCE_LAYER_PATHS="$PWD/evidence-layer-paths"
          ${common.archiveScript}
          ${builtins.readFile ./evidence-assemble.sh}
        '';
      }
    ];

    passthru = {
      ociEvidence = true;
      image = checkedImage;
    };

    meta.description = "Deterministic unsigned OCI evidence for ${imageName}";
  })
