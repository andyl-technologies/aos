##! Hermetic OCI builder API owned by the AOS OCI backend package.
##!
##! The package fixed point exposes this API as `pkgs.ociTools`; consumers do
##! not import backend implementation files or assemble its tool splice.
##!
##! ```nix
##! image = pkgs.ociTools.mkImageLayout { ... };
##! ```
##!
##! The returned builders perform no import-from-derivation.  Closure discovery
##! happens only when a builder realizes structured `exportReferencesGraph`
##! metadata inside its normal build sandbox.
{
  lib,
  mkDerivation,
  runArtifact,
  coreutils,
  findutils,
  gzip,
  jq,
  tar,
  mkReferenceGraph,
  deploymentChecker,
}: let
  common = import ./common.nix {inherit lib;};
  baseDependencies = {
    inherit lib mkDerivation coreutils findutils gzip jq tar common deploymentChecker;
  };
  dependencies = baseDependencies // {inherit mkReferenceGraph;};
in rec {
  inherit common;
  inherit mkReferenceGraph;

  layerAbi = "aos.container.layer/v2";
  evidencePlatformsScript = ./evidence-platforms.sh;
  archivePolicy = {
    tar = "GNU tar 1.35";
    gzip = "gzip 1.14";
    timestamp = 1;
    owner = 0;
    group = 0;
    compressionLevel = 9;
  };

  mkClosureLayer = import ./closure-layer.nix dependencies;
  mkRootMetadataLayer = import ./metadata-layer.nix baseDependencies;
  mkImageLayout = import ./image-layout.nix baseDependencies;
  mkMultiPlatformIndex = import ./multi-platform-index.nix baseDependencies;
  mkDockerArchive = import ./docker-archive.nix baseDependencies;
  mkEvidenceSourceGraph = import ./evidence-source-graph.nix {
    inherit lib mkDerivation coreutils jq;
  };
  mkEvidenceLayout = import ./evidence-layout.nix baseDependencies;
  mkDeploymentArtifact = import ./deployment-artifact.nix {
    inherit lib runArtifact jq common deploymentChecker;
  };

  # Short aliases are useful to call sites while the long names preserve the
  # RFC vocabulary at the public boundary.
  mkMetadataLayer = mkRootMetadataLayer;
  mkImage = mkImageLayout;
  mkIndex = mkMultiPlatformIndex;
}
