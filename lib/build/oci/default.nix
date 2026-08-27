##! lib/build/oci/default.nix -- hermetic AOS OCI builder API.
##!
##! Import this file with explicit AOS package arguments; it never imports
##! nixpkgs or discovers host tools:
##!
##! ```nix
##! oci = import ./lib/build/oci {
##!   inherit lib;
##!   inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
##! };
##! ```
##!
##! The returned builders perform no import-from-derivation.  Closure discovery
##! happens only when a builder realizes structured `exportReferencesGraph`
##! metadata inside its normal build sandbox.
{
  lib,
  mkDerivation,
  coreutils,
  findutils,
  gzip,
  jq,
  tar,
}: let
  common = import ./common.nix {inherit lib;};
  baseDependencies = {
    inherit lib mkDerivation coreutils findutils gzip jq tar common;
  };
  mkReferenceGraph = import ../reference-graph.nix {
    inherit lib mkDerivation coreutils jq;
  };
  dependencies = baseDependencies // {inherit mkReferenceGraph;};
in rec {
  inherit common;
  inherit mkReferenceGraph;

  layerAbi = "aos.container.layer/v1";
  archivePolicy = {
    tar = "GNU tar 1.35";
    gzip = "gzip 1.13";
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

  # Short aliases are useful to call sites while the long names preserve the
  # RFC vocabulary at the public boundary.
  mkMetadataLayer = mkRootMetadataLayer;
  mkImage = mkImageLayout;
  mkIndex = mkMultiPlatformIndex;
}
