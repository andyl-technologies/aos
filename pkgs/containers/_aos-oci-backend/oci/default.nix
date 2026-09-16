##! Hermetic OCI builder API owned by the AOS OCI backend package.
##!
##! Import this file with explicit AOS package arguments; it never imports
##! nixpkgs or discovers host tools:
##!
##! ```nix
##! oci = import ./oci {
##!   inherit lib;
##!   inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
##!   abilityContractValidator = pkgs.aos-ability-contract-validator;
##!   inherit mkReferenceGraph;
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
  abilityContractValidator,
  mkReferenceGraph,
}: let
  common = import ./common.nix {inherit lib;};
  checkedPackageOrigin = import ./checked-package-origin.nix {
    abilities = lib.abilities;
    inherit common;
  };
  baseDependencies = {
    inherit lib mkDerivation coreutils findutils gzip jq tar common;
  };
  abilityContractDependencies = baseDependencies // {inherit abilityContractValidator;};
  dependencies = baseDependencies // {inherit mkReferenceGraph;};
in rec {
  inherit common checkedPackageOrigin;
  inherit mkReferenceGraph;

  layerAbi = "aos.container.layer/v2";
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
  mkImageLayout = import ./image-layout.nix abilityContractDependencies;
  mkMultiPlatformIndex = import ./multi-platform-index.nix abilityContractDependencies;
  mkDockerArchive = import ./docker-archive.nix baseDependencies;
  mkEvidenceSourceGraph = import ./evidence-source-graph.nix {
    inherit lib mkDerivation coreutils jq;
  };
  mkEvidenceLayout = import ./evidence-layout.nix baseDependencies;
  mkStaticAbilityContract = import ./static-ability-contract.nix {
    inherit lib mkDerivation abilityContractValidator common;
  };

  # Short aliases are useful to call sites while the long names preserve the
  # RFC vocabulary at the public boundary.
  mkMetadataLayer = mkRootMetadataLayer;
  mkImage = mkImageLayout;
  mkIndex = mkMultiPlatformIndex;
}
