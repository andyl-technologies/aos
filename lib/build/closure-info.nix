##! lib/build/closure-info.nix — Nix DB registration generator
##!
##! Builds a `nix-store --load-db` input stream for the closure of the
##! supplied root paths. This uses Nix's structured `exportReferencesGraph`
##! metadata, so the NAR hashes and sizes come from Nix without re-hashing
##! the closure in the build sandbox.
{
  pkgs,
  lib,
}: let
  mkReferenceGraph = import ./reference-graph.nix {
    inherit lib;
    inherit (pkgs) mkDerivation coreutils jq;
  };
in
  {
    rootPaths,
    pname ? "aos-closure-info",
  }:
    mkReferenceGraph {
      inherit rootPaths pname;
    }
