# lib/default.nix — AOS library entry point
#
# Composes all library modules into a single attribute set.
# Usage: let lib = import ./lib; in ...
#
let
  trivial = import ./trivial.nix;
  lists = import ./lists.nix;
  attrsets = import ./attrsets.nix;
  strings = import ./strings.nix;
  types = import ./types.nix;
  modules = import ./modules.nix { inherit trivial lists attrsets strings types; };
  derivations = import ./derivations.nix;
in
  trivial // lists // attrsets // strings // {
    inherit types;
    inherit (modules) evalModules mkOption mkIf;
    inherit (derivations) mkDerivation mkShell fetchurl fetchgit;

    # Phase manipulation helpers from derivations module
    inherit (derivations) replacePhase addPhaseAfter addPhaseBefore removePhase;

    # Re-export submodules for direct access when needed
    inherit trivial lists attrsets strings modules derivations;
  }
