##! lib/default.nix — AOS library entry point
##!
##! Composes all library modules into a single attribute set.
##! Usage: `let lib = import ./lib { system = "aarch64-linux"; }; in ...`
##!
##! The `system` parameter is threaded through to all derivation builders
##! (mkDerivation, mkShell, fetchurl, fetchgit, fetchCargoDeps, fetchGoModules)
##! so that every package targets the correct platform.
{system}: let
  trivial = import ./trivial.nix;
  lists = import ./lists.nix;
  attrsets = import ./attrsets.nix;
  strings = import ./strings.nix;
  types = import ./types.nix;
  modules = import ./modules.nix {
    inherit
      trivial
      lists
      attrsets
      strings
      types
      ;
  };
  platformMod = import ./platform.nix;
  derivations = import ./derivations.nix {inherit system;};
  checks = import ./testing/checks.nix;
in
  trivial
  // lists
  // attrsets
  // strings
  // {
    inherit types system;
    inherit (platformMod) mkPlatform cpus satisfies canRun canBuildOn platformIsCompatible constraintsCompatible;
    platform = platformMod.mkPlatform system;
    inherit
      (modules)
      evalModules
      mkOption
      mkIf
      mkMerge
      mkOverride
      mkDefault
      mkForce
      mkOrder
      mkBefore
      mkAfter
      ;
    inherit
      (derivations)
      mkDerivation
      mkShell
      fetchurl
      fetchgit
      fetchCargoDeps
      fetchGoModules
      fakeHash
      ;

    # Phase manipulation helpers from derivations module
    inherit
      (derivations)
      replacePhase
      addPhaseAfter
      addPhaseBefore
      removePhase
      ;

    # Check constructors (pure data, no deps) for use in modules
    inherit
      (checks)
      mkCheck
      mkCheckGroup
      flattenChecks
      composeChecks
      ;

    # Re-export submodules for direct access when needed
    inherit
      trivial
      lists
      attrsets
      strings
      modules
      derivations
      checks
      ;
  }
