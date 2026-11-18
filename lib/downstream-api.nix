##! Downstream builder API exported as the flake's per-system `lib` output.
##!
##! A downstream flake that takes AOS as its only input builds with the same
##! dialect AOS packages use: `buildDeps`/`runtimeDeps`/`propagatedDeps` and
##! `phases = [{ name; script; }]`. This file selects the stable subset of the
##! package set's builders and names it as a versioned contract. Everything
##! else reachable through `legacyPackages` is an implementation detail that
##! may change without notice.
##!
##! The contract, including argument names, the compatibility policy, and the
##! deprecation process, is `docs/engineering/downstream/flake-api.md`. A check
##! fails when a name exported here is missing from that document's export
##! table, or when a documented name disappears from this set.
##!
##! ```text
##! lib.<system>.apiVersion          contract version, "<major>.<minor>"
##! lib.<system>.mkDerivation        package builder
##! lib.<system>.ociTools.<builder>  OCI image builders
##! lib.<system>.toolchains.<name>   toolchain packages the cache publishes
##! ```
{pkgs}: let
  inherit (pkgs) lib;

  # The OCI backend exposes more constructors than downstream images need.
  # Export the builders that assemble an image from store closures. The
  # deployment artifact and closure audit read the package set, so bind them
  # to this one; callers need neither the full set nor AOS's internal `lib`.
  ociTools = {
    inherit
      (pkgs.ociTools)
      mkClosureLayer
      mkDockerArchive
      mkImageLayout
      mkMultiPlatformIndex
      ;
    mkMetadataLayer = pkgs.ociTools.mkRootMetadataLayer;
    mkDeploymentArtifact = args: pkgs.ociTools.mkDeploymentArtifact ({inherit pkgs;} // args);
    mkRuntimeClosureAudit = args: lib.build.runtimeClosureAudit (args // {inherit pkgs;});
  };

  # Each member's package attribute name is its name in the set, which is
  # also the package name the release matrix publishes.
  toolchains = builtins.listToAttrs (map (name: {
    inherit name;
    value = pkgs.${name};
  }) (import ./downstream-toolchains.nix));
in {
  # Bump the minor version for additions and the major version for removals
  # or incompatible changes. The documentation check compares this value with
  # the version stated in the contract.
  apiVersion = "1.0";

  inherit
    (pkgs)
    mkDerivation
    mkShell
    callPackage
    writeTextFile
    writeShellScriptBin
    runCommand
    runtimeShell
    fakeHash
    ;

  inherit
    (lib)
    replacePhase
    addPhaseAfter
    addPhaseBefore
    removePhase
    ;

  inherit
    (pkgs)
    mkCargoPackage
    mkCargoArtifacts
    mkCargoDummySource
    mkCargoNextestCheck
    mkGoPackage
    ;

  inherit
    (pkgs)
    fetchurl
    fetchCargoDeps
    fetchCargoVendor
    fetchGoModules
    fetchNpmDeps
    ;

  inherit ociTools toolchains;
}
