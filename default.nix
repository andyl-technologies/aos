# default.nix — ANDYL OS
#
# The single entry point for everything AOS: library, packages, systems,
# modules, and checks. The flake wraps this for Nix flake consumers and
# adds dev-only things (devShell, formatter).
#
# Usage:
#   nix-build -A pkgs.coreutils                     Build a package
#   nix-build -A stdenv                              Build the production stdenv
#   nix-build -A systems.server.build.toplevel       Build the server system
#   nix-build -A systems.server.build.image.raw      Build a raw disk image
#   nix-build -A systems.server.build.image.qcow2    Build a QCOW2 image
#   nix-build -A systems.edge.build.image.raw        Build an edge raw image
#   nix-build -A checks                              Run all tests
#   nix-build -A checks.eval                         Run evaluation checks only
#
# Structure:
#   stdenv/  — Bootstrap chain + toolchain ladder + stdenv (self-contained)
#   pkgs/    — Package definitions
#   lib/     — Library functions (derivations, modules, types, etc.)
#   modules/ — NixOS-style configuration modules
#   systems/ — Golden image definitions (auto-discovered)
#   lib/testing/ — Test infrastructure and check collection
{
  system ? builtins.currentSystem,
  crossSystem ? null,
}:
let
  lib = import ./lib { inherit system; };
  buildPlatform = lib.platform;
  hostPlatform = if crossSystem != null then lib.mkPlatform crossSystem else buildPlatform;

  # Self-contained stdenv: hex0 bootstrap → toolchain ladder → production stdenv.
  stdenv = import ./stdenv {
    inherit buildPlatform hostPlatform;
    targetPlatform = hostPlatform;
  };

  # All packages are built hermetically from source using only stdenv.
  pkgs = import ./pkgs { inherit lib stdenv; };

  # Auto-discovered module list.
  modules = import ./modules;

  # Build a system from a system definition module (or list of modules).
  mkSystem =
    systemModule:
    let
      extraModules = if builtins.isList systemModule then systemModule else [ systemModule ];
    in
    lib.evalModules {
      modules = modules ++ extraModules;
      inherit pkgs lib;
    };

  # Auto-discover system definitions from ./systems/*.nix
  discoverSystems =
    let
      entries = builtins.readDir ./systems;
      nixFiles = builtins.filter (
        name:
        entries.${name} == "regular"
        && builtins.match ".*\\.nix" name != null
        && builtins.substring 0 1 name != "_"
      ) (builtins.attrNames entries);
    in
    builtins.listToAttrs (
      builtins.map (name: {
        name = lib.removeSuffix ".nix" name;
        value =
          let
            evaluated = mkSystem (./systems + "/${name}");
          in
          {
            config = evaluated.config;
            options = evaluated.options;
            build = {
              toplevel = evaluated.config.system.build.toplevel;
              kernel = evaluated.config.system.build.kernel;
              initrd = evaluated.config.system.build.initrd;
              image = evaluated.config.system.build.image;
            };
          };
      }) nixFiles
    );

  # Test tools — all AOS packages built from source.
  testTools = {
    qemu = pkgs.qemu;
    socat = pkgs.socat;
    jq = pkgs.jq;
  };

  # System definition paths (for test collection to re-evaluate with extra modules)
  systemDefs =
    let
      entries = builtins.readDir ./systems;
      nixFiles = builtins.filter (
        name:
        entries.${name} == "regular"
        && builtins.match ".*\\.nix" name != null
        && builtins.substring 0 1 name != "_"
      ) (builtins.attrNames entries);
    in
    builtins.listToAttrs (
      builtins.map (name: {
        name = lib.removeSuffix ".nix" name;
        value = ./systems + "/${name}";
      }) nixFiles
    );
in
{
  inherit lib pkgs stdenv modules mkSystem;

  # Auto-discovered golden image systems
  systems = discoverSystems;

  # Module-level test suites (run against the server system by default)
  checks = import ./lib/testing/collect.nix {
    inherit pkgs lib testTools;
    system = (mkSystem ./systems/server.nix);
  };

  # System-level integration tests (per-system and multi-VM)
  systemChecks = import ./systems/tests {
    inherit lib pkgs testTools mkSystem systemDefs;
  };
}
