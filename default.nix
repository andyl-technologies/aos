# default.nix — the entire AOS system
#
# Usage:
#   nix-build -A pkgs.coreutils           Build a package
#   nix-build -A stdenv                   Build the production stdenv (GCC 14)
#   nix-build -A stdenv.toolchains.gcc11  Build the GCC 11 stdenv
#   nix-build -A stdenv.bootstrap.gcc     GCC 2.95.3 from hex0 chain
#   nix-build -A systems.server.config    Evaluate a system config
#   nix-build -A images.server            Build a bootable disk image
#   nix-build -A checks                   Run all tests
#   nix-build -A checks.eval              Run evaluation checks only
#   nix-build -A checks.vm.boot           Run VM boot test
#   nix-build -A checks.fleet.k8s-cluster Run k8s cluster fleet test
#
# Structure:
#   stdenv/  — Bootstrap chain + toolchain ladder + stdenv (self-contained)
#   pkgs/    — Package definitions (core, init, kernel, etc.)
#   lib/     — Library functions (derivations, modules, types, etc.)
#   modules/ — NixOS-style configuration modules
#   systems/ — System variant compositions (base, server, k8s-*)
#   tests/   — Multi-layer test suite (eval, build, vm, fleet)
{
  system ? builtins.currentSystem,
}:
let
  lib = import ./lib { inherit system; };
  platform = lib.platform;

  # Self-contained stdenv: hex0 bootstrap → toolchain ladder → production stdenv.
  # stdenv.toolchains.<name> gives alternate stdenvs with the same interface.
  stdenv = import ./stdenv {
    buildPlatform = platform;
    hostPlatform = platform;
    targetPlatform = platform;
  };

  # All packages are built hermetically from source using only stdenv.
  # No nixpkgs anywhere.
  pkgs = import ./pkgs { inherit lib stdenv; };

  # All test tools are AOS packages built from source.
  testTools = {
    qemu = pkgs.qemu;
  };

  # Helper: evaluate a system variant from a module path list.
  mkSystem =
    modules:
    lib.evalModules {
      modules = modules;
      inherit pkgs lib;
    };

  systems = {
    base = mkSystem [ ./systems/base.nix ];
    server = mkSystem [ ./systems/server.nix ];
    seed = mkSystem [ ./systems/seed.nix ];
    k8s-worker = mkSystem [ ./systems/k8s-worker.nix ];
    k8s-control-plane = mkSystem [ ./systems/k8s-control-plane.nix ];
    golden = mkSystem [ ./systems/golden.nix ];
  };
in
{
  inherit pkgs lib systems stdenv;

  images = lib.mapAttrs (name: system: system.config.system.build.image) systems;

  checks = import ./tests { inherit pkgs lib testTools; };
}
