# default.nix — the entire AOS system
#
# Usage:
#   nix-build -A pkgs.coreutils           Build a package
#   nix-build -A systems.server.config     Evaluate a system config
#   nix-build -A images.server             Build a bootable disk image
#   nix-build -A checks                   Run all tests
#   nix-build -A checks.eval              Run evaluation checks only
#   nix-build -A checks.vm.boot           Run VM boot test
#   nix-build -A checks.fleet.k8s-cluster Run k8s cluster fleet test
#
# Structure:
#   pkgs/     — Package definitions (toolchain, core, init, kernel, etc.)
#   lib/      — Library functions (derivations, modules, types, etc.)
#   modules/  — NixOS-style configuration modules
#   systems/  — System variant compositions (base, server, k8s-*)
#   modules/image/ — Disk image builder module
#   tests/    — Multi-layer test suite (eval, build, vm, fleet)
{system ? "x86_64-linux"}: let
  lib = import ./lib {inherit system;};

  # All packages are built hermetically from source using only bootstrap
  # tools and previously-built AOS packages.  No nixpkgs anywhere.
  pkgs = import ./pkgs {inherit lib;};

  # All test tools are AOS packages built from source.
  testTools = {
    qemu = pkgs.qemu;
  };

  # Helper: evaluate a system variant from a module path list.
  mkSystem = modules:
    lib.evalModules {
      modules = modules;
      inherit pkgs lib;
    };

  systems = {
    base = mkSystem [./systems/base.nix];
    server = mkSystem [./systems/server.nix];
    seed = mkSystem [./systems/seed.nix];
    k8s-worker = mkSystem [./systems/k8s-worker.nix];
    k8s-control-plane = mkSystem [./systems/k8s-control-plane.nix];
  };
in {
  inherit pkgs lib systems;

  images = lib.mapAttrs (name: system: system.config.system.build.image) systems;

  checks = import ./tests {inherit pkgs lib testTools;};
}
