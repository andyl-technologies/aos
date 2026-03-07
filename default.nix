# default.nix — the entire AOS system
#
# Usage:
#   nix-build -A pkgs.coreutils           Build a package
#   nix-build -A stdenv                   Build the production stdenv (GCC 14)
#   nix-build -A stdenv.bootstrap.gcc     GCC 2.95.3 from hex0 chain
#   nix-build -A system.config            Evaluate the system config
#   nix-build -A image                    Build the bootable disk image
#   nix-build -A checks                   Run all tests
#   nix-build -A checks.eval              Run evaluation checks only
#   nix-build -A checks.vm.boot           Run VM boot test
#   nix-build -A pkgs.zlib --arg crossSystem '"aarch64-linux"'  Cross-compile
#
# Structure:
#   stdenv/  — Bootstrap chain + toolchain ladder + stdenv (self-contained)
#   pkgs/    — Package definitions (core, init, kernel, etc.)
#   lib/     — Library functions (derivations, modules, types, etc.)
#   modules/ — NixOS-style configuration modules
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
  # No nixpkgs anywhere.
  pkgs = import ./pkgs { inherit lib stdenv; };

  # All test tools are AOS packages built from source.
  testTools = {
    qemu = pkgs.qemu;
  };

  # Evaluate the single system definition.
  aosSystem = lib.evalModules {
    modules = [ ./system.nix ];
    inherit pkgs lib;
  };
in
{
  inherit pkgs lib stdenv;

  system = aosSystem;
  image = aosSystem.config.system.build.image;

  checks = import ./lib/testing/collect.nix {
    inherit pkgs lib testTools;
    system = aosSystem;
  };
}
