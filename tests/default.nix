# tests/default.nix — AOS test suite entry point
#
# Composes all test layers:
#   eval        — Pure Nix evaluation checks (no builds, no VMs)
#   build       — Package build and closure size checks
#   vm          — Single-VM integration tests (boot, immutability, security, etc.)
#   fleet       — Multi-VM orchestration tests (k8s cluster, rolling update)
#   integration — Headless Firecracker microVM tests (per-package checks + central)
#
# Integration checks are defined alongside packages as `checks` attributes on
# each derivation. The collection mechanism below iterates over the package set,
# calls each package's `checks` function, and prefixes the results with the
# package name.
#
# Usage:
#   nix-build -A checks.eval                          Run eval checks only
#   nix-build -A checks.build                         Run build checks only
#   nix-build -A checks.vm.boot                       Run VM boot test
#   nix-build -A checks.fleet.k8s                     Run k8s cluster fleet test
#   nix-build -A checks.integration.zlib-link         Run a single integration test
{
  pkgs,
  lib,
  testTools,
}: let
  mkSystem = modules:
    lib.evalModules {
      modules = modules;
      inherit pkgs lib;
    };

  systems = {
    base = mkSystem [../systems/base.nix];
    server = mkSystem [../systems/server.nix];
    seed = mkSystem [../systems/seed.nix];
    k8s-worker = mkSystem [../systems/k8s-worker.nix];
    k8s-control-plane = mkSystem [../systems/k8s-control-plane.nix];
  };

  # Firecracker-based integration tests use the testing library but don't
  # need QEMU or other testTools — pass an empty set.
  testing = import ../lib/testing {
    inherit pkgs lib;
    testTools = {};
  };

  # Collect integration checks defined on packages via their `checks` attribute.
  # Each package's `checks` is a function: { testing, self, pkgs } -> attrset.
  # Results are prefixed with the package name to avoid collisions.
  prefixAttrs = prefix: attrs:
    builtins.listToAttrs (
      builtins.map (name: {
        name = "${prefix}-${name}";
        value = attrs.${name};
      }) (builtins.attrNames attrs)
    );

  packageChecks = builtins.foldl' (
    acc: name: let
      pkg = pkgs.${name};
    in
      if builtins.isAttrs pkg && pkg ? checks
      then
        acc
        // prefixAttrs name (
          pkg.checks {
            inherit testing pkgs;
            self = pkg;
          }
        )
      else acc
  ) {} (builtins.attrNames pkgs);

  # Cross-cutting and ABI tests that span multiple packages stay central.
  centralChecks = import ./integration/central.nix {inherit pkgs testing;};
in {
  eval = import ./eval.nix {inherit pkgs lib systems;};
  build = import ./build.nix {inherit pkgs lib;};
  vm = import ./vm {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  fleet = import ./fleet {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  integration = packageChecks // centralChecks;
}
