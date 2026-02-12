# tests/default.nix — AOS test suite entry point
#
# Composes all test layers:
#   eval  — Pure Nix evaluation checks (no builds, no VMs)
#   build — Package build and closure size checks
#   vm    — Single-VM integration tests (boot, immutability, security, etc.)
#   fleet — Multi-VM orchestration tests (k8s cluster, rolling update)
#
# Usage:
#   nix-build -A checks.eval          Run eval checks only
#   nix-build -A checks.build         Run build checks only
#   nix-build -A checks.vm.boot       Run VM boot test
#   nix-build -A checks.fleet.k8s     Run k8s cluster fleet test

{ pkgs, lib }:

let
  mkSystem = modules: lib.evalModules {
    modules = modules;
    inherit pkgs lib;
  };

  systems = {
    base = mkSystem [ ../systems/base.nix ];
    server = mkSystem [ ../systems/server.nix ];
    k8s-worker = mkSystem [ ../systems/k8s-worker.nix ];
    k8s-control-plane = mkSystem [ ../systems/k8s-control-plane.nix ];
  };
in {
  eval = import ./eval.nix { inherit pkgs lib systems; };
  build = import ./build.nix { inherit pkgs lib; };
  vm = import ./vm { inherit pkgs lib systems; };
  fleet = import ./fleet { inherit pkgs lib systems; };
}
