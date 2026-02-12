# default.nix — the entire AOS system
#
# No flakes. No experimental features. Pure, stable Nix.
#
# Usage:
#   nix-build -A pkgs.coreutils           Build a package
#   nix-build -A systems.server.config     Evaluate a system config
#   nix-build -A images.server             Build a bootable disk image
#   nix-build -A checks                   Run all tests
#   nix-build -A checks.eval              Run evaluation checks only
#   nix-build -A checks.vm.boot           Run VM boot test
#   nix-build -A checks.fleet.k8s-cluster Run k8s cluster fleet test
#   nix-shell                              Enter dev shell
#
# Structure:
#   pkgs/     — Package definitions (toolchain, core, init, kernel, etc.)
#   lib/      — Library functions (derivations, modules, types, etc.)
#   modules/  — NixOS-style configuration modules
#   systems/  — System variant compositions (base, server, k8s-*)
#   images/   — Disk image builders
#   tests/    — Multi-layer test suite (eval, build, vm, fleet)

let
  lib = import ./lib;
  pkgs = import ./pkgs { inherit lib; };

  # Helper: evaluate a system variant from a module path list.
  mkSystem = modules: lib.evalModules {
    modules = modules;
    inherit pkgs lib;
  };

  systems = {
    base = mkSystem [ ./systems/base.nix ];
    server = mkSystem [ ./systems/server.nix ];
    k8s-worker = mkSystem [ ./systems/k8s-worker.nix ];
    k8s-control-plane = mkSystem [ ./systems/k8s-control-plane.nix ];
  };

in {
  inherit pkgs lib systems;

  images = {
    base = import ./images/base.nix {
      inherit pkgs lib;
      system = systems.base;
    };
    server = import ./images/server.nix {
      inherit pkgs lib;
      system = systems.server;
    };
    k8s-worker = import ./images/k8s-worker.nix {
      inherit pkgs lib;
      system = systems.k8s-worker;
    };
    k8s-control-plane = import ./images/k8s-control-plane.nix {
      inherit pkgs lib;
      system = systems.k8s-control-plane;
    };
  };

  checks = import ./tests { inherit pkgs lib; };

  shell = import ./shell.nix { inherit pkgs; };
}
