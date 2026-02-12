# shell.nix — AOS development environment
#
# Provides the tooling needed for day-to-day AOS development:
# building packages, running tests, inspecting the module system.
#
# Usage:
#   nix-shell              Enter the dev shell
#   nix-shell --pure       Enter with only AOS tools in PATH

{ pkgs ? import ./pkgs { lib = import ./lib; } }:

pkgs.mkShell {
  name = "aos-dev";

  buildDeps = [
    # Core build tools are provided by the host Nix installation.
    # The AOS package set itself is available via `pkgs` in the shell.
  ];

  shellHook = ''
    echo "AOS development shell"
    echo ""
    echo "  nix-build -A pkgs.<name>            Build a package"
    echo "  nix-build -A systems.<variant>       Evaluate a system config"
    echo "  nix-build -A images.<variant>        Build a disk image"
    echo "  nix-build -A checks                  Run all tests"
    echo "  nix-build -A checks.eval             Run eval checks"
    echo "  nix-build -A checks.vm.boot          Run VM boot test"
    echo "  nix-build -A checks.fleet.k8s-cluster  Run k8s fleet test"
    echo ""
    export AOS_ROOT="$(pwd)"
  '';
}
