# Select the Cargo shell directly for fast local iteration. Evaluating the
# flake entry point first also discovers its large package and check surface.
((import ./flake.nix).outputs {}).devShells.${builtins.currentSystem}.cargo
