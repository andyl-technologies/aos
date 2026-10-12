# Select the Cargo shell directly without discovering the broad flake output set.
((import ./flake.nix).outputs {}).devShells.${builtins.currentSystem}.cargo
