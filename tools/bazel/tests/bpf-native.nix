##! Native BPF artifact compilation and qualification entry point.
{
  system ? builtins.currentSystem,
  sourceInventory ? ../metadata/bpf-native-inventory.json,
}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-bpf-native.nix {inherit pkgs sourceInventory;}
