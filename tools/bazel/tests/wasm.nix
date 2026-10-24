##! Standalone qualification while foreign-target adapters are introduced.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-wasm.nix {inherit pkgs;}
