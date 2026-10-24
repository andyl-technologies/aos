##! Standalone Linux cross qualification during native inventory refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-cross-linux.nix {inherit pkgs;}
