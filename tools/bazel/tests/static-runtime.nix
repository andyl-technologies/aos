##! Standalone qualification of the source-built static guest runtime adapter.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-static-runtime.nix {inherit pkgs;}
