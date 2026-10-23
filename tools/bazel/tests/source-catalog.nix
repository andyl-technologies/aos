##! Builds source ownership metadata without compiling application packages.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-source-catalog.nix {inherit pkgs;}
