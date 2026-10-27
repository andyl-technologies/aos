##! Exercises the opt-in Bazel production CLI package, including split outputs.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-aos-cli-package.nix {inherit pkgs;}
