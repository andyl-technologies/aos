##! Qualifies the production boot-identity Bazel selector and installed outputs.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-boot-production.nix {inherit pkgs;}
