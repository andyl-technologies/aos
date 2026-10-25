##! Qualifies checked source patches without a dependency-resolution update.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-rust-source-patches.nix {inherit pkgs;}
