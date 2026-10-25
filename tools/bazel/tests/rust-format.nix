##! Qualifies repository formatting without first-party Cargo manifests.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-rust-format.nix {inherit pkgs;}
