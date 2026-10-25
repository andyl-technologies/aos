##! Audits Crucible declarations and default production feature closures.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-crucible-feature-policy.nix {inherit pkgs;}
