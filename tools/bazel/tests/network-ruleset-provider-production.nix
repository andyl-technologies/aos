##! Installed static network-ruleset provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-network-ruleset-provider-production.nix {inherit pkgs;}
