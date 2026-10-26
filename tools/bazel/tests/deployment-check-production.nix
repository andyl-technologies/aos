##! Installed native deployment validator production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-deployment-check-production.nix {inherit pkgs;}
