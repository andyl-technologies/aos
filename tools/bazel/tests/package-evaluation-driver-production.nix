##! Installed native package-evaluation driver production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-package-evaluation-driver-production.nix {inherit pkgs;}
