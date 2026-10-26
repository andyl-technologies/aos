##! Installed Kubernetes provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-kubernetes-provider-production.nix {inherit pkgs;}
