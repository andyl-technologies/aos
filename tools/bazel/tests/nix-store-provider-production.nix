##! Installed Nix store provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-nix-store-provider-production.nix {inherit pkgs;}
