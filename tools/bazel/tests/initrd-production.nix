##! Exercises the production standalone initrd package and its direct-rustc fallback.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-initrd-production.nix {inherit pkgs;}
