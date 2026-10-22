##! A new trial identity forces fresh samples instead of reusing a Nix result.
{
  trial,
  system ? builtins.currentSystem,
}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-performance.nix {inherit pkgs trial;}
