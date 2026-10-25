##! Regenerates and verifies Bazel-owned Crucible release package identities.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-release-metadata.nix {inherit pkgs;}
