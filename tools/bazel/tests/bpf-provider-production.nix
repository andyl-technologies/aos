##! Installed static BPF provider production qualification.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  import ../../../tests/build/_bazel-bpf-provider-production.nix {inherit pkgs;}
