##! S3 adapter qualification and conservative configured metadata refresh.
{system ? builtins.currentSystem}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
in
  (import ../../../tests/build/_bazel-store-s3.nix {inherit pkgs;})
  // {
    conservative = import ../../../tests/build/_bazel-store-s3.nix {
      inherit pkgs;
      sourceInventory = null;
    };
  }
