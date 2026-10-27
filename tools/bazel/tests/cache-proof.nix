##! Explicit qualification entry point supporting a unique trial identity.
{
  cacheDir,
  trial,
  system ? builtins.currentSystem,
}: let
  aos = import ../../.. {
    inherit system;
    sharedBazelCacheDir = cacheDir;
  };
  pkgs = aos.pkgs;
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
  };
in
  import ../../../tests/build/_bazel-cache.nix {inherit pkgs workspace trial;}
