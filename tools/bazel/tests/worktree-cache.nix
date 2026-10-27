##! Builds the same cache fixture from caller-selected Git worktrees.
{
  checkoutPath,
  cacheDir,
  trial,
  sharedBuildCache ? true,
  system ? builtins.currentSystem,
}: let
  root = builtins.toPath checkoutPath;
  pkgs =
    (import root {
      inherit system;
      sharedBazelCacheDir = cacheDir;
    }).pkgs;
  toolchains = pkgs.mkAosBazelToolchains {identity = "git-worktrees:${trial}";};
  workspace = pkgs.mkAosBazelWorkspace {
    inherit root toolchains;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
  };
in
  pkgs.mkAosBazelBuild {
    pname = "aos-bazel-real-worktree-cache";
    inherit workspace sharedBuildCache;
    cacheNamespace = "rfc0028-git-worktrees-${trial}";
    targets = ["//tools/bazel/tests/fixture:package"];
  }
