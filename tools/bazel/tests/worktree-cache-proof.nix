##! Verifies artifacts and action reuse from three independently built Git worktrees.
{
  producer,
  consumer,
  uncached,
  system ? builtins.currentSystem,
}: let
  pkgs = (import ../../.. {inherit system;}).pkgs;
  builds = builtins.mapAttrs (_: path: builtins.storePath path) {
    inherit producer consumer uncached;
  };
in
  pkgs.runCommand "aos-bazel-real-worktree-cache-proof" {
    buildDeps = [pkgs.python3];
  } ''
    ${pkgs.python3}/bin/python3 ${./verify_cache.py} \
      --producer ${builds.producer} \
      --consumer ${builds.consumer} \
      --uncached ${builds.uncached} \
      --output "$out"

    ${pkgs.python3}/bin/python3 ${./verify_worktree_cache.py} --evidence "$out/evidence.json"
  ''
