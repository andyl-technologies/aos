##! Fault injection touches only a disposable cache inside one Nix sandbox.
{pkgs}: let
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
  };
in
  pkgs.runCommand "aos-bazel-cache-recovery" {buildDeps = [pkgs.python3];} ''
    cp ${../../tools/bazel/tests/cache_recovery.py} cache_recovery.py
    cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
    cp ${../../tools/bazel/metadata/export_packages.py} export_packages.py
    ${pkgs.python3}/bin/python3 cache_recovery.py \
      --source ${workspace.source} --lock ${workspace.preparedLock}/MODULE.bazel.lock \
      --config ${workspace.configuration} --launcher ${../../tools/bazel/launcher.py} --output "$out"
  ''
