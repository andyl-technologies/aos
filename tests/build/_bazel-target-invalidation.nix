##! Changing only the target platform must separate cached native/foreign code.
{
  pkgs,
  trial,
}: let
  targetPackages = (import ../.. {crossSystem = "aarch64-linux";}).pkgs;
  nativeToolchains = pkgs.mkAosBazelToolchains {identity = "target-invalidation:${trial}";};
  toolchains = pkgs.mkAosBazelCrossToolchains {inherit targetPackages nativeToolchains;};
  workspace = targetPlatform:
    pkgs.mkAosBazelWorkspace {
      root = ../..;
      inherit toolchains targetPlatform;
      sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
      analysisTargets = ["//tools/bazel/tests/fixture:package"];
    };
  build = name: targetPlatform: dependencies:
    (pkgs.mkAosBazelBuild {
      pname = "aos-bazel-target-invalidation-${name}";
      workspace = workspace targetPlatform;
      targets = ["//tools/bazel/tests/fixture:package"];
      cacheNamespace = "target-invalidation-${trial}";
    }).overrideAttrs (previous: {buildDeps = previous.buildDeps ++ dependencies;});
  native = build "native" null [];
  foreign = build "foreign" "//tools/bazel/toolchains:aarch64_linux" [native];
  restored = build "restored" "//tools/bazel/toolchains:aarch64_linux" [foreign];
in
  pkgs.runCommand "aos-bazel-target-invalidation-proof" {buildDeps = [pkgs.python3 pkgs.qemu];} ''
    cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
    cp ${../../tools/bazel/tests/verify_cross_linux.py} verify_cross_linux.py
    cp ${../../tools/bazel/tests/verify_target_invalidation.py} verify_target_invalidation.py
    ${pkgs.python3}/bin/python3 verify_target_invalidation.py \
      --native ${native} --foreign ${foreign} --restored ${restored} \
      --qemu ${pkgs.qemu}/bin/qemu-aarch64 --output "$out"
  ''
