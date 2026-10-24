##! Produces real, differently weighted profiles from the same fixture binary.
{
  pkgs,
  workspace,
  source,
}: let
  training = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-pgo-training";
    workspace = workspace // {inherit source;};
    targets = ["//tools/bazel/tests/fixture:package"];
    sharedBuildCache = false;
  };
in
  pkgs.runCommand "aos-bazel-pgo-profiles" {buildDeps = [pkgs.python3 pkgs.llvm];} ''
    cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
    cp ${../../tools/bazel/tests/train_pgo.py} train_pgo.py
    ${pkgs.python3}/bin/python3 train_pgo.py \
      --build ${training} --profdata ${pkgs.llvm}/bin/llvm-profdata \
      --rustc ${pkgs.rust}/bin/rustc.unwrapped --output "$out"
  ''
