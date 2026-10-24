##! Qualifies native execution tools and foreign Linux Rust/C++ artifacts.
{pkgs}: let
  targetPackages = (import ../.. {crossSystem = "aarch64-linux";}).pkgs;
  toolchains = pkgs.mkAosBazelCrossToolchains {inherit targetPackages;};
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit toolchains;
    sourceDirectories = ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "tools/bazel/tests/fixture"];
    targetPlatform = "//tools/bazel/toolchains:aarch64_linux";
    analysisTargets = ["//tools/bazel/tests/fixture:package"];
  };
in rec {
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-aarch64-fixtures";
    inherit workspace;
    targets = ["//tools/bazel/tests/fixture:package"];
  };
  all = pkgs.runCommand "aos-bazel-aarch64-toolchain-check" {buildDeps = [pkgs.python3 pkgs.qemu];} ''
    mkdir -p "$out"
    cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
    cp ${../../tools/bazel/tests/verify_cross_linux.py} verify_cross_linux.py
    ${pkgs.python3}/bin/python3 verify_cross_linux.py \
      --build ${build} --qemu ${pkgs.qemu}/bin/qemu-aarch64 --output "$out/evidence.json"

    # The same target must fail without its adapter. Native execution tools
    # must never become an implicit fallback for target compilation.
    mkdir workspace
    cp -a ${workspace.source}/. workspace/
    chmod -R u+w workspace
    cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    ${pkgs.python3}/bin/python3 - ${workspace.configuration} <<'PYTHON'
    import json
    from pathlib import Path
    import sys

    configuration = json.loads(Path(sys.argv[1]).read_text())
    configuration["repositories"]["aos_tools"] = "${pkgs.aosBazelToolchains}"
    Path("native-only.json").write_text(json.dumps(configuration))
    PYTHON
    if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config "$PWD/native-only.json" --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/reject-native" --nix-sandbox --batch \
      -- build //tools/bazel/tests/fixture:package --nobuild \
      > "$out/rejected-native-fallback.log" 2>&1; then
      printf '%s\n' 'foreign target unexpectedly accepted a native-only toolchain repository' >&2
      exit 1
    fi
    grep -F 'No matching toolchains found for types:' "$out/rejected-native-fallback.log"
  '';
}
