##! Separates native execution tools from a source-built WASM target sysroot.
{pkgs}: let
  verifier = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-bazel-wasm-verifier";
    filter = path: type: type == "directory" || builtins.elem (baseNameOf path) ["verify_wasm.py" "verify_cache.py"];
  };
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = [
      "tools/bazel/toolchains"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/testing"
      "tools/bazel/tests/fixture"
    ];
    targetPlatform = "//tools/bazel/toolchains:wasm32";
    analysisTargets = ["//tools/bazel/tests/fixture:wasm_package"];
  };
in rec {
  build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-wasm-fixture";
    inherit workspace;
    targets = ["//tools/bazel/tests/fixture:wasm_package"];
  };
  all = pkgs.runCommand "aos-bazel-wasm-toolchain-check" {buildDeps = [pkgs.python3];} ''
    mkdir -p "$out"
    ${pkgs.python3}/bin/python3 ${verifier}/verify_wasm.py \
      --build ${build} --output "$out/evidence.json"

    # A native C++ dependency must fail analysis for this target. Supplying a
    # host compiler as a fallback would silently break foreign-target linking.
    mkdir workspace
    cp -a ${workspace.source}/. workspace/
    chmod -R u+w workspace
    cp ${workspace.preparedLock}/MODULE.bazel.lock workspace/MODULE.bazel.lock
    if ${pkgs.python3}/bin/python3 ${../../tools/bazel/launcher.py} \
      --config ${workspace.configuration} --workspace "$PWD/workspace" \
      --output-base "$TMPDIR/reject-native" --nix-sandbox --batch \
      -- build //tools/bazel/tests/fixture:native_app --nobuild \
      > "$out/rejected-native-compiler.log" 2>&1; then
      printf '%s\n' 'WASM analysis unexpectedly admitted a native C++ dependency' >&2
      exit 1
    fi
    grep -F 'No matching toolchains found for types:' "$out/rejected-native-compiler.log"
    grep -F '//tools/cpp:toolchain_type' "$out/rejected-native-compiler.log"
  '';
}
