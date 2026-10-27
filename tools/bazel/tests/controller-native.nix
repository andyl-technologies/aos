##! Qualifies native intermediates from the controller's real ring dependency.
{
  system ? builtins.currentSystem,
  pkgs ? (import ../../.. {inherit system;}).pkgs,
}: let
  tools = builtins.path {
    path = ./.;
    name = "aos-bazel-controller-native-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_controller_native.py" "verify_cache.py"];
  };
  mappedToolchains = pkgs.mkAosBazelToolchains {
    cc = import ../../../pkgs/build-support/_bazel/native-source-paths.nix {inherit pkgs;};
    identity = "controller-native-source-paths";
  };
  build = mode: variant: let
    graph = import ../../../tests/build/_bazel-crucible-controller-tests.nix {
      inherit pkgs;
      sourceInventory =
        if variant == "strict"
        then ../metadata/crucible-controller-tests-inventory.json
        else null;
      toolchains =
        if mode == "mapped"
        then mappedToolchains
        else pkgs.aosBazelToolchains;
    };
    # Keep the diagnostic root out of the production source inventory. Its
    # only dependency is the same pinned ring target used by the controller.
    probeSource = pkgs.runCommand "aos-bazel-controller-ring-probe-source" {} ''
      mkdir -p "$out"
      cp -R ${graph.workspace.source}/. "$out/"
      chmod -R u+w "$out"
      mkdir -p "$out/tools/bazel/tests/native_ring_probe"
      cat > "$out/tools/bazel/tests/native_ring_probe/BUILD.bazel" <<'BUILD'
      filegroup(
          name = "ring",
          testonly = True,
          srcs = ["@aos_controller_tests_crates__ring-0.17.14//:ring"],
      )
      BUILD
    '';
    outputBaseName = "ring-${variant}";
    candidate = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-controller-native-${mode}-${variant}";
      workspace = graph.workspace;
      targets = ["//tools/bazel/tests/native_ring_probe:ring"];
      inherit outputBaseName;
      retainActionGraph = true;
      sharedBuildCache = false;
    };
  in
    candidate.overrideAttrs (previous: {
      src = probeSource;
      phases =
        previous.phases
        ++ [
          {
            name = "retain-native-inputs";
            script = ''
              PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${tools}/verify_controller_native.py retain \
                --execution-root "$TMPDIR/${outputBaseName}/execroot/_main" --output "$out"
            '';
          }
        ];
    });
in rec {
  ordinary-strict = build "ordinary" "strict";
  ordinary-conservative = build "ordinary" "conservative";
  mapped-strict = build "mapped" "strict";
  mapped-conservative = build "mapped" "conservative";
  check =
    pkgs.runCommand "aos-bazel-controller-native-repeatability" {
      buildDeps = [pkgs.python3 pkgs.binutils];
      sharedBuildCache = false;
    } ''
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${tools}/verify_controller_native.py verify \
        --ordinary-strict ${ordinary-strict} --ordinary-conservative ${ordinary-conservative} \
        --mapped-strict ${mapped-strict} --mapped-conservative ${mapped-conservative} \
        --readelf ${pkgs.binutils}/bin/readelf --output "$out"
    '';
}
