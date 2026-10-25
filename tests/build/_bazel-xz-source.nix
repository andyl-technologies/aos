##! Compiles the static XZ dependency with the declared AOS C/Rust toolchain.
{pkgs}: let
  root = ../..;
  targets = ["//tools/bazel/tests/fixture:rust_library"];
  workspace = pkgs.mkAosBazelWorkspace {
    inherit root;
    dependencyProfile = "hub-native-postgres";
    sourceDirectories = ["tools/bazel" "third_party/rust"];
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.hub-native-postgres;
    analysisTargets = targets;
  };
  # Inventory exports require a first-party root. Add the upstream dependency
  # to the existing fixture in a private source view, preserving checkout inputs.
  source =
    pkgs.runCommand "aos-bazel-bounded-xz-probe-source" {
      buildDeps = [pkgs.python3];
    } ''
      mkdir -p "$out"
      cp -R ${workspace.source}/. "$out/"
      chmod u+w "$out/tools/bazel/tests/fixture/BUILD.bazel"
      ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
      from pathlib import Path
      import sys
      path = Path(sys.argv[1]) / "tools/bazel/tests/fixture/BUILD.bazel"
      contents = path.read_text()
      old = '    deps = [":generated_library"],'
      assert contents.count(old) == 1
      path.write_text(contents.replace(old, '    deps = [":generated_library", "//third_party/rust:core_xz2"],'))
      PYTHON
    '';
in
  pkgs.mkAosBazelBuild {
    pname = "aos-bazel-bounded-xz-native-source-probe";
    workspace = workspace // {inherit source;};
    inherit targets;
    retainActionGraph = true;
    sharedBuildCache = false;
  }
