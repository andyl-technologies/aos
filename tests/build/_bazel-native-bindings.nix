##! Qualifies the workspace SSH binding against the selected AOS native library.
{pkgs}: let
  packagePath = "crates/bindings/libssh2-sys";
  packageLabel = "//${packagePath}:";
  inputs = import ./_bazel-registry-native-inputs.nix {inherit pkgs;};
  parityTools = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-native-binding-parity-tools";
    filter = path: type: type == "directory" || pkgs.lib.hasSuffix ".py" path;
  };
  workspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    sourceDirectories = [
      "tools/bazel/toolchains"
      "tools/bazel/rules"
      "tools/bazel/metadata"
      "tools/bazel/testing"
      "third_party/rust"
      packagePath
    ];
    dependencyProfile = "native-bindings";
    analysisTargets = ["${packageLabel}lib" "${packageLabel}unit" "${packageLabel}production_license_closure"];
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.native-bindings
      // {aos_native = pkgs.aosBazelNativeFoundationLibraries;};
  };
in rec {
  inherit workspace;
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-native-binding-tests";
    inherit workspace;
    targets = workspace.selectedTargets;
    sharedBuildCache = false;
    retainActionGraph = true;
  };
  cargo = import ./_bazel-cargo-oracle.nix {
    inherit pkgs;
    pname = "aos-bazel-native-binding-cargo-oracle";
    packages = ["libssh2-sys"];
    inherit (inputs) nativeLibraries nativeTools cargoSetup;
    captureCompilerArguments = true;
  };
  all =
    pkgs.runCommand "aos-bazel-native-binding-checks" {
      buildDeps = [pkgs.python3 tests cargo];
    } ''
      mkdir -p "$out"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
      ${parityTools}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl \
        --package-path libssh2-sys=${packagePath} --output "$out/parity.json"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 \
      ${parityTools}/verify_compiler_options.py \
        --build ${tests} --cargo ${cargo} --output "$out/compiler.json"
    '';
}
