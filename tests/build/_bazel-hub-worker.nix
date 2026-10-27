##! Qualifies runtime-independent Worker tests and their selected editor graph.
{
  pkgs,
  allFeatures ? false,
  sourceInventory ? ../../tools/bazel/metadata/hub-worker-inventory.json,
}: let
  packages = {aos-hub-worker = "crates/hub/aos-hub-worker";};
  dependencyPackages = {
    libssh2-sys = "crates/bindings/libssh2-sys";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-core = "crates/core/aos-core";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-client = "crates/hub/aos-hub-client";
    aos-hub-db = "crates/hub/aos-hub-db";
    aos-hub-model = "crates/hub/aos-hub-model";
    aos-hub-native = "crates/hub/aos-hub-native";
    aos-hub-service = "crates/hub/aos-hub-service";
    aos-hub-ui = "crates/hub/aos-hub-ui";
    aos-module-docs = "crates/modules/aos-module-docs";
    aos-module-format = "crates/modules/aos-module-format";
    aos-nar = "crates/artifacts/aos-nar";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-registry-client = "crates/registry/aos-registry-client";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-release-format = "crates/release/aos-release-format";
    aos-transfer = "crates/transfer/aos-transfer";
  };
  profile =
    if allFeatures
    then "hub-worker-all-features-tests"
    else "hub-worker-tests";
  cargoFlags = pkgs.lib.optionals allFeatures ["--all-features"];
  inputs = import ./_bazel-registry-native-inputs.nix {inherit pkgs;};
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.${profile}
    // {
      aos_native = pkgs.aosBazelHubServiceLibraries;
      aos_codegen = pkgs.aosBazelCodegenTools;
      aos_console_assets = pkgs.aosBazelConsoleAssets;
    };
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
    inherit (pkgs) lib;
    extraPaths = ["api/proto/aos/hub/v1/hub.proto"];
  };
  nativeLibraries = inputs.nativeLibraries ++ [pkgs.sqlite];
  nativeTools = inputs.nativeTools;
  cargoSetup =
    inputs.cargoSetup
    + ''
      export LIBSQLITE3_SYS_USE_PKG_CONFIG=1
      export AOS_HUB_CONSOLE_JS="${pkgs.aosBazelConsoleAssets}/hub-console.js"
      export AOS_HUB_CONSOLE_WASM="${pkgs.aosBazelConsoleAssets}/hub-console_bg.wasm"
      export AOS_HUB_CONSOLE_CSS="${pkgs.aosBazelConsoleAssets}/hub-console.css"
      export RUST_TEST_THREADS="$NIX_BUILD_CORES"
    '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories nativeLibraries nativeTools cargoSetup cargoSource cargoFlags;
    pname = "aos-bazel-${profile}";
    dependencyProfile = profile;
    extraSourceDirectories = ["api/proto"] ++ builtins.attrValues dependencyPackages;
    extraEditorTargets = ["//crates/hub/aos-hub-service:build_script_program" "//crates/hub/aos-hub-api:build_script_program"];
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorCargoFlags = cargoFlags;
    editorDiagnosticContext = true;
  };
in
  family
  // {
    inherit packages dependencyPackages;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-${profile}-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        [
          "//crates/hub/aos-hub-worker:lib"
          "//crates/hub/aos-hub-worker:unit"
          "//crates/hub/aos-hub-worker:unit_binary"
          "//crates/hub/aos-hub-worker:doc"
          "//crates/hub/aos-hub-worker:clippy"
          "//crates/hub/aos-hub-worker:documentation"
          "//crates/hub/aos-hub-worker:format"
          "//crates/hub/aos-hub-worker:license_closure"
        ]
        ++ map (path: "//${path}:source_package") (builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
    };
  }
