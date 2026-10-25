##! Portable AOS shared libraries qualify together with their Cargo oracle.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/shared-inventory.json,
}: let
  packages = {
    aos-core = "crates/core/aos-core";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-oci-types = "crates/artifacts/aos-oci-types";
  };
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages sourceInventory;
    pname = "aos-bazel-shared";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.core;
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    # The analyzer's native query uses -O independently of Cargo's test profile.
    editorCfgFlags = [];
    editorExecRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes" "-Cstrip=none"];
    retainEditorActionGraph = true;
    retainTestActionGraph = true;
    captureCompilerArguments = true;
  };
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs;
    inherit (family) tests cargo;
    pname = "aos-bazel-shared-execution-profiles";
    firstPartyTests = {
      "//crates/core/aos-core:unit_binary" = "aos_core";
      "//crates/artifacts/aos-artifact-evidence:unit_binary" = "aos_artifact_evidence";
      "//crates/artifacts/aos-oci-types:unit_binary" = "aos_oci_types";
      "//crates/artifacts/aos-oci-types:golden_binary" = "golden";
      "//crates/artifacts/aos-oci-types:reference_vectors_binary" = "reference_vectors";
    };
    proceduralMacros = ["serde_derive" "thiserror_impl"];
  };
  editor-builtin-cfg = import ./_bazel-editor-builtin-cfg.nix {
    inherit pkgs;
    inherit (family) editor;
    pname = "aos-bazel-shared-editor-builtin-cfg";
    cargo = family.editor-cargo-oracle;
    workspace = family.editorWorkspace;
    flags = [];
  };
  editor-execution-profiles = import ./_bazel-rust-editor-profiles.nix {
    inherit pkgs;
    inherit (family) editor;
    pname = "aos-bazel-shared-editor-execution-profiles";
    cargo = family.editor-cargo-oracle;
    proceduralMacros = ["serde_derive" "thiserror_impl"];
    macroDebuginfo = "0";
  };
in
  family
  // {
    inherit execution-profiles editor-builtin-cfg editor-execution-profiles;
    all =
      pkgs.runCommand "aos-bazel-shared-qualified-checks" {
        buildDeps = [family.all family.editor-parity execution-profiles editor-builtin-cfg editor-execution-profiles];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
        cp ${editor-builtin-cfg}/evidence.json "$out/editor-builtin-cfg.json"
        cp ${editor-execution-profiles}/evidence.json "$out/editor-execution-profiles.json"
      '';
  }
