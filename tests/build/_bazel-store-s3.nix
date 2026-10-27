##! Qualifies S3 adapter compilation and its ordinary offline test inventory.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/store-s3-inventory.json,
}: let
  packages = {
    crucible-store-s3 = "crates/crucible/crucible-store-s3";
  };
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages sourceInventory;
    pname = "aos-bazel-store-s3";
    dependencyPackages = {
      crucible-store = "crates/crucible/crucible-store";
    };
    dependencyProfile = "store-s3";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.store-s3 // {aos_native = pkgs.aosBazelStoreLibraries;};
    extraSourceDirectories = ["BUILD.bazel" "crates"];
    nativeLibraries = [pkgs.sqlite pkgs.zstdStaticMultithread];
    nativeTools = [pkgs.pkg-config];
    cargoSetup = ''
      export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
    '';
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    editorRustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    editorComparisonScope = "selected-packages";
    editorDiagnosticContext = true;
    editorLibraryTargets = {crucible-store-s3 = "lib_for_tests";};
  };
in
  family
  // rec {
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-store-s3-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets = map (name: "//crates/crucible/crucible-store-s3:${name}") [
        "unit"
        "live_conformance"
        "doc"
        "license_closure"
        "production_license_closure"
        "clippy"
        "documentation"
        "format"
      ];
    };
    production-license = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-store-s3-production-license";
      workspace = family.workspace;
      targets = ["//crates/crucible/crucible-store-s3:production_license_closure"];
    };
    all =
      pkgs.runCommand "aos-bazel-store-s3-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-license];
      } ''
        mkdir -p "$out/editor"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json "$out/inventory.json"
        cp ${family.oracle}/parity.json "$out/default.json"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp -r ${family.editor} "$out/editor/bazel"
        cp -r ${family.editor-cargo-oracle} "$out/editor/cargo"
        cp -r ${production-license} "$out/production-license"
      '';
  }
