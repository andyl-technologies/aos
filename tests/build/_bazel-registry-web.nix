##! Qualifies native registry SPA models, verification, tests, and editor inputs.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/registry-web-inventory.json,
}: let
  packages = {aos-registry-web = "crates/registry/aos-registry-web";};
  dependencyPackages = {
    aos-core = "crates/core/aos-core";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-registry-format = "crates/registry/aos-registry-format";
  };
  repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.registry-web;
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  prefix = "//crates/registry/aos-registry-web:";
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory repositories rustcFlags;
    pname = "aos-bazel-registry-web";
    dependencyProfile = "registry-web";
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    extraTests = ["${prefix}bin_aos-registry-spa"];
    emptyTests = ["${prefix}bin_aos-registry-spa"];
    extraEditorTargets = ["${prefix}aos-registry-spa" "${prefix}bin_aos-registry-spa_binary"];
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = map (name: prefix + name) ["lib" "shared" "aos-registry-spa" "production_license_closure"];
in
  family
  // rec {
    inherit packages dependencyPackages;
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-registry-web-native-production";
      workspace = family.workspace;
      targets = productionTargets;
      retainActionGraph = true;
    };
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-registry-web-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        map (name: prefix + name) ["unit" "bin_aos-registry-spa" "doc" "clippy" "documentation" "format" "license_closure"]
        ++ productionTargets
        ++ map (path: "//${path}:source_package") (builtins.attrValues dependencyPackages);
    };
    all =
      pkgs.runCommand "aos-bazel-registry-web-native-checks" {
        buildDeps = [family.all family.editor-parity production];
      } ''
        mkdir -p "$out"
        ln -s ${family.all} "$out/tests"
        ln -s ${family.editor-parity} "$out/editor"
        ln -s ${production} "$out/production"
      '';
  }
