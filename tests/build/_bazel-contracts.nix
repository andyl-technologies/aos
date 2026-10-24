##! Qualifies the connected portable release, deployment and storage contracts.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/contracts-inventory.json,
}: let
  packages = {
    aos-release-format = "crates/release/aos-release-format";
    aos-module-docs = "crates/modules/aos-module-docs";
    aos-deployment-format = "crates/packages/aos-deployment-format";
    aos-storage-layout = "crates/boot/aos-storage-layout";
  };
  dependencyPackages = {
    aos-core = "crates/core/aos-core";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-module-format = "crates/modules/aos-module-format";
    aos-registry-format = "crates/registry/aos-registry-format";
  };
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags;
    pname = "aos-bazel-contracts";
    dependencyProfile = "formats";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.formats // {aos_native = pkgs.aosBazelStoreLibraries;};
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
in
  family
  // {
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-contracts-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["unit" "doc" "license_closure" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ [
          "//crates/release/aos-release-format:qualification"
          "//crates/release/aos-release-format:nix_inventory"
        ];
    };
    all =
      pkgs.runCommand "aos-bazel-contracts-qualified-checks" {
        buildDeps = [family.all family.editor-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
      '';
  }
