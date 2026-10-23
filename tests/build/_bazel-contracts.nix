##! Qualifies the connected portable release, deployment and storage contracts.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/contracts-inventory.json,
}: let
  packages = {
    aos-release-format = "crates/aos/release/aos-release-format";
    aos-module-docs = "crates/aos/modules/aos-module-docs";
    aos-deployment-format = "crates/aos/packages/aos-deployment-format";
    aos-storage-layout = "crates/aos/boot/aos-storage-layout";
  };
  dependencyPackages = {
    aos-core = "crates/shared/aos-core";
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
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
          "//crates/aos/release/aos-release-format:qualification"
          "//crates/aos/release/aos-release-format:nix_inventory"
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
