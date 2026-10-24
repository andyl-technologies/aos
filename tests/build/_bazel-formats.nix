##! Portable format libraries preserve default and optional NAR compression graphs.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/formats-inventory.json,
}: let
  packages = {
    aos-nar = "crates/artifacts/aos-nar";
    aos-module-format = "crates/modules/aos-module-format";
    aos-registry-format = "crates/registry/aos-registry-format";
  };
  dependencyPackages = {
    aos-core = "crates/core/aos-core";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-oci-types = "crates/artifacts/aos-oci-types";
  };
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = compression:
    import ./_bazel-rust-family.nix {
      inherit pkgs packages dependencyPackages sourceInventory rustcFlags;
      pname = "aos-bazel-formats${pkgs.lib.optionalString compression "-compression"}";
      dependencyProfile = "formats";
      repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.formats // {aos_native = pkgs.aosBazelStoreLibraries;};
      extraSourceDirectories = builtins.attrValues dependencyPackages;
      nativeLibraries = [pkgs.zstdStaticMultithread];
      nativeTools = [pkgs.pkg-config];
      cargoSetup = ''
        export ZSTD_SYS_USE_PKG_CONFIG=1
      '';
      cargoFlags = pkgs.lib.optionals compression ["--features" "aos-nar/compression"];
      packageTargets =
        builtins.mapAttrs (name: _: let
          suffix = pkgs.lib.optionalString compression "_compression";
        in {
          root = "lib${suffix}";
          unit = "unit${suffix}";
          doctest = "doc${suffix}";
          license = "license_closure${suffix}";
        })
        packages;
      targetSuffix = pkgs.lib.optionalString compression "_compression";
      editorComparisonScope = "selected-packages";
      editorRustcFlags = rustcFlags;
      editorDiagnosticContext = true;
    };
  default = family false;
in
  default
  // rec {
    compression = family true;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-formats-inventory";
      workspace = default.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (name:
          map (target: "//${packages.${name}}:${target}") ["unit" "doc" "license_closure" "clippy" "documentation" "format"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (path: map (target: "//${path}:${target}_compression") ["unit" "doc" "license_closure"]) (builtins.attrValues packages);
    };
    all =
      pkgs.runCommand "aos-bazel-formats-qualified-checks" {
        buildDeps = [default.all default.editor-parity compression.all];
      } ''
        mkdir -p "$out/default" "$out/compression"
        cp -r ${default.all}/. "$out/default/"
        cp ${default.editor-parity}/parity.json "$out/default/editor-parity.json"
        cp -r ${compression.all}/. "$out/compression/"
      '';
  }
