##! Qualifies one native Hub database feature configuration and its dependency units.
{
  pkgs,
  allFeatures ? false,
  sourceInventory ? ../../tools/bazel/metadata/hub-db-inventory.json,
}: let
  packages = {
    aos-hub-db = "crates/hub/aos-hub-db";
  };
  dependencyPackages = {
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-core = "crates/shared/aos-core";
    aos-hub-model = "crates/hub/aos-hub-model";
    aos-module-docs = "crates/aos/modules/aos-module-docs";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
    aos-release-format = "crates/aos/release/aos-release-format";
  };
  profile = "hub-db" + pkgs.lib.optionalString allFeatures "-all-features";
  cargoFlags = pkgs.lib.optional allFeatures "--all-features";
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories."${profile}-tests"
    // {
      aos_native = pkgs.aosBazelStoreLibraries;
    };
  productionRepositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.${profile}
    // {
      aos_native = pkgs.aosBazelStoreLibraries;
    };
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
  nativeLibraries = [pkgs.openssl pkgs.sqlite pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config];
  cargoSetup = ''
    export OPENSSL_DIR=${pkgs.openssl} OPENSSL_NO_VENDOR=1
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
    # The retained Cargo oracle and Bazel runner share a bounded outer budget;
    # concurrency exercised inside each case remains unchanged.
    export RUST_TEST_THREADS="$NIX_BUILD_CORES"
  '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories nativeLibraries nativeTools cargoSetup cargoSource cargoFlags;
    pname = "aos-bazel-${profile}";
    dependencyProfile = "${profile}-tests";
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    # Cargo discovers the model's API dev dependency as an automatic member.
    # It remains outside the selected database editor targets.
    editorDependencyPackages = dependencyPackages // {aos-hub-api = "crates/hub/aos-hub-api";};
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorCargoFlags = cargoFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = pkgs.lib.concatMap (path:
    map (target: "//${path}:${target}") ["lib" "production_license_closure"])
  (builtins.attrValues packages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    repositories = productionRepositories;
    dependencyProfile = profile;
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
    analysisTargets = productionTargets;
  };
in
  family
  // rec {
    inherit packages dependencyPackages productionWorkspace;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-${profile}-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "unit" "doc" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ map (path: "//${path}:source_package") (builtins.attrValues dependencyPackages);
    };
    production-inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-${profile}-production-inventory";
      workspace = productionWorkspace;
      inventoryOnly = true;
      targets = productionTargets;
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-${profile}-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-${profile}-production-cargo";
      version = "1";
      src = cargoSource;
      buildDeps = [pkgs.rust pkgs.sed] ++ nativeTools;
      runtimeDeps = nativeLibraries;
      sharedBuildCache = false;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;
      phases = [
        {
          name = "compile";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
            export CARGO_HOME="$TMPDIR/cargo" CARGO_TARGET_DIR="$TMPDIR/target"
            mkdir -p "$CARGO_HOME" .cargo "$out"
            sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
              ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
            ${cargoSetup}
            cargo build --frozen --offline --manifest-path crates/Cargo.toml --lib \
              ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) (builtins.attrNames packages))} \
              ${pkgs.lib.escapeShellArgs cargoFlags} \
              --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-hub-db-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-${profile}-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    all =
      pkgs.runCommand "aos-bazel-${profile}-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
      '';
  }
