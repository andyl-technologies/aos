##! Qualifies portable Hub domain values and complete retained-control source audits.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/hub-model-inventory.json,
}: let
  packages = {
    aos-hub-model = "crates/hub/aos-hub-model";
  };
  dependencyPackages = {
    aos-core = "crates/shared/aos-core";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
  };
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.hub-model-tests
    // {
      aos_codegen = pkgs.aosBazelCodegenTools;
      aos_hub_model_test_sources = pkgs.aosBazelRepositoryTestSources;
    };
  productionRepositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.hub-model;
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
    inherit (pkgs) lib;
    extraPaths =
      [
        "docs/rfcs/0012-hub-surface-topology/hub-api-manifest-v1.json"
      ]
      ++ pkgs.aosBazelRepositoryTestSources.passthru.productionSourceFiles;
  };
  contractSourceDirectories = ["api/proto" "docs/rfcs/0012-hub-surface-topology"];
  nativeTools = [pkgs.protobuf];
  cargoSetup = ''
    export PROTOC="${pkgs.protobuf}/bin/protoc"
    export PROTOC_INCLUDE="${pkgs.protobuf}/include"
  '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories nativeTools cargoSetup cargoSource;
    pname = "aos-bazel-hub-model";
    dependencyProfile = "hub-model-tests";
    extraSourceDirectories = builtins.attrValues dependencyPackages ++ contractSourceDirectories;
    extraEditorTargets = ["//crates/hub/aos-hub-api:build_script_program"];
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = pkgs.lib.concatMap (path:
    map (target: "//${path}:${target}") ["lib" "production_license_closure"])
  (builtins.attrValues packages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    repositories = productionRepositories;
    dependencyProfile = "hub-model";
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages ++ contractSourceDirectories);
    analysisTargets = productionTargets;
  };
in
  family
  // rec {
    inherit packages dependencyPackages productionWorkspace;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-hub-model-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "unit" "doc" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ [
          "//crates/hub/aos-hub-model:retained_control_foundation"
          "//crates/hub/aos-hub-model:production_source_audit"
          "//crates/hub/aos-hub-api:build_script_program"
        ];
    };
    production-inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-hub-model-production-inventory";
      workspace = productionWorkspace;
      inventoryOnly = true;
      targets = productionTargets;
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-hub-model-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-hub-model-production-cargo";
      version = "1";
      src = cargoSource;
      buildDeps = [pkgs.rust pkgs.sed];
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
            cargo build --frozen --offline --manifest-path crates/Cargo.toml --lib \
              ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) (builtins.attrNames packages))} \
              --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-hub-model-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-hub-model-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    all =
      pkgs.runCommand "aos-bazel-hub-model-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
      '';
  }
