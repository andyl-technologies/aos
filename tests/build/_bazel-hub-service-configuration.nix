##! Qualifies one native Hub service feature configuration and its dependency units.
{
  pkgs,
  allFeatures ? false,
  sourceInventory ? ../../tools/bazel/metadata/hub-service-inventory.json,
}: let
  packages = {
    aos-hub-service = "crates/hub/aos-hub-service";
  };
  dependencyPackages = {
    libssh2-sys = "crates/bindings/libssh2-sys";
    aos-activation = "crates/activation/aos-activation";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-cli-ui = "crates/cli/aos-cli-ui";
    aos-core = "crates/core/aos-core";
    aos-deployment = "crates/packages/aos-deployment";
    aos-deployment-format = "crates/packages/aos-deployment-format";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-client = "crates/hub/aos-hub-client";
    aos-hub-db = "crates/hub/aos-hub-db";
    aos-hub-model = "crates/hub/aos-hub-model";
    aos-hub-ui = "crates/hub/aos-hub-ui";
    aos-module-docs = "crates/modules/aos-module-docs";
    aos-module-format = "crates/modules/aos-module-format";
    aos-nar = "crates/artifacts/aos-nar";
    aos-nix = "crates/nix/aos-nix";
    aos-nix-cache = "crates/packages/aos-nix-cache";
    aos-oci = "crates/artifacts/aos-oci";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-registry-authoring = "crates/registry/aos-registry-authoring";
    aos-registry-client = "crates/registry/aos-registry-client";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-release-format = "crates/release/aos-release-format";
    aos-transfer = "crates/transfer/aos-transfer";
  };
  profile = "hub-service" + pkgs.lib.optionalString allFeatures "-all-features";
  cargoFlags = pkgs.lib.optional allFeatures "--all-features";
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories."${profile}-tests"
    // {
      aos_native = pkgs.aosBazelHubServiceLibraries;
      aos_codegen = pkgs.aosBazelCodegenTools;
      aos_console_assets = pkgs.aosBazelConsoleAssets;
      aos_registry_runtime = pkgs.aosBazelRegistryTestTools;
      aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
    };
  productionRepositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.${profile}
    // {
      aos_native = pkgs.aosBazelStoreLibraries;
      aos_codegen = pkgs.aosBazelCodegenTools;
      aos_console_assets = pkgs.aosBazelConsoleAssets;
    };
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
    inherit (pkgs) lib;
    extraPaths = ["api/proto/aos/hub/v1/hub.proto"];
  };
  nativeLibraries = [pkgs.openssl pkgs.sqlite pkgs.zstdStaticMultithread pkgs.libssh2 pkgs.zlib];
  nativeTools = [pkgs.pkg-config pkgs.protobuf pkgs.git-minimal pkgs.openssh pkgs.nix pkgs.cmake pkgs.perl pkgs.zstd pkgs.which];
  cargoSetup = ''
    export AOS_LIBSSH2_PREFIX="${pkgs.libssh2}"
    export OPENSSL_DIR=${pkgs.openssl} OPENSSL_NO_VENDOR=1
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
    export PROTOC="${pkgs.protobuf}/bin/protoc" PROTOC_INCLUDE="${pkgs.protobuf}/include"
    export AOS_HUB_CONSOLE_JS="${pkgs.aosBazelConsoleAssets}/hub-console.js"
    export AOS_HUB_CONSOLE_WASM="${pkgs.aosBazelConsoleAssets}/hub-console_bg.wasm"
    export AOS_HUB_CONSOLE_CSS="${pkgs.aosBazelConsoleAssets}/hub-console.css"
    export AOS_NIX_STORE="${pkgs.nix}/bin/nix-store" AOS_NIX_INSTANTIATE="${pkgs.nix}/bin/nix-instantiate"
    # The retained Cargo oracle and Bazel runner share a bounded outer budget;
    # concurrency exercised inside each case remains unchanged.
    export RUST_TEST_THREADS="$NIX_BUILD_CORES"
  '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories nativeLibraries nativeTools cargoSetup cargoSource cargoFlags;
    pname = "aos-bazel-${profile}";
    dependencyProfile = "${profile}-tests";
    extraSourceDirectories = ["api/proto"] ++ builtins.attrValues dependencyPackages;
    extraEditorTargets = ["//crates/hub/aos-hub-service:build_script_program" "//crates/hub/aos-hub-api:build_script_program"];
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorCargoFlags = cargoFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = pkgs.lib.concatMap (path:
    map (target: "//${path}:${target}") ["lib" "build_script_program" "production_license_closure" "generated_assets_evidence"])
  (builtins.attrValues packages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    repositories = productionRepositories;
    dependencyProfile = profile;
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust" "api/proto"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
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
          map (target: "//${path}:${target}") ["license_closure" "unit" "signing_key_lifecycle" "wasm_clock_guard" "doc" "clippy" "documentation" "format" "build_script_program"])
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
      buildDeps = [pkgs.rust pkgs.sed pkgs.python3] ++ nativeTools;
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
            ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
            import json
            from pathlib import Path
            import sys

            output = Path(sys.argv[1])
            directories = []
            for line in (output / "cargo-messages.jsonl").read_text().splitlines():
                event = json.loads(line)
                if (event.get("reason") == "build-script-executed"
                        and "/aos-hub-service#" in event["package_id"]):
                    directories.append(Path(event["out_dir"]))
            if len(directories) != 1:
                raise ValueError("Cargo must execute exactly one service asset generator")
            expected = {"hub-console.js", "hub-console_bg.wasm", "hub-console.css"}
            actual = {path.name for path in directories[0].iterdir()}
            if actual != expected:
                raise ValueError("Cargo service generator produced an unexpected asset inventory")
            destination = output / "generated-assets"
            destination.mkdir()
            for name in sorted(expected):
                (destination / name).write_bytes((directories[0] / name).read_bytes())
            PYTHON
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-hub-service-feature-parity-tools";
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
    generated-asset-parity = pkgs.runCommand "aos-bazel-${profile}-generated-asset-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      cp ${../../tools/bazel/metadata/snapshot_generated_sources.py} snapshot_generated_sources.py
      ${pkgs.python3}/bin/python3 - ${production}/packages ${production-cargo}/generated-assets ${pkgs.aosBazelConsoleAssets} "$out/parity.json" <<'PYTHON'
      import hashlib
      import json
      from pathlib import Path
      import sys

      from snapshot_generated_sources import snapshot

      packages, cargo, declared, output = map(Path, sys.argv[1:])
      index = json.loads((packages / "index.json").read_text())
      label = "//crates/hub/aos-hub-service:generated_assets_evidence"
      actual = json.loads((packages / index[label] / "files/console-assets.json").read_text())
      expected = ["hub-console.js", "hub-console_bg.wasm", "hub-console.css"]
      original = snapshot(cargo, expected)
      inputs = {
          name: {"sha256": hashlib.sha256((declared / name).read_bytes()).hexdigest(),
                 "size": (declared / name).stat().st_size}
          for name in expected
      }
      if actual != original or actual != inputs:
          raise ValueError("Bazel/Cargo service assets differ from their declared browser package")
      output.write_text(json.dumps({"status": "PASS", "count": 3, "files": actual}, indent=2, sort_keys=True) + "\n")
      PYTHON
    '';
    all =
      pkgs.runCommand "aos-bazel-${profile}-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity generated-asset-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
        cp ${generated-asset-parity}/parity.json "$out/generated-asset-parity.json"
      '';
  }
