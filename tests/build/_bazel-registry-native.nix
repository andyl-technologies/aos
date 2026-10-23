##! Qualifies native registry acquisition, authoring and Nix cache libraries.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/registry-native-inventory.json,
}: let
  packages = {
    aos-nix-cache = "crates/aos/packages/aos-nix-cache";
    aos-registry-authoring = "crates/aos/registry/aos-registry-authoring";
    aos-registry-client = "crates/aos/registry/aos-registry-client";
  };
  dependencyPackages = {
    aos-activation = "crates/aos/activation/aos-activation";
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-cli-ui = "crates/aos/cli/aos-cli-ui";
    aos-core = "crates/shared/aos-core";
    aos-deployment = "crates/aos/packages/aos-deployment";
    aos-deployment-format = "crates/aos/packages/aos-deployment-format";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-client = "crates/hub/aos-hub-client";
    aos-module-docs = "crates/aos/modules/aos-module-docs";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-nar = "crates/shared/aos-nar";
    aos-nix = "crates/shared/aos-nix";
    aos-oci = "crates/shared/aos-oci";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
    aos-release-format = "crates/aos/release/aos-release-format";
    aos-transfer = "crates/shared/aos-transfer";
  };
  inputs = import ./_bazel-registry-native-inputs.nix {inherit pkgs;};
  repositories = profile:
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.${profile}
    // {
      aos_codegen = pkgs.aosBazelCodegenTools;
      aos_native = pkgs.aosBazelNativeFoundationLibraries;
      aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
      aos_registry_runtime = pkgs.aosBazelRegistryTestTools;
    };
  contractSourceDirectories = ["api/proto" "crates/hub/aos-hub-native"] ++ builtins.attrValues dependencyPackages;
  inherit (inputs) cargoSource nativeLibraries nativeTools cargoSetup;
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags cargoSource nativeLibraries nativeTools cargoSetup;
    pname = "aos-bazel-registry-native";
    repositories = repositories "registry-native-tests";
    dependencyProfile = "registry-native-tests";
    extraSourceDirectories = contractSourceDirectories;
    extraEditorTargets = ["//crates/hub/aos-hub-api:build_script_program"];
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets =
    pkgs.lib.concatMap (path:
      map (target: "//${path}:${target}") ["lib" "production_license_closure"])
    (builtins.attrValues packages)
    ++ ["//crates/hub/aos-hub-api:generated_sources_evidence"];
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    repositories = repositories "registry-native";
    dependencyProfile = "registry-native";
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ contractSourceDirectories);
    analysisTargets = productionTargets;
  };
in
  family
  // rec {
    inherit packages dependencyPackages productionWorkspace;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-registry-native-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "unit" "doc" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ [
          "//crates/hub/aos-hub-api:build_script_program"
          "//crates/hub/aos-hub-api:generated_sources_evidence"
          # These dependency packages declare nonempty integration-test globs.
          # Retain their discovery roots even when only their libraries compile.
          "//crates/shared/aos-oci:source_package"
          "//crates/aos/release/aos-release-format:source_package"
        ]
        ++ pkgs.lib.concatMap (name:
          map (file: "//${packages.${name}}:${file}")
          (
            if name == "aos-registry-authoring"
            then ["change_requests" "registry_default_channel" "registry_e2e" "registry_perf" "registry_pki_e2e"]
            else if name == "aos-nix-cache"
            then ["backend_matrix" "conditional_writes"]
            else []
          ))
        (builtins.attrNames packages)
        ++ productionTargets;
    };
    production-inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-registry-native-production-inventory";
      workspace = productionWorkspace;
      inventoryOnly = true;
      targets = productionTargets;
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-registry-native-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-registry-native-production-cargo";
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
              --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
            ${pkgs.python3}/bin/python3 - "$out" <<'PYTHON'
            import json
            from pathlib import Path
            import shutil
            import sys

            output = Path(sys.argv[1])
            events = [json.loads(line) for line in (output / "cargo-messages.jsonl").read_text().splitlines()]
            identities = {event["package_id"] for event in events
                          if event.get("reason") == "compiler-artifact"
                          and event["manifest_path"].endswith("/crates/hub/aos-hub-api/Cargo.toml")}
            scripts = [event for event in events
                       if event.get("reason") == "build-script-executed"
                       and event["package_id"] in identities]
            if len(identities) != 1 or len(scripts) != 1:
                raise ValueError("Hub API must have exactly one Cargo generator output")
            shutil.copytree(scripts[0]["out_dir"], output / "generated-api")
            PYTHON
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-registry-native-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-registry-native-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    generated-source-parity = pkgs.runCommand "aos-bazel-registry-native-generated-source-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      cp ${../../tools/bazel/metadata/snapshot_generated_sources.py} snapshot_generated_sources.py
      ${pkgs.python3}/bin/python3 - ${production}/packages ${production-cargo}/generated-api "$out/parity.json" <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      from snapshot_generated_sources import snapshot

      packages, cargo, output = map(Path, sys.argv[1:])
      index = json.loads((packages / "index.json").read_text())
      label = "//crates/hub/aos-hub-api:generated_sources_evidence"
      bazel = json.loads((packages / index[label] / "files/generated-api.json").read_text())
      expected = [
          "aos.hub.v1.rs", "aos.hub.v1.serde.rs",
          "aos.hub.v1.descriptor.bin", "connect_paths.rs",
      ]
      actual = snapshot(cargo, expected)
      if bazel != actual:
          raise ValueError("Bazel/Cargo generated API inventories or source bytes differ")
      output.write_text(json.dumps({"files": actual, "status": "PASS", "count": len(actual)}, indent=2, sort_keys=True) + "\n")
      PYTHON
    '';
    build-script-metadata = import ./_bazel-build-script-metadata.nix {inherit pkgs;};
    stage-preview-lock = import ./_bazel-stage-preview-lock.nix {
      inherit pkgs;
      workspace = family.workspace;
    };
    all =
      pkgs.runCommand "aos-bazel-registry-native-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity generated-source-parity build-script-metadata stage-preview-lock];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
        cp ${generated-source-parity}/parity.json "$out/generated-source-parity.json"
        cp ${build-script-metadata}/report.json "$out/build-script-metadata.json"
        cp ${stage-preview-lock}/report.json "$out/stage-preview-lock.json"
      '';
  }
