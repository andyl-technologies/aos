##! Qualifies native console outputs, tests, generated protocol and editor diagnostics.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/hub-console-inventory.json,
}: let
  packages = {
    aos-hub-console = "crates/hub/aos-hub-console";
  };
  dependencyPackages = {
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-core = "crates/shared/aos-core";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-ui = "crates/hub/aos-hub-ui";
    aos-module-docs = "crates/aos/modules/aos-module-docs";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
  };
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.hub-console
    // {
      aos_codegen = pkgs.aosBazelCodegenTools;
    };
  contractSourceDirectories = ["api/proto"] ++ builtins.attrValues dependencyPackages;
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
    inherit (pkgs) lib;
    extraPaths = ["api/proto/aos/hub/v1/hub.proto" "crates/hub/aos-hub-console/assets/app.css"];
  };
  nativeLibraries = [];
  nativeTools = [pkgs.pkg-config pkgs.protobuf];
  cargoSetup = ''
    export PROTOC="${pkgs.protobuf}/bin/protoc"
    export PROTOC_INCLUDE="${pkgs.protobuf}/include"
  '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories cargoSource nativeLibraries nativeTools cargoSetup;
    pname = "aos-bazel-hub-console";
    dependencyProfile = "hub-console";
    extraSourceDirectories = contractSourceDirectories;
    extraTests = ["//crates/hub/aos-hub-console:bin_aos-hub-console"];
    emptyTests = ["//crates/hub/aos-hub-console:bin_aos-hub-console"];
    extraEditorTargets = ["//crates/hub/aos-hub-api:build_script_program" "//crates/hub/aos-hub-console:aos-hub-console" "//crates/hub/aos-hub-console:bin_aos-hub-console_binary"];
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets =
    pkgs.lib.concatMap (path:
      map (target: "//${path}:${target}") ["lib" "shared" "aos-hub-console" "production_license_closure"])
    (builtins.attrValues packages)
    ++ ["//crates/hub/aos-hub-api:generated_sources_evidence"];
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags repositories;
    dependencyProfile = "hub-console";
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
      pname = "aos-bazel-hub-console-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "unit" "doc" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ [
          "//crates/hub/aos-hub-api:build_script_program"
          "//crates/hub/aos-hub-api:generated_sources_evidence"
        ]
        ++ map (path: "//${path}:source_package") (builtins.attrValues dependencyPackages)
        ++ ["//crates/hub/aos-hub-console:bin_aos-hub-console"]
        ++ productionTargets;
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-hub-console-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-hub-console-production-cargo";
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
            cargo build --frozen --offline --manifest-path crates/Cargo.toml --lib --bin aos-hub-console \
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
        name = "aos-hub-console-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-hub-console-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    generated-source-parity = pkgs.runCommand "aos-bazel-hub-console-generated-source-parity" {buildDeps = [pkgs.python3];} ''
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
    all =
      pkgs.runCommand "aos-bazel-hub-console-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity generated-source-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
        cp ${generated-source-parity}/parity.json "$out/generated-source-parity.json"
      '';
  }
