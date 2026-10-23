##! Qualifies generated build APIs, their typed client and the build server.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/build-services-inventory.json,
}: let
  packages = {
    aos-build-api = "crates/aos/packages/aos-build-api";
    aos-build-client = "crates/aos/packages/aos-build-client";
    aos-build-server = "crates/aos/packages/aos-build-server";
  };
  dependencyPackages = {
    aos-core = "crates/shared/aos-core";
    aos-nar = "crates/shared/aos-nar";
    aos-nix = "crates/shared/aos-nix";
  };
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.build-services
    // {
      aos_native = pkgs.aosBazelStoreLibraries;
      aos_codegen = pkgs.aosBazelCodegenTools;
    };
  cargoSource = import ../../pkgs/tools/crucible/_cargo-source.nix {
    inherit (pkgs) lib;
    extraPaths = [
      "api/proto/aos/auth/v1/auth.proto"
      "api/proto/aos/build/v1/build.proto"
      "api/proto/aos/cache/v1/cache.proto"
      "api/proto/aos/gc/v1/gc.proto"
    ];
  };
  nativeLibraries = [pkgs.sqlite pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config pkgs.protobuf];
  cargoSetup = ''
    export PROTOC="${pkgs.protobuf}/bin/protoc"
    export PROTOC_INCLUDE="${pkgs.protobuf}/include"
  '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories cargoSource nativeLibraries nativeTools cargoSetup;
    pname = "aos-bazel-build-services";
    dependencyProfile = "build-services";
    extraSourceDirectories = builtins.attrValues dependencyPackages ++ ["api/proto"];
    emptyTests = [
      "//crates/aos/packages/aos-build-api:unit"
      "//crates/aos/packages/aos-build-client:unit"
    ];
    extraEditorTargets = ["//crates/aos/packages/aos-build-api:build_script_program"];
    generatedDoctests.aos-build-api = "build_script.out_dir";
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets =
    pkgs.lib.concatMap (path:
      map (target: "//${path}:${target}") ["lib" "production_license_closure"])
    (builtins.attrValues packages)
    ++ ["//crates/aos/packages/aos-build-api:generated_sources_evidence"];
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags repositories;
    dependencyProfile = "build-services";
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
      pname = "aos-bazel-build-services-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "unit" "doc" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ [
          "//crates/aos/packages/aos-build-api:decode_limits"
          "//crates/aos/packages/aos-build-server:rpc_roundtrip"
          "//crates/aos/packages/aos-build-api:build_script_program"
          "//crates/aos/packages/aos-build-api:generated_sources_evidence"
        ]
        ++ productionTargets;
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-build-services-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-build-services-production-cargo";
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
                          and event["manifest_path"].endswith("/crates/aos/packages/aos-build-api/Cargo.toml")}
            scripts = [event for event in events
                       if event.get("reason") == "build-script-executed"
                       and event["package_id"] in identities]
            if len(identities) != 1 or len(scripts) != 1:
                raise ValueError("build API must have exactly one Cargo generator output")
            shutil.copytree(scripts[0]["out_dir"], output / "generated-api")
            PYTHON
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-build-services-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-build-services-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    generated-source-parity = pkgs.runCommand "aos-bazel-build-services-generated-source-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      cp ${../../tools/bazel/metadata/snapshot_generated_sources.py} snapshot_generated_sources.py
      ${pkgs.python3}/bin/python3 - ${production}/packages ${production-cargo}/generated-api "$out/parity.json" <<'PYTHON'
      import json
      from pathlib import Path
      import sys

      from snapshot_generated_sources import snapshot

      packages, cargo, output = map(Path, sys.argv[1:])
      index = json.loads((packages / "index.json").read_text())
      label = "//crates/aos/packages/aos-build-api:generated_sources_evidence"
      bazel = json.loads((packages / index[label] / "files/generated-api.json").read_text())
      expected = ["_connectrpc.rs"] + [
          "aos." + service + ".v1." + filename + ".rs"
          for service in ["auth", "build", "cache", "gc"]
          for filename in ["mod", service, service + ".__connect", service + ".__view"]
      ]
      actual = snapshot(cargo, expected)
      if bazel != actual:
          raise ValueError("Bazel/Cargo generated API inventories or source bytes differ")
      output.write_text(json.dumps({"files": actual, "status": "PASS", "count": len(actual)}, indent=2, sort_keys=True) + "\n")
      PYTHON
    '';
    all =
      pkgs.runCommand "aos-bazel-build-services-qualified-checks" {
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
