##! Qualifies presentation, closure inspection and Nix documentation libraries.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/cli-support-inventory.json,
}: let
  packages = {
    aos-cli-ui = "crates/cli/aos-cli-ui";
    aos-closure-analysis = "crates/cli/aos-closure-analysis";
    aos-nix-docs = "crates/cli/aos-nix-docs";
  };
  dependencyPackages = {
    aos-core = "crates/core/aos-core";
    aos-nar = "crates/artifacts/aos-nar";
    aos-nix = "crates/nix/aos-nix";
    aos-transfer = "crates/transfer/aos-transfer";
  };
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags execRustcFlags;
    pname = "aos-bazel-cli-support";
    dependencyProfile = "cli-support";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.cli-support;
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    # The editor's global flags also reach its host procedural macros.
    editorExecRustcFlags = rustcFlags;
    retainTestActionGraph = true;
    captureCompilerArguments = true;
    editorDiagnosticContext = true;
  };
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs;
    inherit (family) tests cargo;
    pname = "aos-bazel-cli-support-execution-profiles";
    firstPartyTests = {
      "//crates/cli/aos-cli-ui:unit_binary" = "aos_cli_ui";
      "//crates/cli/aos-closure-analysis:unit_binary" = "aos_closure_analysis";
      "//crates/cli/aos-nix-docs:unit_binary" = "aos_nix_docs";
    };
    proceduralMacros = [
      "curve25519_dalek_derive"
      "darling_macro"
      "derive_more_impl"
      "document_features"
      "indoc"
      "instability"
      "rustversion"
      "serde_derive"
      "strum_macros"
      "thiserror_impl"
      "tokio_macros"
    ];
  };
  productionTargets = pkgs.lib.concatMap (path:
    map (target: "//${path}:${target}") ["lib" "production_license_closure"])
  (builtins.attrValues packages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags execRustcFlags;
    dependencyProfile = "cli-support";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.cli-support;
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
    analysisTargets = productionTargets;
  };
in
  family
  // rec {
    inherit packages dependencyPackages productionWorkspace execution-profiles;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-cli-support-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        productionTargets
        ++ pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "unit" "doc" "clippy" "documentation" "format"])
        (builtins.attrValues packages);
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-cli-support-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-cli-support-production-cargo";
      version = "1";
      src = import ../../pkgs/tools/crucible/_cargo-source.nix {inherit (pkgs) lib;};
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
        name = "aos-cli-support-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-cli-support-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    all =
      pkgs.runCommand "aos-bazel-cli-support-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity execution-profiles];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
        cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
      '';
  }
