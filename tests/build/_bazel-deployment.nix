##! Qualifies authenticated deployment evaluation, retention and activation.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/deployment-inventory.json,
}: let
  packages = {
    aos-deployment = "crates/packages/aos-deployment";
  };
  dependencyPackages = {
    aos-activation = "crates/activation/aos-activation";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-core = "crates/core/aos-core";
    aos-deployment-format = "crates/packages/aos-deployment-format";
    aos-module-docs = "crates/modules/aos-module-docs";
    aos-module-format = "crates/modules/aos-module-format";
    aos-nar = "crates/artifacts/aos-nar";
    aos-nix = "crates/nix/aos-nix";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-release-format = "crates/release/aos-release-format";
  };
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.deployment
    // {
      aos_nix_test_tools = pkgs.aosBazelNixTestTools;
    };
  nativeTools = [pkgs.nix];
  cargoSetup = ''
    export AOS_NIX_STORE="${pkgs.nix}/bin/nix-store"
  '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags repositories nativeTools cargoSetup;
    pname = "aos-bazel-deployment";
    dependencyProfile = "deployment";
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = pkgs.lib.concatMap (path:
    map (target: "//${path}:${target}") ["lib" "production_license_closure"])
  (builtins.attrValues packages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags repositories;
    dependencyProfile = "deployment";
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
      pname = "aos-bazel-deployment-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "unit" "doc" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ productionTargets
        # This dependency's BUILD evaluates an integration-test glob even when
        # only its library is compiled. Retain that declaration's source inputs.
        ++ [
          "//crates/release/aos-release-format:qualification"
          "//crates/release/aos-release-format:nix_inventory"
        ];
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-deployment-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-deployment-production-cargo";
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
        name = "aos-deployment-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-deployment-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    all =
      pkgs.runCommand "aos-bazel-deployment-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
      '';
  }
