##! Qualifies maintenance policy, final-byte image assembly and file-backed signing.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/release-preparation-inventory.json,
}: let
  packages = {
    aos-image-finalizer = "crates/release/aos-image-finalizer";
    aos-package-maintenance = "crates/release/aos-package-maintenance";
    aos-release-signer = "crates/release/aos-release-signer";
  };
  dependencyPackages = {
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-boot-identity = "crates/boot/aos-boot-identity";
    aos-core = "crates/core/aos-core";
    aos-deployment-format = "crates/packages/aos-deployment-format";
    aos-module-docs = "crates/modules/aos-module-docs";
    aos-module-format = "crates/modules/aos-module-format";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-release-format = "crates/release/aos-release-format";
  };
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags;
    pname = "aos-bazel-release-preparation";
    packageTargets = {
      aos-package-maintenance = {
        root = "lib";
        unit = "unit";
        doctest = "doc";
      };
      aos-image-finalizer = {
        root = "lib";
        unit = "unit";
        doctest = "doc";
      };
      aos-release-signer = {
        root = "aos-release-signer";
        unit = "bin_aos-release-signer";
        doctest = null;
      };
    };
    extraTests = ["//crates/release/aos-image-finalizer:bin_aos-image-metadata"];
    extraEditorTargets = [
      "//crates/release/aos-image-finalizer:aos-image-metadata"
      "//crates/release/aos-image-finalizer:bin_aos-image-metadata_binary"
    ];
    dependencyProfile = "release-preparation";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.release-preparation;
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = pkgs.lib.concatMap (name:
    map (target: "//${packages.${name}}:${target}")
    ((
        if name == "aos-release-signer"
        then ["aos-release-signer"]
        else ["lib"]
      )
      ++ pkgs.lib.optional (name == "aos-image-finalizer") "aos-image-metadata"
      ++ ["production_license_closure"]))
  (builtins.attrNames packages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    dependencyProfile = "release-preparation";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.release-preparation;
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
      pname = "aos-bazel-release-preparation-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (name:
          map (target: "//${packages.${name}}:${target}")
          (["license_closure" "clippy" "documentation" "format"]
            ++ (
              if name == "aos-release-signer"
              then ["bin_aos-release-signer"]
              else ["unit" "doc"]
            )))
        (builtins.attrNames packages)
        ++ [
          "//crates/release/aos-image-finalizer:bin_aos-image-metadata"
          # Preserve the dependency package's nonempty integration-source glob
          # when its BUILD file loads in the strict compilation workspace.
          "//crates/release/aos-release-format:qualification_binary"
        ]
        ++ productionTargets;
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-release-preparation-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-release-preparation-production-cargo";
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
            cargo build --frozen --offline --manifest-path crates/Cargo.toml \
              ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) (builtins.attrNames packages))} \
              --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-release-preparation-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-release-preparation-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    all =
      pkgs.runCommand "aos-bazel-release-preparation-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
      '';
  }
