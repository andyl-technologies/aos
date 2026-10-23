##! Qualifies filesystem, Nix-store and storage activation providers.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/activation-storage-inventory.json,
}: let
  packages = {
    aos-activation-filesystem = "crates/aos/activation/aos-activation-filesystem";
    aos-activation-nix-store = "crates/aos/activation/aos-activation-nix-store";
    aos-activation-storage = "crates/aos/activation/aos-activation-storage";
  };
  dependencyPackages = {
    aos-core = "crates/shared/aos-core";
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-activation = "crates/aos/activation/aos-activation";
    aos-storage-layout = "crates/aos/boot/aos-storage-layout";
  };
  commands = {
    aos-activation-filesystem = ["aos-filesystem-provider"];
    aos-activation-nix-store = ["aos-nix-store-provider"];
    aos-activation-storage = [
      "aos-cryptsetup-provider"
      "aos-storage-format-provider"
      "aos-zfs-pool-provider"
      "aos-zfs-dataset-provider"
      "aos-zfs-memory-policy"
      "aos-zfs-maintenance"
      "aos-storage-provisioning-provider"
      "aos-storage-provisioning-marker-observer"
      "aos-boot-transaction-storage-provider"
    ];
  };
  commandTargets = targetName:
    pkgs.lib.concatMap (name:
      map (command: "//${packages.${name}}:${targetName command}") commands.${name})
    (builtins.attrNames commands);

  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags;
    pname = "aos-bazel-activation-storage";
    dependencyProfile = "activation-storage";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-storage;
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    extraTests = commandTargets (command: "bin_${command}");
    extraEditorTargets =
      commandTargets (command: command)
      ++ commandTargets (command: "bin_${command}_binary");
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets =
    pkgs.lib.concatMap (path:
      map (target: "//${path}:${target}") ["lib" "production_license_closure"])
    (builtins.attrValues packages)
    ++ commandTargets (command: command);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    dependencyProfile = "activation-storage";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-storage;
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
    analysisTargets = productionTargets;
  };
in
  family
  // rec {
    inherit packages dependencyPackages commands productionWorkspace;
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-activation-storage-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-activation-storage-production-cargo";
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
            cargo build --frozen --offline --manifest-path crates/Cargo.toml --lib --bins \
              ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) (builtins.attrNames packages))} \
              --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-activation-storage-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"]) (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-activation-storage-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-activation-storage-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["unit" "doc" "license_closure" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ commandTargets (command: "bin_${command}");
    };
    all =
      pkgs.runCommand "aos-bazel-activation-storage-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
      '';
  }
