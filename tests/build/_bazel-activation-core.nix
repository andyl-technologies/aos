##! Qualifies activation libraries and their stable installed command names.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/activation-core-inventory.json,
}: let
  packages = {
    aos-activation = "crates/aos/activation/aos-activation";
    aos-activation-config-files = "crates/aos/activation/aos-activation-config-files";
    aos-activation-sysctl = "crates/aos/activation/aos-activation-sysctl";
    aos-activation-bpf-lsm = "crates/aos/activation/aos-activation-bpf-lsm";
    aos-activation-bpf-network = "crates/aos/activation/aos-activation-bpf-network";
    aos-activation-kubernetes = "crates/aos/activation/aos-activation-kubernetes";
    aos-activation-nftables = "crates/aos/activation/aos-activation-nftables";
  };
  dependencyPackages = {
    aos-core = "crates/shared/aos-core";
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-module-format = "crates/aos/modules/aos-module-format";
  };
  commands = {
    aos-activation-config-files = "aos-configuration-provider";
    aos-activation-sysctl = "aos-kernel-tunable-provider";
    aos-activation-bpf-lsm = "aos-ebpf-lsm-provider";
    aos-activation-bpf-network = "aos-ebpf-net-policy-provider";
    aos-activation-kubernetes = "aos-kubernetes-provider";
    aos-activation-nftables = "aos-network-ruleset-provider";
  };
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags;
    pname = "aos-bazel-activation-core";
    dependencyProfile = "activation-core-tests";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-core-tests;
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    extraTests = map (name: "//${packages.${name}}:bin_${commands.${name}}") (builtins.attrNames commands);
    extraEditorTargets = pkgs.lib.concatMap (name: [
      "//${packages.${name}}:${commands.${name}}"
      "//${packages.${name}}:bin_${commands.${name}}_binary"
    ]) (builtins.attrNames commands);
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = pkgs.lib.concatMap (name:
    ["//${packages.${name}}:lib" "//${packages.${name}}:production_license_closure"]
    ++ pkgs.lib.optional (builtins.hasAttr name commands) "//${packages.${name}}:${commands.${name}}")
  (builtins.attrNames packages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    dependencyProfile = "activation-core";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-core;
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
      pname = "aos-bazel-activation-core-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-activation-core-production-cargo";
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
        name = "aos-activation-core-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"]) (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-activation-core-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-activation-core-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["unit" "doc" "license_closure" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ map (name: "//${packages.${name}}:bin_${commands.${name}}") (builtins.attrNames commands);
    };
    all =
      pkgs.runCommand "aos-bazel-activation-core-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
      '';
  }
