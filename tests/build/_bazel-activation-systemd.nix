##! Qualifies systemd commands and their source-built native parser fixtures.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/activation-systemd-inventory.json,
}: let
  packagePath = "crates/aos/activation/aos-activation-systemd";
  packages = {aos-activation-systemd = packagePath;};
  dependencyPackages = {
    aos-core = "crates/shared/aos-core";
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-activation = "crates/aos/activation/aos-activation";
    aos-nar = "crates/shared/aos-nar";
    aos-nix = "crates/shared/aos-nix";
    aos-systemd-client = "crates/shared/aos-systemd-client";
  };
  commands = ["aos-systemd-native-resource-provider" "aos-systemd-credential-encrypt"];
  commandTargets = targetName: map (command: "//${packagePath}:${targetName command}") commands;
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags;
    pname = "aos-bazel-activation-systemd";
    dependencyProfile = "activation-systemd";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-systemd;
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    packageTargets.aos-activation-systemd = {
      root = "aos-systemd-native-resource-provider";
      unit = "bin_aos-systemd-native-resource-provider";
      doctest = null;
    };
    extraTests = ["//${packagePath}:bin_aos-systemd-credential-encrypt"];
    extraEditorTargets =
      commandTargets (command: command)
      ++ commandTargets (command: "bin_${command}_binary");
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
  };
  productionTargets = ["//${packagePath}:production_license_closure"] ++ commandTargets (command: command);
  parserTargets = ["//${packagePath}:parser_test_package" "//${packagePath}:parser_license_closure"];
  parserVerifier = builtins.path {
    path = ../../tools/bazel/tests;
    name = "aos-systemd-parser-parity-tools";
    filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
  };
  parserEnvironment = ''
    export AOS_SYSTEMD_ANALYZE="${pkgs.systemd}/bin/systemd-analyze"
    export AOS_SYSTEMD_UNIT_PATH="${pkgs.systemd}/lib/systemd/system"
    export AOS_SYSTEMD_PARSER_SHELL="${pkgs.bash}/bin/bash"
  '';
  packageOptions =
    pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
    (builtins.attrNames packages)
    ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
    (builtins.attrNames dependencyPackages);
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    dependencyProfile = "activation-systemd";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-systemd;
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
      pname = "aos-bazel-activation-systemd-production";
      workspace = productionWorkspace;
      targets = productionTargets;
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-activation-systemd-production-cargo";
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
            cargo build --frozen --offline --manifest-path crates/Cargo.toml --bins \
              ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["-p" name]) (builtins.attrNames packages))} \
              --jobs "$NIX_BUILD_CORES" --message-format=json > "$out/cargo-messages.jsonl"
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-activation-systemd-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"]) (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
        (builtins.attrNames dependencyPackages);
    in
      pkgs.runCommand "aos-bazel-activation-systemd-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-activation-systemd-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (path:
          map (target: "//${path}:${target}") ["license_closure" "clippy" "documentation" "format"])
        (builtins.attrValues packages)
        ++ commandTargets (command: "bin_${command}")
        # Bazel loads the client's test globs while parsing its library package.
        # Retain their declared sources without selecting dependency test runs.
        ++ ["//crates/shared/aos-systemd-client:source_package"];
    };
    parser-build = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-activation-systemd-parser-artifacts";
      workspace = family.workspace;
      targets = parserTargets;
    };
    parser-package =
      (pkgs.mkAosBazelPackage {
        pname = "aos-activation-systemd";
        version = "0.1.0";
        build = parser-build;
        packageLabel = "//${packagePath}:parser_test_package";
        runtimeDeps = [pkgs.gcc-libs];
      }).overrideAttrs (_: {
        # These are test artifacts, whose synthetic store paths are fixtures.
        # Keep their bytes and compiler runtime references exactly as Bazel built them.
        dontStrip = true;
        dontPatchELF = true;
        dontNukeRefs = true;
      });
    parser-cargo = import ./_bazel-cargo-oracle.nix {
      inherit pkgs;
      pname = "aos-bazel-activation-systemd-parser-cargo";
      packages = builtins.attrNames packages;
      nativeTools = [pkgs.systemd pkgs.bash];
      cargoFlags = ["--features" "aos-activation-systemd/systemd-parser-tests"];
      cargoSetup = parserEnvironment;
    };
    parser-tests =
      pkgs.runCommand "aos-bazel-activation-systemd-parser-tests" {
        buildDeps = [pkgs.python3 pkgs.systemd pkgs.bash];
      } ''
        ${parserEnvironment}
        ${pkgs.python3}/bin/python3 ${../../tools/bazel/tests/run_systemd_parser.py} \
          --artifacts ${parser-package}/libexec \
          --runner ${../../tools/bazel/testing/runner.py} \
          --policy ${../../tools/bazel/testing/policy.json} --output "$out"
      '';
    parser-parity = pkgs.runCommand "aos-bazel-activation-systemd-parser-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 ${parserVerifier}/verify_protocol.py \
        --tests ${parser-tests} --inventory ${parser-build}/inventory.json \
        --messages ${parser-cargo}/cargo-messages.jsonl --cargo-log ${parser-cargo}/cargo-tests.log \
        --output "$out/parity.json" --target-suffix _parser \
        ${pkgs.lib.escapeShellArgs packageOptions}
    '';
    all =
      pkgs.runCommand "aos-bazel-activation-systemd-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity parser-parity];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
        cp ${parser-parity}/parity.json "$out/parser-parity.json"
        cp -r ${parser-tests} "$out/parser-tests"
      '';
  }
