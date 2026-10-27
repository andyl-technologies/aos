##! Qualifies the optional static adapter without changing its production builder.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/activation-crucible-inventory.json,
}: let
  packagePath = "crates/activation/aos-activation-crucible";
  label = "//${packagePath}";
  packages.aos-activation-crucible = packagePath;
  productionDependencies = {
    aos-core = "crates/core/aos-core";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-module-format = "crates/modules/aos-module-format";
    aos-activation = "crates/activation/aos-activation";
    crucible-guest = "crates/crucible/crucible-guest";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
  };
  dependencyPackages =
    productionDependencies
    // {
      crucible-engine = "crates/crucible/crucible-engine";
      crucible-determinism = "crates/crucible/crucible-determinism";
      crucible-campaign = "crates/crucible/crucible-campaign";
      crucible-device = "crates/crucible/crucible-device";
      crucible-store = "crates/crucible/crucible-store";
      crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
    };
  triple = pkgs.stdenv.hostPlatform.config;
  targetFlagsVariable = "CARGO_TARGET_${pkgs.lib.toUpper (builtins.replaceStrings ["-"] ["_"] triple)}_RUSTFLAGS";
  rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no" "-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
  editorFlags = ["-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
  staticSetup = libraries: ''
    export CARGO_BUILD_TARGET=${pkgs.lib.escapeShellArg triple}
    export ${targetFlagsVariable}="-C target-feature=+crt-static -C relocation-model=static -L ${libraries}/static/lib"
  '';
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory rustcFlags;
    pname = "aos-bazel-activation-crucible";
    dependencyProfile = "activation-crucible-tests";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-crucible-tests // {aos_native = pkgs.aosBazelGuestLibraries;};
    extraSourceDirectories = builtins.attrValues dependencyPackages;
    extraTests = ["${label}:bin_aos-ability-crucible"];
    extraEditorTargets = ["${label}:aos-ability-crucible" "${label}:bin_aos-ability-crucible_binary"];
    editorComparisonScope = "selected-packages";
    editorDiagnosticContext = true;
    # Native analyzer target queries inherit static flags. Host macros retain
    # their independent development profile and dynamic loading requirements.
    editorTargetRustcFlags = editorFlags;
    editorCfgFlags = editorFlags;
    # The actual native analyzer trace retains full macro debug information.
    # Override opt-mode stripping so that information survives compilation.
    editorExecRustcFlags = ["-Copt-level=0" "-Cdebuginfo=2" "-Cdebug-assertions=yes" "-Coverflow-checks=yes" "-Cstrip=none"];
    retainTestActionGraph = true;
    retainEditorActionGraph = true;
    captureCompilerArguments = true;
    nativeLibraries = [pkgs.sqliteStatic pkgs.zstdStaticMultithread];
    nativeTools = [pkgs.pkg-config];
    cargoFlags = ["--release"];
    cargoSetup =
      staticSetup pkgs.aosBazelGuestLibraries
      + ''
        export SQLITE3_LIB_DIR=${pkgs.sqliteStatic}/lib SQLITE3_INCLUDE_DIR=${pkgs.sqliteStatic}/include SQLITE3_STATIC=1
        export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1 PKG_CONFIG_ALL_STATIC=1
      '';
  };
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs;
    inherit (family) tests cargo;
    pname = "aos-bazel-activation-crucible-execution-profiles";
    targetOptLevel = "3";
    debugAssertions = false;
    firstPartyTests = {
      "${label}:unit_binary" = "aos_activation_crucible";
      "${label}:bin_aos-ability-crucible_binary" = "aos_ability_crucible";
    };
    proceduralMacros = ["curve25519_dalek_derive" "ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl" "tracing_attributes" "zerocopy_derive"];
  };
  editor-builtin-cfg = import ./_bazel-editor-builtin-cfg.nix {
    inherit pkgs;
    inherit (family) editor;
    pname = "aos-bazel-activation-crucible-editor-builtin-cfg";
    cargo = family.editor-cargo-oracle;
    workspace = family.editorWorkspace;
    flags = editorFlags;
  };
  editor-execution-profiles = import ./_bazel-rust-editor-profiles.nix {
    inherit pkgs;
    inherit (family) editor;
    pname = "aos-bazel-activation-crucible-editor-execution-profiles";
    cargo = family.editor-cargo-oracle;
    proceduralMacros = ["curve25519_dalek_derive" "ref_cast_impl" "schemars_derive" "serde_derive" "thiserror_impl" "tracing_attributes" "zerocopy_derive"];
  };
  development = import ./_bazel-activation-crucible-development.nix {
    inherit pkgs packages dependencyPackages editor-builtin-cfg;
    inherit (family) editor tests cargo;
  };
  productionTargets = ["${label}:package" "${label}:production_license_closure"];
  productionLibraries = pkgs.mkAosBazelStaticLibraries {libraries = {};};
  productionWorkspace = pkgs.mkAosBazelWorkspace {
    root = ../..;
    inherit sourceInventory rustcFlags;
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    dependencyProfile = "activation-crucible";
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.activation-crucible // {aos_native = productionLibraries;};
    sourceDirectories =
      pkgs.lib.optionals (sourceInventory == null)
      (["tools/bazel" "third_party/rust"] ++ builtins.attrValues packages ++ builtins.attrValues productionDependencies);
    analysisTargets = productionTargets;
  };
in
  family
  // rec {
    inherit execution-profiles editor-builtin-cfg editor-execution-profiles development;
    inherit packages dependencyPackages productionDependencies productionWorkspace productionLibraries;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-activation-crucible-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets = map (target: "${label}:${target}") ["license_closure" "unit" "bin_aos-ability-crucible" "doc" "clippy" "documentation" "format"];
    };
    production = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-activation-crucible-production";
      workspace = productionWorkspace;
      targets = productionTargets;
      sharedBuildCache = false;
      retainActionGraph = true;
    };
    package = pkgs.mkAosBazelPackage {
      pname = "aos-ability-crucible";
      version = "0.1.0";
      build = production;
      packageLabel = "${label}:package";
    };
    production-cargo = pkgs.mkDerivation {
      pname = "aos-bazel-activation-crucible-production-cargo";
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
            mkdir -p "$CARGO_HOME" .cargo "$out/bin"
            sed 's|@vendor@|${pkgs.aos.passthru.cargoDeps}|g' \
              ${pkgs.aos.passthru.cargoDeps}/.cargo/config.toml > .cargo/config.toml
            ${staticSetup productionLibraries}
            cargo build --release --frozen --offline --manifest-path crates/Cargo.toml --lib --bins \
              -p aos-activation-crucible --jobs "$NIX_BUILD_CORES" \
              --message-format=json > "$out/cargo-messages.jsonl"
            cp "$CARGO_TARGET_DIR/$CARGO_BUILD_TARGET/release/aos-ability-crucible" "$out/bin/"
          '';
        }
      ];
    };
    production-parity = let
      verifier = builtins.path {
        path = ../../tools/bazel/tests;
        name = "aos-activation-crucible-feature-parity-tools";
        filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
      };
      packageOptions =
        pkgs.lib.concatMap (name: ["--package-path" "${name}=${packages.${name}}"])
        (builtins.attrNames packages)
        ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${productionDependencies.${name}}"])
        (builtins.attrNames productionDependencies);
    in
      pkgs.runCommand "aos-bazel-activation-crucible-production-features" {buildDeps = [pkgs.python3];} ''
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${verifier}/verify_protocol.py --features-only \
          --inventory ${production}/inventory.json --messages ${production-cargo}/cargo-messages.jsonl \
          --output "$out/parity.json" ${pkgs.lib.escapeShellArgs packageOptions}
      '';
    runtime =
      pkgs.runCommand "aos-bazel-activation-crucible-static-runtime" {
        buildDeps = [pkgs.python3];
        outputChecks.out = {};
        exportReferencesGraph.package = [package];
      } ''
        mkdir -p "$out"
        cp ${../../tools/bazel/tests/verify_cache.py} verify_cache.py
        cp ${../../tools/bazel/tests/verify_static_runtime.py} verify_static_runtime.py
        cp ${../../tools/bazel/tests/verify_activation_crucible.py} verify_activation_crucible.py
        ${pkgs.python3}/bin/python3 verify_activation_crucible.py \
          --build ${production} --package ${package} --libraries ${productionLibraries} \
          --cargo ${production-cargo} --readelf ${pkgs.binutils}/bin/readelf --output "$out/runtime.json"
      '';
    all =
      pkgs.runCommand "aos-bazel-activation-crucible-qualified-checks" {
        buildDeps = [family.all family.editor-parity production-parity runtime execution-profiles editor-builtin-cfg editor-execution-profiles development];
      } ''
        mkdir -p "$out"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json ${family.all}/parity.json "$out/"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
        cp ${editor-builtin-cfg}/evidence.json "$out/editor-builtin-cfg.json"
        cp ${editor-execution-profiles}/evidence.json "$out/editor-execution-profiles.json"
        cp ${development}/evidence.json "$out/development.json"
        cp ${production-parity}/parity.json "$out/production-parity.json"
        cp -r ${runtime} "$out/runtime"
      '';
  }
