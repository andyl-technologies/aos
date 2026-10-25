##! Qualifies engine feature variants without changing production consumers.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/engine-inventory.json,
}: let
  label = "//crates/crucible/crucible-engine";
  sourceCatalog = import ./_bazel-source-catalog.nix {inherit pkgs;};
  inputPaths = [
    "tests/crucible/engineering-hygiene-baseline.txt"
    "tests/crucible/fixtures/debugger-live-x86_64.scenario.toml"
    "tests/crucible/fixtures/debugger-live-aarch64.scenario.toml"
    "tests/crucible/fixtures/live-qemu-search.scenario.toml"
    "tests/crucible/fixtures/live-qemu-fuzz.family.toml"
    "tests/crucible/fixtures/nginx-curl-http-200.scenario.toml"
    "tests/crucible/fixtures/happy-path.scenario.toml"
    "docs/rfcs/0014-signal-driven-fault-model/04-fault-taxonomy.md"
    "docs/rfcs/0014-signal-driven-fault-model/08-executable-effect-contracts.md"
    "docs/users/crucible/README.md"
    "docs/users/crucible/bindings.md"
    "docs/users/crucible/network-faults.md"
    "docs/users/crucible/reference.md"
    "docs/users/crucible/signal-driven-faults.md"
    "docs/users/crucible/signals.md"
    "docs/users/crucible/storage-node-faults.md"
    "docs/users/crucible/topology.md"
  ];
  root = ../..;
  parityTools = builtins.path {
    path = root + "/tools/bazel/tests";
    name = "aos-engine-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
  };
  cargoSource = import (root + "/pkgs/tools/crucible/_cargo-source.nix") {
    inherit (pkgs) lib;
    extraPaths = inputPaths;
  };
  cargoSetup = ''
    aos_engine_cargo_source="$PWD"
    if [ -d source/crates ]; then aos_engine_cargo_source="$PWD/source"; fi
    cp ${sourceCatalog.crates}/share/aos/source-catalog.json "$aos_engine_cargo_source/crates/source_catalog.json"
    export AOS_SOURCE_CATALOG="$aos_engine_cargo_source/crates/source_catalog.json"
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
  '';
  packages.crucible-engine = "crates/crucible/crucible-engine";
  dependencyPackages = {
    crucible-determinism = "crates/crucible/crucible-determinism";
    crucible-campaign = "crates/crucible/crucible-campaign";
    crucible-device = "crates/crucible/crucible-device";
    crucible-store = "crates/crucible/crucible-store";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
    crucible-test-support = "crates/crucible/crucible-test-support";
  };
  dependencyOptions =
    pkgs.lib.concatMap
    (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
    (builtins.attrNames dependencyPackages);
  nativeLibraries = [pkgs.sqlite pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config];
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  excludedTests = ["gate_replay_oracle" "gate_abi_conformance" "gate_scheduler_liveness" "gate_e2e_determinism_concurrency"];
  emptyTests = ["guest_host_channel_determinism" "guest_host_marker_observability" "property_fingerprint_neutrality"];
  family = import (root + "/tests/build/_bazel-rust-family.nix") {
    inherit pkgs packages dependencyPackages sourceInventory nativeLibraries nativeTools cargoSource cargoSetup excludedTests rustcFlags;
    pname = "aos-bazel-engine";
    dependencyProfile = "engine";
    editorComparisonScope = "selected-packages";
    emptyTests = map (name: "${label}:${name}") emptyTests;
    editorRustcFlags = rustcFlags;
    execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    # The editor oracle applies its global flags to host macros as well.
    editorExecRustcFlags = rustcFlags;
    retainTestActionGraph = true;
    captureCompilerArguments = true;
    editorDiagnosticContext = true;
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.engine // {aos_native = pkgs.aosBazelStoreLibraries;};
    extraSourceDirectories = ["BUILD.bazel" "crates" "tests/crucible" "docs/rfcs/0014-signal-driven-fault-model" "docs/rfcs/0020-crucible-campaigns" "docs/users/crucible"];
  };
  execution-profiles = import ./_bazel-rust-test-profiles.nix {
    inherit pkgs;
    inherit (family) tests cargo;
    pname = "aos-bazel-engine-execution-profiles";
    firstPartyTests = {
      "${label}:unit_binary" = "crucible_engine";
    };
    proceduralMacros = ["curve25519_dalek_derive" "serde_derive" "thiserror_impl" "tracing_attributes" "zerocopy_derive"];
  };
  variantTargets = suffix: features: let
    files = builtins.readDir (root + "/crates/crucible/crucible-engine/tests");
    names = map (pkgs.lib.removeSuffix ".rs") (builtins.filter (name: files.${name} == "regular" && pkgs.lib.hasSuffix ".rs" name) (builtins.attrNames files));
    selected = builtins.filter (name: builtins.elem "test-double" features || !(builtins.elem name excludedTests)) names;
  in
    map (name: "${label}:${name}${suffix}") (["unit" "doc" "license_closure" "phase5_live_asset_fixture" "crucible-debugger-live-fixture"] ++ selected);
  featureVariant = name: features: let
    suffix = "_${name}";
    tests = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-engine-${name}-tests";
      workspace = family.workspace;
      targets = variantTargets suffix features;
    };
    cargo = import (root + "/tests/build/_bazel-cargo-oracle.nix") {
      inherit pkgs nativeLibraries nativeTools cargoSource cargoSetup;
      pname = "aos-bazel-engine-${name}-cargo-oracle";
      packages = builtins.attrNames packages;
      cargoFlags = ["--features" (pkgs.lib.concatStringsSep "," (map (feature: "crucible-engine/${feature}") features))];
    };
  in
    pkgs.runCommand "aos-bazel-engine-${name}-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --cargo-log ${cargo}/cargo-tests.log \
        --package-path crucible-engine=crates/crucible/crucible-engine \
        ${pkgs.lib.escapeShellArgs dependencyOptions} \
        ${pkgs.lib.escapeShellArgs (pkgs.lib.concatMap (name: ["--allow-empty-test" "${label}:${name}${suffix}"]) (pkgs.lib.optionals (!(builtins.elem "test-double" features)) emptyTests))} \
        --target-suffix ${suffix} --output "$out/parity.json"
      cp ${tests}/inventory.json "$out/inventory.json"
      cp -r ${tests}/evidence "$out/evidence"
    '';
in
  family
  // rec {
    inherit execution-profiles;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-engine-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap (variant: variantTargets variant.suffix variant.features) [
          {
            suffix = "";
            features = [];
          }
          {
            suffix = "_test_support";
            features = ["test-support"];
          }
          {
            suffix = "_test_double";
            features = ["test-double"];
          }
          {
            suffix = "_all_features";
            features = ["test-double" "test-support"];
          }
        ]
        ++ map (name: "${label}:${name}") ["clippy" "documentation" "format"];
    };
    test-support = featureVariant "test_support" ["test-support"];
    test-double = featureVariant "test_double" ["test-double"];
    all-features = featureVariant "all_features" ["test-double" "test-support"];
    all =
      pkgs.runCommand "aos-bazel-engine-qualified-checks" {
        buildDeps = [family.all family.editor-parity test-support test-double all-features sourceCatalog.all execution-profiles];
      } ''
        mkdir -p "$out/variants" "$out/editor"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json "$out/inventory.json"
        cp ${family.oracle}/parity.json "$out/default.json"
        cp ${execution-profiles}/evidence.json "$out/execution-profiles.json"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp -r ${family.editor} "$out/editor/bazel"
        cp -r ${family.editor-cargo-oracle} "$out/editor/cargo"
        cp ${sourceCatalog.crates}/share/aos/source-catalog.json "$out/source-catalog.json"
        cp -r ${test-support} "$out/variants/test-support"
        cp -r ${test-double} "$out/variants/test-double"
        cp -r ${all-features} "$out/variants/all-features"
      '';
  }
