##! Qualifies the daemon test graph without changing production consumers.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/daemon-inventory.json,
}: let
  root = ../..;
  parityTools = builtins.path {
    path = root + "/tools/bazel/tests";
    name = "aos-daemon-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
  };
  cargoSource = import (root + "/pkgs/tools/crucible/_cargo-source.nix") {
    inherit (pkgs) lib;
    extraPaths = ["tests/crucible/fixtures/e2e-determinism.scenario.toml"];
  };
  cargoSetup = ''
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
  '';
  packages = {
    crucible-daemon = "crates/crucible/crucible-daemon";
  };
  dependencyPackages = {
    crucible-control-client = "crates/crucible/crucible-control-client";
    crucible-control-server = "crates/crucible/crucible-control-server";
    crucible-control-api = "crates/crucible/crucible-control-api";
    crucible-session = "crates/crucible/crucible-session";
    crucible-qemu-host = "crates/crucible/crucible-qemu-host";
    crucible-store-s3 = "crates/crucible/crucible-store-s3";
    crucible-guest = "crates/crucible/crucible-guest";
    aos-linux-project-quota = "crates/linux/aos-linux-project-quota";
    crucible-engine = "crates/crucible/crucible-engine";
    crucible-determinism = "crates/crucible/crucible-determinism";
    crucible-campaign = "crates/crucible/crucible-campaign";
    crucible-device = "crates/crucible/crucible-device";
    crucible-store = "crates/crucible/crucible-store";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
  };
  packageOptions =
    pkgs.lib.concatMap
    (name: ["--package-path" "${name}=${packages.${name}}"])
    (builtins.attrNames packages);
  dependencyOptions =
    pkgs.lib.concatMap
    (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
    (builtins.attrNames dependencyPackages);
  nativeLibraries = [pkgs.sqlite pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config];
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  family = import (root + "/tests/build/_bazel-rust-family.nix") {
    inherit pkgs packages dependencyPackages sourceInventory nativeLibraries nativeTools cargoSource cargoSetup rustcFlags;
    pname = "aos-bazel-daemon";
    dependencyProfile = "daemon";
    excludedTests = supportTests;
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
    editorLibraryTargets = builtins.mapAttrs (_: _: "lib_for_tests") packages;
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.daemon // {aos_native = pkgs.aosBazelStoreLibraries;};
    extraSourceDirectories = [
      "BUILD.bazel"
      "crates"
      "docs/rfcs/0020-crucible-campaigns"
      "tests/crucible"
    ];
  };
  supportTests = ["gate_campaign_component_contract" "gate_exact_closure_streaming"];
  variantTargets = suffix:
    pkgs.lib.concatMap (name: let
      files = builtins.readDir (root + "/${packages.${name}}/tests");
      integrations = map (pkgs.lib.removeSuffix ".rs") (builtins.filter (file: files.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file) (builtins.attrNames files));
    in
      map (target: "//${packages.${name}}:${target}${suffix}") (["unit" "doc" "license_closure" "crucible-e2e-determinism-scenario"] ++ builtins.filter (target: builtins.elem suffix ["_test_support" "_all_features"] || !(builtins.elem target supportTests)) integrations))
    (builtins.attrNames packages);
  featureVariant = name: features: let
    suffix = "_${name}";
    tests = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-daemon-${name}-tests";
      workspace = family.workspace;
      targets = variantTargets suffix;
    };
    cargo = import (root + "/tests/build/_bazel-cargo-oracle.nix") {
      inherit pkgs nativeLibraries nativeTools cargoSource cargoSetup;
      pname = "aos-bazel-daemon-${name}-cargo-oracle";
      packages = builtins.attrNames packages;
      cargoFlags = ["--features" (pkgs.lib.concatStringsSep "," (map (feature: "crucible-daemon/${feature}") features))];
    };
  in
    pkgs.runCommand "aos-bazel-daemon-${name}-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${cargo}/cargo-messages.jsonl --cargo-log ${cargo}/cargo-tests.log \
        ${pkgs.lib.escapeShellArgs packageOptions} \
        ${pkgs.lib.escapeShellArgs dependencyOptions} \
        --target-suffix ${suffix} --output "$out/parity.json"
      cp ${tests}/inventory.json "$out/inventory.json"
      cp -r ${tests}/evidence "$out/evidence"
    '';
in
  family
  // rec {
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-daemon-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap variantTargets ["" "_test_support" "_recovery_faults" "_all_features"]
        ++ pkgs.lib.concatMap (name: map (target: "//${packages.${name}}:${target}") ["clippy" "documentation" "format"]) (builtins.attrNames packages);
    };
    test-support = featureVariant "test_support" ["test-support"];
    recovery-faults = featureVariant "recovery_faults" ["destructive-recovery-faults"];
    all-features = featureVariant "all_features" ["destructive-recovery-faults" "test-support"];
    production-license = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-daemon-production-license";
      workspace = family.workspace;
      targets = [
        "//crates/crucible/crucible-daemon:production_license_closure"
        "//crates/crucible/crucible-daemon:production_license_closure_test_support"
        "//crates/crucible/crucible-daemon:production_license_closure_recovery_faults"
        "//crates/crucible/crucible-daemon:production_license_closure_all_features"
      ];
    };
    all =
      pkgs.runCommand "aos-bazel-daemon-qualified-checks" {
        buildDeps = [family.all family.editor-parity test-support recovery-faults all-features production-license];
      } ''
        mkdir -p "$out/variants" "$out/editor"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json "$out/inventory.json"
        cp ${family.oracle}/parity.json "$out/default.json"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp -r ${family.editor} "$out/editor/bazel"
        cp -r ${family.editor-cargo-oracle} "$out/editor/cargo"
        cp -r ${test-support} "$out/variants/test-support"
        cp -r ${recovery-faults} "$out/variants/recovery-faults"
        cp -r ${all-features} "$out/variants/all-features"
        cp -r ${production-license} "$out/production-license"
      '';
  }
