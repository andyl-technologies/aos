##! Qualifies session and control API test graphs without changing production consumers.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/session-inventory.json,
}: let
  root = ../..;
  parityTools = builtins.path {
    path = root + "/tools/bazel/tests";
    name = "aos-session-parity-tools";
    filter = path: type:
      type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
  };
  cargoSource = import (root + "/pkgs/tools/crucible/_cargo-source.nix") {inherit (pkgs) lib;};
  cargoSetup = ''
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
  '';
  packages = {
    crucible-session = "crates/crucible/control/crucible-session";
    crucible-control-api = "crates/crucible/control/crucible-control-api";
  };
  dependencyPackages = {
    crucible-engine = "crates/crucible/engine/crucible-engine";
    crucible-determinism = "crates/crucible/engine/crucible-determinism";
    crucible-campaign = "crates/crucible/engine/crucible-campaign";
    crucible-device = "crates/crucible/engine/crucible-device";
    crucible-store = "crates/crucible/storage/crucible-store";
    crucible-qemu-protocol = "crates/crucible/protocol/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/protocol/crucible-qemu-shmem";
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
    pname = "aos-bazel-session";
    dependencyProfile = "session";
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
    editorLibraryTargets = builtins.mapAttrs (_: _: "lib_for_tests") packages;
    repositories = pkgs.aosBazelRepositories // pkgs.aosBazelRustRepositories.session // {aos_native = pkgs.aosBazelStoreLibraries;};
    extraSourceDirectories = ["BUILD.bazel" "crates"];
  };
  variantTargets = suffix:
    pkgs.lib.concatMap (name: let
      files = builtins.readDir (root + "/${packages.${name}}/tests");
      integrations = map (pkgs.lib.removeSuffix ".rs") (builtins.filter (file: files.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file) (builtins.attrNames files));
    in
      map (target: "//${packages.${name}}:${target}${suffix}") (["unit" "doc" "license_closure"] ++ integrations))
    (builtins.attrNames packages);
  featureVariant = name: features: let
    suffix = "_${name}";
    tests = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-session-${name}-tests";
      workspace = family.workspace;
      targets = variantTargets suffix;
    };
    cargo = import (root + "/tests/build/_bazel-cargo-oracle.nix") {
      inherit pkgs nativeLibraries nativeTools cargoSource cargoSetup;
      pname = "aos-bazel-session-${name}-cargo-oracle";
      packages = builtins.attrNames packages;
      cargoFlags = ["--features" (pkgs.lib.concatStringsSep "," (map (feature: "crucible-session/${feature}") features))];
    };
  in
    pkgs.runCommand "aos-bazel-session-${name}-parity" {buildDeps = [pkgs.python3];} ''
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
      pname = "aos-bazel-session-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap variantTargets ["" "_test_support" "_test_double" "_all_features"]
        ++ pkgs.lib.concatMap (name: map (target: "//${packages.${name}}:${target}") ["clippy" "documentation" "format"]) (builtins.attrNames packages);
    };
    test-support = featureVariant "test_support" ["test-support"];
    test-double = featureVariant "test_double" ["test-double"];
    all-features = featureVariant "all_features" ["test-double" "test-support"];
    all =
      pkgs.runCommand "aos-bazel-session-qualified-checks" {
        buildDeps = [family.all family.editor-parity test-support test-double all-features];
      } ''
        mkdir -p "$out/variants" "$out/editor"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json "$out/inventory.json"
        cp ${family.oracle}/parity.json "$out/default.json"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp -r ${family.editor} "$out/editor/bazel"
        cp -r ${family.editor-cargo-oracle} "$out/editor/cargo"
        cp -r ${test-support} "$out/variants/test-support"
        cp -r ${test-double} "$out/variants/test-double"
        cp -r ${all-features} "$out/variants/all-features"
      '';
  }
