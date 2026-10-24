##! Qualifies CLI graphs while retaining dedicated packaged-runtime gates.
{
  pkgs,
  sourceInventory ? ../../tools/bazel/metadata/crucible-cli-inventory.json,
}: let
  root = ../..;
  packagePath = "crates/crucible/crucible-cli";
  packages = {crucible-cli = packagePath;};
  dependencyPackages = {
    crucible-control-client = "crates/crucible/crucible-control-client";
    crucible-control-server = "crates/crucible/crucible-control-server";
    crucible-control-api = "crates/crucible/crucible-control-api";
    crucible-daemon = "crates/crucible/crucible-daemon";
    crucible-session = "crates/crucible/crucible-session";
    crucible-qemu-host = "crates/crucible/crucible-qemu-host";
    crucible-store-s3 = "crates/crucible/crucible-store-s3";
    crucible-guest = "crates/crucible/crucible-guest";
    crucible-test-support = "crates/crucible/crucible-test-support";
    aos-linux-project-quota = "crates/linux/aos-linux-project-quota";
    crucible-engine = "crates/crucible/crucible-engine";
    crucible-determinism = "crates/crucible/crucible-determinism";
    crucible-campaign = "crates/crucible/crucible-campaign";
    crucible-device = "crates/crucible/crucible-device";
    crucible-store = "crates/crucible/crucible-store";
    crucible-qemu-protocol = "crates/crucible/crucible-qemu-protocol";
    crucible-qemu-shmem = "crates/crucible/crucible-qemu-shmem";
  };
  cargoSource = import (root + "/pkgs/tools/crucible/_cargo-source.nix") {
    inherit (pkgs) lib;
    extraPaths = ["tests/crucible/fixtures/e2e-determinism.scenario.toml"];
  };
  nativeLibraries = [pkgs.sqlite pkgs.zstdStaticMultithread];
  nativeTools = [pkgs.pkg-config];
  cargoSetup = ''
    export LIBSQLITE3_SYS_USE_PKG_CONFIG=1 ZSTD_SYS_USE_PKG_CONFIG=1
    export SSL_CERT_FILE=${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt
  '';
  rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  testDoubleTests = ["machine_readable" "gate_campaign_store_composition"];
  variants = {
    default = [];
    recovery_faults = ["destructive-recovery-faults"];
    test_double = ["test-double"];
    recovery_test_double = ["destructive-recovery-faults" "test-double"];
    packaged_midpoint_flight = ["packaged-midpoint-flight"];
    packaged_recovery = ["destructive-recovery-faults" "packaged-midpoint-flight"];
    packaged_test_double = ["packaged-midpoint-flight" "test-double"];
    all_features = ["destructive-recovery-faults" "packaged-midpoint-flight" "test-double"];
  };
  packagedVariants = ["packaged_midpoint_flight" "packaged_recovery" "packaged_test_double" "all_features"];
  suffixFor = name:
    if name == "default"
    then ""
    else "_${name}";
  integrationFiles = builtins.readDir (root + "/${packagePath}/tests");
  integrations = map (pkgs.lib.removeSuffix ".rs") (builtins.filter (file:
    integrationFiles.${file} == "regular" && pkgs.lib.hasSuffix ".rs" file)
  (builtins.attrNames integrationFiles));
  variantTargets = name:
    map (target: "//${packagePath}:${target}${suffixFor name}") (
      ["bin_crucible" "license_closure"]
      ++ builtins.filter (target: builtins.elem "test-double" variants.${name} || !(builtins.elem target testDoubleTests)) integrations
    );
  family = import ./_bazel-rust-family.nix {
    inherit pkgs packages dependencyPackages sourceInventory nativeLibraries nativeTools cargoSource cargoSetup rustcFlags;
    pname = "aos-bazel-crucible-cli";
    packageTargets.crucible-cli = {
      root = "crucible_for_tests";
      unit = "bin_crucible";
      doctest = null;
    };
    dependencyProfile = "crucible-cli";
    excludedTests = testDoubleTests;
    editorComparisonScope = "selected-packages";
    editorRustcFlags = rustcFlags;
    editorDiagnosticContext = true;
    repositories =
      pkgs.aosBazelRepositories
      // pkgs.aosBazelRustRepositories.crucible-cli
      // {
        aos_native = pkgs.aosBazelStoreLibraries;
        aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
      };
    extraSourceDirectories = ["BUILD.bazel" "crates" "docs/rfcs/0020-crucible-campaigns" "tests/crucible"];
  };
  parityTools = builtins.path {
    path = root + "/tools/bazel/tests";
    name = "aos-crucible-cli-parity-tools";
    filter = path: type: type == "regular" && builtins.elem (baseNameOf path) ["verify_protocol.py" "verify_pilot.py"];
  };
  packageOptions =
    ["--package-path" "crucible-cli=${packagePath}"]
    ++ pkgs.lib.concatMap (name: ["--dependency-package-path" "${name}=${dependencyPackages.${name}}"])
    (builtins.attrNames dependencyPackages);
  featureOracles = import ./_bazel-cargo-feature-oracles.nix {
    inherit pkgs nativeLibraries nativeTools cargoSource cargoSetup;
    pname = "aos-bazel-crucible-cli-feature-oracles";
    packages = ["crucible-cli"];
    compileOnlyVariants = packagedVariants;
    variants = builtins.mapAttrs (_: features:
      pkgs.lib.optionals (features != []) [
        "--features"
        (pkgs.lib.concatStringsSep "," (map (feature: "crucible-cli/${feature}") features))
      ])
    variants;
  };
  featureVariant = name: let
    tests = pkgs.mkAosBazelCheck {
      pname = "aos-bazel-crucible-cli-${name}-tests";
      workspace = family.workspace;
      targets = variantTargets name;
    };
  in
    pkgs.runCommand "aos-bazel-crucible-cli-${name}-parity" {buildDeps = [pkgs.python3];} ''
      mkdir -p "$out"
      PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 ${parityTools}/verify_protocol.py \
        --tests ${tests}/evidence/tests --inventory ${tests}/inventory.json \
        --messages ${featureOracles}/${name}/cargo-messages.jsonl \
        --cargo-log ${featureOracles}/${name}/cargo-tests.log \
        ${pkgs.lib.escapeShellArgs packageOptions} \
        --target-suffix ${suffixFor name} --output "$out/parity.json"
      cp ${tests}/inventory.json "$out/inventory.json"
      cp -r ${tests}/evidence "$out/evidence"
    '';
in
  family
  // rec {
    inherit featureOracles;
    inventory = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-crucible-cli-inventory";
      workspace = family.workspace;
      inventoryOnly = true;
      targets =
        pkgs.lib.concatMap variantTargets (builtins.attrNames variants)
        ++ map (target: "//${packagePath}:${target}") ["clippy" "documentation" "format"];
    };
    test-double = featureVariant "test_double";
    recovery-faults = featureVariant "recovery_faults";
    recovery-test-double = featureVariant "recovery_test_double";
    # Packaged flight tests need kernel, QEMU and deployment resources supplied by
    # their dedicated VM gates. Compile every artifact here without executing it.
    packaged-compilation = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-crucible-cli-packaged-compilation";
      workspace = family.workspace;
      targets = pkgs.lib.concatMap (name:
        ["//${packagePath}:crucible${suffixFor name}"]
        ++ map (target: target + "_binary") (builtins.filter (target: !(pkgs.lib.hasInfix ":license_closure" target)) (variantTargets name)))
      packagedVariants;
    };
    production-license = pkgs.mkAosBazelBuild {
      pname = "aos-bazel-crucible-cli-production-license";
      workspace = family.workspace;
      targets = map (name: "//${packagePath}:production_license_closure${suffixFor name}") (builtins.attrNames variants);
    };
    all =
      pkgs.runCommand "aos-bazel-crucible-cli-qualified-checks" {
        buildDeps = [family.all family.editor-parity test-double recovery-faults recovery-test-double packaged-compilation production-license];
      } ''
        mkdir -p "$out/variants" "$out/editor"
        cp -r ${family.all}/evidence "$out/evidence"
        cp ${family.all}/inventory.json "$out/inventory.json"
        cp ${family.oracle}/parity.json "$out/default.json"
        cp ${family.editor-parity}/parity.json "$out/editor-parity.json"
        cp -r ${family.editor} "$out/editor/bazel"
        cp -r ${family.editor-cargo-oracle} "$out/editor/cargo"
        cp -r ${test-double} "$out/variants/test-double"
        cp -r ${recovery-faults} "$out/variants/recovery-faults"
        cp -r ${recovery-test-double} "$out/variants/recovery-test-double"
        cp -r ${packaged-compilation} "$out/packaged-compilation"
        cp -r ${production-license} "$out/production-license"
      '';
  }
