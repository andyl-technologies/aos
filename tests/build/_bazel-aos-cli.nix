##! Builds the CLI test graph from its configured source inventory.
{
  pkgs,
  fleet ? false,
  sourceInventory ? ../../tools/bazel/metadata/aos-cli-inventory.json,
}: let
  lib = pkgs.lib;
  root = ../..;
  profile =
    if fleet
    then "aos-cli-fleet-tests"
    else "aos-cli-tests";
  packages = {aos-cli = "crates/cli/aos-cli";};
  dependencyPackages = {
    libssh2-sys = "crates/bindings/libssh2-sys";
    aos-activation = "crates/activation/aos-activation";
    aos-artifact-evidence = "crates/artifacts/aos-artifact-evidence";
    aos-boot-identity = "crates/boot/aos-boot-identity";
    aos-build-api = "crates/packages/aos-build-api";
    aos-build-client = "crates/packages/aos-build-client";
    aos-build-server = "crates/packages/aos-build-server";
    aos-cli-ui = "crates/cli/aos-cli-ui";
    aos-closure-analysis = "crates/cli/aos-closure-analysis";
    aos-core = "crates/core/aos-core";
    aos-deployment = "crates/packages/aos-deployment";
    aos-deployment-format = "crates/packages/aos-deployment-format";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-client = "crates/hub/aos-hub-client";
    aos-hub-db = "crates/hub/aos-hub-db";
    aos-hub-model = "crates/hub/aos-hub-model";
    aos-hub-native = "crates/hub/aos-hub-native";
    aos-hub-service = "crates/hub/aos-hub-service";
    aos-hub-ui = "crates/hub/aos-hub-ui";
    aos-image-finalizer = "crates/release/aos-image-finalizer";
    aos-module-docs = "crates/modules/aos-module-docs";
    aos-module-format = "crates/modules/aos-module-format";
    aos-nar = "crates/artifacts/aos-nar";
    aos-nix = "crates/nix/aos-nix";
    aos-nix-cache = "crates/packages/aos-nix-cache";
    aos-nix-docs = "crates/cli/aos-nix-docs";
    aos-oci = "crates/artifacts/aos-oci";
    aos-oci-types = "crates/artifacts/aos-oci-types";
    aos-package-maintenance = "crates/release/aos-package-maintenance";
    aos-package-manager = "crates/packages/aos-package-manager";
    aos-platform-metadata = "crates/boot/aos-platform-metadata";
    aos-registry-authoring = "crates/registry/aos-registry-authoring";
    aos-registry-client = "crates/registry/aos-registry-client";
    aos-registry-format = "crates/registry/aos-registry-format";
    aos-release-coordinator = "crates/release/aos-release-coordinator";
    aos-release-format = "crates/release/aos-release-format";
    aos-storage-layout = "crates/boot/aos-storage-layout";
    aos-transfer = "crates/transfer/aos-transfer";
  };
  prefix = "//crates/cli/aos-cli:";
  normalBins = ["aos" "apr" "apm" "aos-package-runtime" "aos-boot-configuration" "aos-provisioning-configuration-evaluator"];
  fleetBins = ["aos-release-fleet-fixture" "aos-ability-interruption-audit" "aos-ability-authority-audit"];
  selectedBins = normalBins ++ lib.optionals fleet fleetBins;
  integrations = map (name: lib.removeSuffix ".rs" name) (builtins.filter
    (name: lib.hasSuffix ".rs" name)
    (builtins.attrNames (builtins.readDir ../../crates/cli/aos-cli/tests)));
  testTargets = ["unit"] ++ map (name: "bin_" + name) selectedBins ++ integrations;
  tools = import ../../pkgs/build-support/_bazel/registry-test-tools.nix {
    inherit pkgs lib;
    exportNixEnvironment = true;
    extraTools = [pkgs.alejandra pkgs.mtools pkgs.tpm2-tools pkgs.util-linux pkgs.aos-landlock pkgs.python3];
    extraInputs = [lifecycleFixtures cacheFixtures ../../tests/build/fixtures/apm_lifecycle_registry.py];
    extraEnvironment =
      {
        AOS_NATIVE_CACHE_FIXTURES = "${cacheFixtures}/fixtures.json";
        AOS_LIFECYCLE_FIXTURES = "${lifecycleFixtures}/fixtures.json";
        AOS_LIFECYCLE_PYTHON = "${pkgs.python3}/bin/python3";
        AOS_LIFECYCLE_REGISTRY_SCRIPT = "${../../tests/build/fixtures/apm_lifecycle_registry.py}";
        NIX_CONFIG = "experimental-features = nix-command flakes";
        AOS_MCOPY = "${pkgs.mtools}/bin/mcopy";
        AOS_LANDLOCK_WRAPPER = "${pkgs.aos-landlock}/bin/aos-landlock";
        AOS_UNSHARE = "${pkgs.util-linux}/bin/unshare";
        AOS_PRLIMIT = "${pkgs.util-linux}/bin/prlimit";
      }
      // builtins.listToAttrs (map (name: {
        name = "AOS_TPM2_" + lib.toUpper name;
        value = "${pkgs.tpm2-tools}/bin/tpm2_${name}";
      }) ["createek" "createak" "readpublic" "quote" "pcrread" "pcrextend" "checkquote" "flushcontext"]);
  };
  cacheFixtures = import ./fixtures/apm-profile-lifecycle.nix {
    inherit pkgs;
    cache = true;
  };
  lifecycleFixtures = import ./fixtures/apm-profile-lifecycle.nix {inherit pkgs;};
  repositories =
    pkgs.aosBazelRepositories
    // pkgs.aosBazelRustRepositories.${profile}
    // {
      aos_native = pkgs.aosBazelHubServiceLibraries;
      aos_codegen = pkgs.aosBazelCodegenTools;
      aos_console_assets = pkgs.aosBazelConsoleAssets;
      aos_cli_runtime = pkgs.aosBazelCrucibleCliRuntime;
      aos_registry_runtime = tools;
      aos_cli_test_sources = import ../../pkgs/build-support/_bazel/cli-test-sources.nix {inherit pkgs;};
    };
  # Cargo's test build tools use the unoptimized build-override profile even
  # when first-party target tests use the workspace's size optimization.
  execRustcFlags = ["-Copt-level=0" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
  workspace = pkgs.mkAosBazelWorkspace {
    inherit root sourceInventory;
    # Integration contracts inspect declared repository inputs. Architecture
    # checks consume the generated all-profile Bazel production graph.
    # Keep qualification scripts and evidence outside compiler inputs. The
    # integration contracts receive their own declared repository snapshot.
    sourceDirectories = lib.optionals (sourceInventory == null) (
      ["tools/bazel/toolchains" "tools/bazel/rules" "tools/bazel/metadata" "tools/bazel/testing" "third_party/rust" "api/proto"]
      ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages
    );
    dependencyProfile = profile;
    cargoProfile = "debug";
    inherit repositories execRustcFlags;
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["${prefix}lib"];
  };
in {
  inherit packages dependencyPackages repositories selectedBins workspace;
  compile = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-${profile}-compile";
    inherit workspace;
    targets = map (name: prefix + name) (["lib"] ++ normalBins ++ map (name: name + "_binary") testTargets);
    retainActionGraph = true;
  };
  tests = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-${profile}-tests";
    inherit workspace;
    targets = map (name: prefix + name) testTargets;
    retainActionGraph = true;
  };
  developer-build = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-${profile}-developer";
    inherit workspace;
    targets = map (name: prefix + name) ["clippy" "documentation"];
  };
  format = pkgs.mkAosBazelCheck {
    pname = "aos-bazel-${profile}-format";
    inherit workspace;
    targets = ["${prefix}format"];
  };
  inventory = pkgs.mkAosBazelBuild {
    pname = "aos-bazel-${profile}-inventory";
    inherit workspace;
    inventoryOnly = true;
    targets =
      map (name: prefix + name)
      (["lib" "clippy" "documentation" "format" "license_closure"] ++ selectedBins ++ testTargets)
      ++ map (path: "//${path}:source_package") (builtins.attrValues packages ++ builtins.attrValues dependencyPackages);
  };
}
