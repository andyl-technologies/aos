##! Compiles the CLI graph while its runtime and strict-source gates are qualified.
{
  pkgs,
  fleet ? false,
}: let
  lib = pkgs.lib;
  root = ../..;
  profile =
    if fleet
    then "aos-cli-fleet-tests"
    else "aos-cli-tests";
  packages = {aos-cli = "crates/aos/cli/aos-cli";};
  dependencyPackages = {
    aos-activation = "crates/aos/activation/aos-activation";
    aos-artifact-evidence = "crates/shared/aos-artifact-evidence";
    aos-boot-identity = "crates/aos/boot/aos-boot-identity";
    aos-build-api = "crates/aos/packages/aos-build-api";
    aos-build-client = "crates/aos/packages/aos-build-client";
    aos-build-server = "crates/aos/packages/aos-build-server";
    aos-cli-ui = "crates/aos/cli/aos-cli-ui";
    aos-closure-analysis = "crates/aos/cli/aos-closure-analysis";
    aos-core = "crates/shared/aos-core";
    aos-deployment = "crates/aos/packages/aos-deployment";
    aos-deployment-format = "crates/aos/packages/aos-deployment-format";
    aos-hub-api = "crates/hub/aos-hub-api";
    aos-hub-client = "crates/hub/aos-hub-client";
    aos-hub-db = "crates/hub/aos-hub-db";
    aos-hub-model = "crates/hub/aos-hub-model";
    aos-hub-native = "crates/hub/aos-hub-native";
    aos-hub-service = "crates/hub/aos-hub-service";
    aos-hub-ui = "crates/hub/aos-hub-ui";
    aos-image-finalizer = "crates/aos/release/aos-image-finalizer";
    aos-module-docs = "crates/aos/modules/aos-module-docs";
    aos-module-format = "crates/aos/modules/aos-module-format";
    aos-nar = "crates/shared/aos-nar";
    aos-nix = "crates/shared/aos-nix";
    aos-nix-cache = "crates/aos/packages/aos-nix-cache";
    aos-nix-docs = "crates/aos/cli/aos-nix-docs";
    aos-oci = "crates/shared/aos-oci";
    aos-oci-types = "crates/shared/aos-oci-types";
    aos-package-maintenance = "crates/aos/release/aos-package-maintenance";
    aos-package-manager = "crates/aos/packages/aos-package-manager";
    aos-platform-metadata = "crates/aos/boot/aos-platform-metadata";
    aos-registry-authoring = "crates/aos/registry/aos-registry-authoring";
    aos-registry-client = "crates/aos/registry/aos-registry-client";
    aos-registry-format = "crates/aos/registry/aos-registry-format";
    aos-release-coordinator = "crates/aos/release/aos-release-coordinator";
    aos-release-format = "crates/aos/release/aos-release-format";
    aos-storage-layout = "crates/aos/boot/aos-storage-layout";
    aos-transfer = "crates/shared/aos-transfer";
  };
  prefix = "//crates/aos/cli/aos-cli:";
  normalBins = ["aos" "apr" "apm" "aos-package-runtime" "aos-boot-configuration" "aos-provisioning-configuration-evaluator"];
  fleetBins = ["aos-release-fleet-fixture" "aos-ability-interruption-audit" "aos-ability-authority-audit"];
  selectedBins = normalBins ++ lib.optionals fleet fleetBins;
  integrations = map (name: lib.removeSuffix ".rs" name) (builtins.filter
    (name: lib.hasSuffix ".rs" name)
    (builtins.attrNames (builtins.readDir ../../crates/aos/cli/aos-cli/tests)));
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
  workspace = pkgs.mkAosBazelWorkspace {
    inherit root;
    # Repository architecture tests still read Cargo manifests. Keep this
    # conservative input set explicit until their metadata audit is migrated.
    sourceDirectories =
      ["tools/bazel" "third_party/rust" "api/proto"]
      ++ builtins.attrValues packages ++ builtins.attrValues dependencyPackages;
    dependencyProfile = profile;
    inherit repositories;
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
