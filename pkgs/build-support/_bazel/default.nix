##! Shared first-party Bazel interfaces; upstream Bazel builders remain separate.
{
  pkgs,
  lib,
  sharedBazelCacheDir ? null,
}: rec {
  mkAosBazelToolchains = import ./toolchains.nix {inherit pkgs lib;};
  mkAosBazelNativeLibraries = import ./native-libraries.nix {inherit pkgs lib;};
  mkAosBazelStaticLibraries = import ./static-libraries.nix {inherit pkgs lib;};
  mkAosBazelCrossToolchains = arguments: import ./cross-toolchains.nix ({inherit pkgs;} // arguments);
  aosBazelModules = import ./modules.nix {inherit pkgs lib;};
  aosBazelToolchains = mkAosBazelToolchains {};
  aosBazelStoreLibraries = mkAosBazelNativeLibraries {
    libraries = {
      sqlite = {
        package = pkgs.sqlite;
        libraryFile = "lib/libsqlite3.so";
        pkgConfigFiles = ["lib/pkgconfig/sqlite3.pc"];
      };
      zstd = {
        package = pkgs.zstdStaticMultithread;
        libraryFile = "lib/libzstd.a";
        linkage = "static";
        pkgConfigFiles = ["lib/pkgconfig/libzstd.pc"];
      };
    };
  };
  aosBazelRepositories = import ./repositories.nix {
    inherit pkgs lib;
    modules = aosBazelModules;
  };
  aosBazelNativeFoundationLibraries = mkAosBazelNativeLibraries {
    libraries = import ./native-foundation-libraries.nix {inherit pkgs;};
  };
  aosBazelHubServiceLibraries = mkAosBazelNativeLibraries {
    libraries =
      (import ./native-foundation-libraries.nix {inherit pkgs;})
      // {
        sqlite = {
          package = pkgs.sqlite;
          libraryFile = "lib/libsqlite3.so";
          pkgConfigFiles = ["lib/pkgconfig/sqlite3.pc"];
        };
      };
  };
  aosBazelGuestLibraries = mkAosBazelStaticLibraries {
    libraries = {
      sqlite = {
        package = pkgs.sqliteStatic;
        libraryFile = "lib/libsqlite3.a";
        linkage = "static";
        pkgConfigFiles = ["lib/pkgconfig/sqlite3.pc"];
      };
      zstd = {
        package = pkgs.zstdStaticMultithread;
        libraryFile = "lib/libzstd.a";
        linkage = "static";
        pkgConfigFiles = ["lib/pkgconfig/libzstd.pc"];
      };
    };
  };
  aosBazelRepositoryTestSources = import ./repository-test-sources.nix {inherit pkgs lib;};
  aosBazelArchitecture = import ./architecture.nix {inherit pkgs;};
  aosBazelBootTools = import ./boot-tools.nix {inherit pkgs lib;};
  aosBazelRegistryTestTools = import ./registry-test-tools.nix {inherit pkgs lib;};
  aosBazelNixTestTools = import ./nix-test-tools.nix {inherit pkgs;};
  aosBazelCodegenTools = import ./codegen-tools.nix {inherit pkgs;};
  aosBazelQemuPluginAbi = import ./qemu-plugin-abi.nix {inherit pkgs;};
  aosBazelWasmTools = import ./wasm-tools.nix {inherit pkgs;};
  aosBazelWorkerTools = import ./worker-tools.nix {inherit pkgs;};
  aosBazelConsoleAssets = import ./console-assets.nix {
    inherit pkgs;
    build = (import ../../../tests/build/_bazel-hub-console-wasm.nix {inherit pkgs;}).build;
  };
  aosBazelDependencyGenerator = pkgs.callPackage ../../tools/workerd/_cargo-bazel.nix {};
  aosBazelDependencyUpdater = import ./updater.nix {
    inherit pkgs lib;
    generator = aosBazelDependencyGenerator;
  };
  aosBazelCrucibleCliRuntime = pkgs.runCommand "aos-bazel-crucible-cli-runtime" {} ''
    mkdir -p "$out"
    ln -s ${pkgs.ca-certificates}/etc/ssl/certs/ca-certificates.crt "$out/ca-certificates.crt"
    cat > "$out/BUILD.bazel" <<'BUILD'
    exports_files(["ca-certificates.crt"], visibility = ["//visibility:public"])
    BUILD
    touch "$out/REPO.bazel"
  '';
  aosBazelRustRepositories = {
    aos-cli-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "aos-cli-tests";
    };

    aos-cli-fleet-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "aos-cli-fleet-tests";
    };

    aos-cli-production = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "aos-cli-production";
    };

    hub-worker-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-worker-tests";
    };

    hub-worker-all-features-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-worker-all-features-tests";
    };

    hub-worker-wasm = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-worker-wasm";
    };

    hub-worker-wasm-do-e2e = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-worker-wasm-do-e2e";
    };

    hub-worker-wasm-all-features = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-worker-wasm-all-features";
    };

    hub-native-postgres = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-native-postgres";
    };
    hub-native-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-native-tests";
    };
    hub-service = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-service";
    };
    hub-service-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-service-tests";
    };
    hub-service-all-features = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-service-all-features";
    };
    hub-service-all-features-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-service-all-features-tests";
    };
    accache = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "accache";
    };
    registry-web = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "registry-web";
    };
    registry-web-wasm = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "registry-web-wasm";
    };
    hub-console = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-console";
    };
    hub-console-wasm = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-console-wasm";
    };
    hub-db = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-db";
    };
    hub-db-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-db-tests";
    };
    hub-db-all-features = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-db-all-features";
    };
    hub-db-all-features-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-db-all-features-tests";
    };
    package-manager = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "package-manager";
    };
    package-manager-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "package-manager-tests";
    };
    boot-preparation = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "boot-preparation";
    };
    boot-preparation-minimal = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "boot-preparation-minimal";
    };
    release-coordination = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "release-coordination";
    };
    registry-native = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "registry-native";
    };
    registry-native-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "registry-native-tests";
    };
    release-preparation = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "release-preparation";
    };
    hub-client = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-client";
    };
    hub-model-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-model-tests";
    };
    hub-model = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-model";
    };
    hub-portable = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "hub-portable";
    };
    deployment = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "deployment";
    };
    build-services = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "build-services";
    };
    cli-support = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "cli-support";
    };
    activation-crucible = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "activation-crucible";
    };
    activation-crucible-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "activation-crucible-tests";
    };
    activation-systemd = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "activation-systemd";
    };
    activation-storage = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "activation-storage";
    };
    activation-core = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "activation-core";
    };
    activation-core-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "activation-core-tests";
    };
    native-foundation = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "native-foundation";
    };
    native-bindings = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "native-bindings";
    };
    native-foundation-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "native-foundation-tests";
    };
    native-foundation-minimal = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "native-foundation-minimal";
    };
    core = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "core";
    };
    device = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "device";
    };
    store = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "store";
    };
    guest = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "guest";
    };
    formats = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "formats";
    };
    crucible-cli = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "crucible-cli";
    };
    daemon = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "daemon";
    };
    store-s3 = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "store-s3";
    };
    qemu-gpl-production = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "qemu-gpl-production";
    };
    qemu-gpl-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "qemu-gpl-tests";
    };
    qemu-gpl-plugin-tests = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "qemu-gpl-plugin-tests";
    };
    qemu-test-oracle-host = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "qemu-test-oracle-host";
    };
    qemu-host = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "qemu-host";
    };
    control = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "control";
    };
    session = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "session";
    };
    quota = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "quota";
    };
    engine = import ./rust-sources.nix {
      inherit pkgs lib;
      root = ../../..;
      family = "engine";
    };
  };
  mkAosBazelWorkspace = import ./workspace.nix {
    inherit pkgs lib;
    modules = aosBazelModules;
    defaultToolchains = aosBazelToolchains;
    defaultRepositories = aosBazelRepositories;
  };
  mkAosBazelBuild = import ./build.nix {inherit pkgs lib sharedBazelCacheDir;};
  mkAosBazelPackage = import ./package.nix {inherit pkgs lib;};
  mkAosBazelCheck = arguments: mkAosBazelBuild (arguments // {command = "test";});
  aosBazelWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates" "native" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.core // aosBazelRustRepositories.device // aosBazelRustRepositories.store // {aos_native = aosBazelStoreLibraries;};
  };
  aosBazelGuestWorkspace =
    (import ../../../tests/build/_bazel-guest.nix {
      inherit pkgs;
      sourceInventory = null;
    }).workspace;
  aosBazelGuestEditorWorkspace =
    (import ../../../tests/build/_bazel-guest.nix {
      inherit pkgs;
      sourceInventory = null;
    }).editorWorkspace;
  aosBazelQuotaWorkspace =
    (import ../../../tests/build/_bazel-quota.nix {
      inherit pkgs;
      sourceInventory = null;
    }).workspace;
  aosBazelQuotaEditorWorkspace =
    (import ../../../tests/build/_bazel-quota.nix {
      inherit pkgs;
      sourceInventory = null;
    }).editorWorkspace;
  aosBazelEngineWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust" "tests/crucible" "docs/rfcs/0014-signal-driven-fault-model" "docs/rfcs/0020-crucible-campaigns" "docs/users/crucible"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.engine // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "engine";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/crucible-engine:unit"];
  };
  aosBazelSessionWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.session // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "session";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/crucible-session:unit" "//crates/crucible/crucible-control-api:unit"];
  };
  aosBazelControlWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.control // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "control";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/crucible-control-client:unit" "//crates/crucible/crucible-control-server:unit"];
  };
  aosBazelHubWorkerWorkspace =
    (import ../../../tests/build/_bazel-hub-worker.nix {
      inherit pkgs;
    }).workspace;
  aosBazelHubWorkerAllFeaturesWorkspace =
    (import ../../../tests/build/_bazel-hub-worker.nix {
      inherit pkgs;
      allFeatures = true;
    }).workspace;
  aosBazelHubWorkerWasmWorkspace =
    (import ../../../tests/build/_bazel-hub-worker-wasm.nix {
      inherit pkgs;
    }).workspace;
  aosBazelHubWorkerWasmDoE2eWorkspace =
    (import ../../../tests/build/_bazel-hub-worker-wasm.nix {
      inherit pkgs;
      featureSet = "do-e2e";
    }).workspace;
  aosBazelHubWorkerWasmAllFeaturesWorkspace =
    (import ../../../tests/build/_bazel-hub-worker-wasm.nix {
      inherit pkgs;
      featureSet = "all-features";
    }).workspace;
  aosBazelHubNativeWorkspace =
    (import ../../../tests/build/_bazel-hub-native.nix {
      inherit pkgs;
      sourceInventory = null;
    }).workspace;
  aosBazelHubServiceWorkspace =
    (import ../../../tests/build/_bazel-hub-service-configuration.nix {
      inherit pkgs;
      sourceInventory = null;
      allFeatures = false;
    }).workspace;
  aosBazelHubServiceAllFeaturesWorkspace =
    (import ../../../tests/build/_bazel-hub-service-configuration.nix {
      inherit pkgs;
      sourceInventory = null;
      allFeatures = true;
    }).workspace;
  aosBazelAccacheWorkspace =
    (import ../../../tests/build/_bazel-accache.nix {
      inherit pkgs;
      sourceInventory = null;
    }).workspace;
  aosBazelAccacheEditorWorkspace =
    (import ../../../tests/build/_bazel-accache.nix {
      inherit pkgs;
      sourceInventory = null;
    }).editorWorkspace;
  aosBazelRegistryWebWorkspace =
    (import ../../../tests/build/_bazel-registry-web.nix {
      inherit pkgs;
      sourceInventory = null;
    }).workspace;
  aosBazelRegistryWebWasmWorkspace =
    (import ../../../tests/build/_bazel-registry-web-wasm.nix {
      inherit pkgs;
      sourceInventory = null;
    }).workspace;
  aosBazelHubConsoleWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["tools/bazel" "third_party/rust" "api/proto" "crates/artifacts/aos-artifact-evidence" "crates/core/aos-core" "crates/hub/aos-hub-api" "crates/hub/aos-hub-console" "crates/hub/aos-hub-ui" "crates/modules/aos-module-docs" "crates/modules/aos-module-format" "crates/artifacts/aos-oci-types" "crates/registry/aos-registry-format"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.hub-console
      // {
        aos_codegen = aosBazelCodegenTools;
      };
    dependencyProfile = "hub-console";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/hub/aos-hub-console:unit"];
  };
  aosBazelHubConsoleWasmWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["tools/bazel" "third_party/rust" "api/proto" "crates/artifacts/aos-artifact-evidence" "crates/core/aos-core" "crates/hub/aos-hub-api" "crates/hub/aos-hub-console" "crates/hub/aos-hub-ui" "crates/modules/aos-module-docs" "crates/modules/aos-module-format" "crates/artifacts/aos-oci-types" "crates/registry/aos-registry-format"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.hub-console-wasm
      // {
        aos_codegen = aosBazelCodegenTools;
        aos_wasm_tools = aosBazelWasmTools;
      };
    dependencyProfile = "hub-console-wasm";
    targetPlatform = "//tools/bazel/toolchains:wasm32";
    compileOnly = true;
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Clto=thin" "-Cembed-bitcode=yes" "-Ccodegen-units=1" "-Cstrip=symbols" "-Cdebug-assertions=no" "-Coverflow-checks=no"];
    analysisTargets = ["//crates/hub/aos-hub-console:browser_dist"];
  };
  aosBazelHubDbWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/modules/aos-module-docs"
      "crates/modules/aos-module-format"
      "crates/registry/aos-registry-format"
      "crates/release/aos-release-format"
      "crates/hub/aos-hub-db"
      "crates/hub/aos-hub-model"
      "crates/artifacts/aos-artifact-evidence"
      "crates/core/aos-core"
      "crates/artifacts/aos-oci-types"
    ];
    repositories = aosBazelRepositories // aosBazelRustRepositories.hub-db-tests // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "hub-db-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/hub/aos-hub-db:unit"];
  };
  aosBazelHubDbAllFeaturesWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/modules/aos-module-docs"
      "crates/modules/aos-module-format"
      "crates/registry/aos-registry-format"
      "crates/release/aos-release-format"
      "crates/hub/aos-hub-db"
      "crates/hub/aos-hub-model"
      "crates/artifacts/aos-artifact-evidence"
      "crates/core/aos-core"
      "crates/artifacts/aos-oci-types"
    ];
    repositories = aosBazelRepositories // aosBazelRustRepositories.hub-db-all-features-tests // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "hub-db-all-features-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/hub/aos-hub-db:unit"];
  };
  aosBazelPackageManagerWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "crates/hub/aos-hub-native"
      "crates/activation/aos-activation"
      "crates/boot/aos-platform-metadata"
      "crates/boot/aos-storage-layout"
      "crates/cli/aos-cli-ui"
      "crates/modules/aos-module-docs"
      "crates/modules/aos-module-format"
      "crates/packages/aos-deployment"
      "crates/packages/aos-deployment-format"
      "crates/packages/aos-nix-cache"
      "crates/packages/aos-package-manager"
      "crates/registry/aos-registry-authoring"
      "crates/registry/aos-registry-client"
      "crates/registry/aos-registry-format"
      "crates/release/aos-release-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-client"
      "crates/artifacts/aos-artifact-evidence"
      "crates/core/aos-core"
      "crates/artifacts/aos-nar"
      "crates/nix/aos-nix"
      "crates/artifacts/aos-oci"
      "crates/artifacts/aos-oci-types"
      "crates/transfer/aos-transfer"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.package-manager-tests
      // {
        aos_codegen = aosBazelCodegenTools;
        aos_native = aosBazelNativeFoundationLibraries;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
        aos_registry_runtime = aosBazelRegistryTestTools;
      };
    dependencyProfile = "package-manager-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/packages/aos-package-manager:unit"];
  };
  aosBazelBootPreparationWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/activation/aos-activation"
      "crates/boot/aos-boot-identity"
      "crates/boot/aos-boot-runtime"
      "crates/boot/aos-configuration-image"
      "crates/boot/aos-platform-metadata"
      "crates/boot/aos-storage-layout"
      "crates/modules/aos-module-format"
      "crates/registry/aos-registry-format"
      "crates/release/aos-release-format"
      "crates/artifacts/aos-artifact-evidence"
      "crates/core/aos-core"
      "crates/artifacts/aos-nar"
      "crates/nix/aos-nix"
      "crates/artifacts/aos-oci-types"
      "crates/transfer/aos-transfer"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.boot-preparation
      // {
        aos_native = aosBazelNativeFoundationLibraries;
        aos_boot_tools = aosBazelBootTools;
      };
    dependencyProfile = "boot-preparation";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/boot/aos-boot-runtime:unit" "//crates/boot/aos-configuration-image:unit" "//crates/boot/aos-platform-metadata:unit"];
  };
  aosBazelReleaseCoordinationWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "crates/boot/aos-boot-identity"
      "crates/cli/aos-cli-ui"
      "crates/modules/aos-module-docs"
      "crates/modules/aos-module-format"
      "crates/packages/aos-deployment-format"
      "crates/packages/aos-nix-cache"
      "crates/registry/aos-registry-client"
      "crates/registry/aos-registry-format"
      "crates/release/aos-image-finalizer"
      "crates/release/aos-release-coordinator"
      "crates/release/aos-release-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-client"
      "crates/artifacts/aos-artifact-evidence"
      "crates/core/aos-core"
      "crates/artifacts/aos-nar"
      "crates/nix/aos-nix"
      "crates/artifacts/aos-oci-types"
      "crates/transfer/aos-transfer"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.release-coordination
      // {
        aos_codegen = aosBazelCodegenTools;
        aos_native = aosBazelNativeFoundationLibraries;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
      };
    dependencyProfile = "release-coordination";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/release/aos-release-coordinator:unit"];
  };
  aosBazelRegistryNativeWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "crates/hub/aos-hub-native"
      "crates/activation/aos-activation"
      "crates/artifacts/aos-artifact-evidence"
      "crates/cli/aos-cli-ui"
      "crates/core/aos-core"
      "crates/packages/aos-deployment"
      "crates/packages/aos-deployment-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-client"
      "crates/modules/aos-module-docs"
      "crates/modules/aos-module-format"
      "crates/artifacts/aos-nar"
      "crates/nix/aos-nix"
      "crates/packages/aos-nix-cache"
      "crates/artifacts/aos-oci"
      "crates/artifacts/aos-oci-types"
      "crates/registry/aos-registry-authoring"
      "crates/registry/aos-registry-client"
      "crates/registry/aos-registry-format"
      "crates/release/aos-release-format"
      "crates/transfer/aos-transfer"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.registry-native-tests
      // {
        aos_codegen = aosBazelCodegenTools;
        aos_native = aosBazelNativeFoundationLibraries;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
        aos_registry_runtime = aosBazelRegistryTestTools;
      };
    dependencyProfile = "registry-native-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = [
      "//crates/packages/aos-nix-cache:unit"
      "//crates/registry/aos-registry-authoring:unit"
      "//crates/registry/aos-registry-client:unit"
    ];
  };
  aosBazelReleasePreparationWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/artifacts/aos-artifact-evidence"
      "crates/boot/aos-boot-identity"
      "crates/core/aos-core"
      "crates/packages/aos-deployment-format"
      "crates/release/aos-image-finalizer"
      "crates/modules/aos-module-docs"
      "crates/modules/aos-module-format"
      "crates/artifacts/aos-oci-types"
      "crates/release/aos-package-maintenance"
      "crates/registry/aos-registry-format"
      "crates/release/aos-release-format"
      "crates/release/aos-release-signer"
    ];
    repositories = aosBazelRepositories // aosBazelRustRepositories.release-preparation;
    dependencyProfile = "release-preparation";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = [
      "//crates/release/aos-package-maintenance:unit"
      "//crates/release/aos-image-finalizer:unit"
      "//crates/release/aos-release-signer:bin_aos-release-signer"
    ];
  };
  aosBazelHubClientWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-client"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.hub-client
      // {
        aos_codegen = aosBazelCodegenTools;
      };
    dependencyProfile = "hub-client";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/hub/aos-hub-client:unit"];
  };
  aosBazelHubModelWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "docs/rfcs/0012-hub-surface-topology"
      "crates/registry/aos-registry-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-model"
      "crates/core/aos-core"
      "crates/artifacts/aos-oci-types"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.hub-model-tests
      // {
        aos_codegen = aosBazelCodegenTools;
        aos_hub_model_test_sources = aosBazelRepositoryTestSources;
      };
    dependencyProfile = "hub-model-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/hub/aos-hub-model:unit"];
  };
  aosBazelHubPortableWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-ui"
      "crates/hub/aos-hub-console"
      "crates/hub/aos-hub-service"
      "docs/rfcs/0012-hub-surface-topology"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.hub-portable
      // {
        aos_codegen = aosBazelCodegenTools;
      };
    dependencyProfile = "hub-portable";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/hub/aos-hub-api:unit" "//crates/hub/aos-hub-ui:unit"];
  };
  aosBazelDeploymentWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/activation/aos-activation"
      "crates/modules/aos-module-docs"
      "crates/modules/aos-module-format"
      "crates/packages/aos-deployment"
      "crates/packages/aos-deployment-format"
      "crates/registry/aos-registry-format"
      "crates/release/aos-release-format"
      "crates/artifacts/aos-artifact-evidence"
      "crates/core/aos-core"
      "crates/artifacts/aos-nar"
      "crates/nix/aos-nix"
      "crates/artifacts/aos-oci-types"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.deployment
      // {
        aos_nix_test_tools = aosBazelNixTestTools;
      };
    dependencyProfile = "deployment";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/packages/aos-deployment:unit"];
  };
  aosBazelBuildServicesWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/packages/aos-build-api" "crates/packages/aos-build-client" "crates/packages/aos-build-server" "crates/core/aos-core" "crates/artifacts/aos-nar" "crates/nix/aos-nix" "api/proto" "tools/bazel" "third_party/rust"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.build-services
      // {
        aos_native = aosBazelStoreLibraries;
        aos_codegen = aosBazelCodegenTools;
      };
    dependencyProfile = "build-services";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/packages/aos-build-api:unit" "//crates/packages/aos-build-client:unit" "//crates/packages/aos-build-server:unit"];
  };
  aosBazelCliSupportWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/cli/aos-cli-ui" "crates/cli/aos-closure-analysis" "crates/cli/aos-nix-docs" "crates/core/aos-core" "crates/artifacts/aos-nar" "crates/nix/aos-nix" "crates/transfer/aos-transfer" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.cli-support;
    dependencyProfile = "cli-support";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/cli/aos-cli-ui:unit" "//crates/cli/aos-closure-analysis:unit" "//crates/cli/aos-nix-docs:unit"];
  };
  aosBazelActivationCrucibleWorkspace =
    (import ../../../tests/build/_bazel-activation-crucible.nix {
      inherit pkgs;
      sourceInventory = null;
    }).workspace;
  aosBazelActivationCrucibleEditorWorkspace =
    (import ../../../tests/build/_bazel-activation-crucible.nix {
      inherit pkgs;
      sourceInventory = null;
    }).editorWorkspace;
  aosBazelActivationSystemdWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/activation" "crates/modules/aos-module-format" "crates/core" "crates/artifacts" "crates/linux" "crates/nix" "crates/transfer" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.activation-systemd;
    dependencyProfile = "activation-systemd";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/activation/aos-activation-systemd:bin_aos-systemd-native-resource-provider"];
  };
  aosBazelActivationStorageWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/activation" "crates/boot/aos-storage-layout" "crates/modules/aos-module-format" "crates/core/aos-core" "crates/artifacts/aos-artifact-evidence" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.activation-storage;
    dependencyProfile = "activation-storage";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = map (name: "//crates/activation/${name}:unit") [
      "aos-activation-filesystem"
      "aos-activation-nix-store"
      "aos-activation-storage"
    ];
  };
  aosBazelActivationCoreWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/activation" "crates/modules/aos-module-format" "crates/core/aos-core" "crates/artifacts/aos-artifact-evidence" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.activation-core-tests;
    dependencyProfile = "activation-core-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = map (name: "//crates/activation/${name}:unit") [
      "aos-activation"
      "aos-activation-config-files"
      "aos-activation-sysctl"
      "aos-activation-bpf-lsm"
      "aos-activation-bpf-network"
      "aos-activation-kubernetes"
      "aos-activation-nftables"
    ];
  };
  aosBazelNativeFoundationWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/core" "crates/artifacts" "crates/linux" "crates/nix" "crates/transfer" "crates/registry/aos-registry-format" "tools/bazel" "third_party/rust"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.native-foundation-tests
      // {
        aos_native = aosBazelNativeFoundationLibraries;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
      };
    dependencyProfile = "native-foundation-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/nix/aos-nix:unit" "//crates/transfer/aos-transfer:unit" "//crates/artifacts/aos-oci:unit" "//crates/linux/aos-systemd-client:unit"];
  };
  aosBazelContractsWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/core" "crates/artifacts" "crates/linux" "crates/nix" "crates/transfer" "crates/modules" "crates/registry/aos-registry-format" "crates/release/aos-release-format" "crates/packages/aos-deployment-format" "crates/boot/aos-storage-layout" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.formats // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "formats";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/release/aos-release-format:unit" "//crates/modules/aos-module-docs:unit" "//crates/packages/aos-deployment-format:unit" "//crates/boot/aos-storage-layout:unit"];
  };
  aosBazelFormatsWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/core" "crates/artifacts" "crates/linux" "crates/nix" "crates/transfer" "crates/modules/aos-module-format" "crates/registry/aos-registry-format" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.formats // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "formats";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/artifacts/aos-nar:unit" "//crates/modules/aos-module-format:unit" "//crates/registry/aos-registry-format:unit"];
  };
  aosBazelCrucibleCliWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust" "docs/rfcs/0020-crucible-campaigns" "tests/crucible"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.crucible-cli
      // {
        aos_native = aosBazelStoreLibraries;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
      };
    dependencyProfile = "crucible-cli";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/crucible-cli:bin_crucible"];
  };
  aosBazelDaemonWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust" "docs/rfcs/0020-crucible-campaigns" "tests/crucible"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.daemon // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "daemon";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/crucible-daemon:unit"];
  };
  aosBazelStoreS3Workspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.store-s3 // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "store-s3";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/crucible-store-s3:unit"];
  };
  aosBazelQemuHostWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "BUILD.bazel"
      "crates"
      "native"
      "tools/bazel"
      "third_party/rust"
      "docs/rfcs/0020-crucible-campaigns"
      "tests/crucible"
      "pkgs/default.nix"
      "pkgs/emulation/qemu.nix"
      "pkgs/emulation/qemu-patches/crucible-qemu-11.1.1.patch"
    ];
    repositories = aosBazelRepositories // aosBazelRustRepositories.qemu-host // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "qemu-host";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/crucible-qemu-host:unit"];
  };
  mkAosBazelShell = {workspace ? aosBazelWorkspace}:
    (import ./development.nix {inherit pkgs lib workspace;}).shell;
  aosBazelLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelWorkspace;
    }).launcher;
  aosBazelGuestLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelGuestWorkspace;
    }).launcher;
  aosBazelGuestEditorLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelGuestEditorWorkspace;
    }).launcher;
  aosBazelQuotaLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelQuotaWorkspace;
    }).launcher;
  aosBazelQuotaEditorLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelQuotaEditorWorkspace;
    }).launcher;
  aosBazelEngineLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelEngineWorkspace;
    }).launcher;
  aosBazelSessionLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelSessionWorkspace;
    }).launcher;
  aosBazelControlLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelControlWorkspace;
    }).launcher;
  aosBazelHubWorkerLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubWorkerWorkspace;
    }).launcher;
  aosBazelHubWorkerAllFeaturesLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubWorkerAllFeaturesWorkspace;
    }).launcher;
  aosBazelHubWorkerWasmLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubWorkerWasmWorkspace;
    }).launcher;
  aosBazelHubWorkerWasmDoE2eLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubWorkerWasmDoE2eWorkspace;
    }).launcher;
  aosBazelHubWorkerWasmAllFeaturesLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubWorkerWasmAllFeaturesWorkspace;
    }).launcher;
  aosBazelHubNativeLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubNativeWorkspace;
    }).launcher;
  aosBazelHubServiceLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubServiceWorkspace;
    }).launcher;
  aosBazelHubServiceAllFeaturesLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubServiceAllFeaturesWorkspace;
    }).launcher;
  aosBazelAccacheLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelAccacheWorkspace;
    }).launcher;
  aosBazelAccacheEditorLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelAccacheEditorWorkspace;
    }).launcher;
  aosBazelRegistryWebLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelRegistryWebWorkspace;
    }).launcher;
  aosBazelRegistryWebWasmLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelRegistryWebWasmWorkspace;
    }).launcher;
  aosBazelHubConsoleLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubConsoleWorkspace;
    }).launcher;
  aosBazelHubConsoleWasmLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubConsoleWasmWorkspace;
    }).launcher;
  aosBazelHubDbLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubDbWorkspace;
    }).launcher;
  aosBazelHubDbAllFeaturesLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubDbAllFeaturesWorkspace;
    }).launcher;
  aosBazelPackageManagerLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelPackageManagerWorkspace;
    }).launcher;
  aosBazelBootPreparationLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelBootPreparationWorkspace;
    }).launcher;
  aosBazelReleaseCoordinationLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelReleaseCoordinationWorkspace;
    }).launcher;
  aosBazelRegistryNativeLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelRegistryNativeWorkspace;
    }).launcher;
  aosBazelReleasePreparationLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelReleasePreparationWorkspace;
    }).launcher;
  aosBazelHubClientLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubClientWorkspace;
    }).launcher;
  aosBazelHubModelLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubModelWorkspace;
    }).launcher;
  aosBazelHubPortableLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelHubPortableWorkspace;
    }).launcher;
  aosBazelDeploymentLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelDeploymentWorkspace;
    }).launcher;
  aosBazelBuildServicesLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelBuildServicesWorkspace;
    }).launcher;
  aosBazelCliSupportLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelCliSupportWorkspace;
    }).launcher;
  aosBazelActivationCrucibleLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelActivationCrucibleWorkspace;
    }).launcher;
  aosBazelActivationCrucibleEditorLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelActivationCrucibleEditorWorkspace;
    }).launcher;
  aosBazelActivationSystemdLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelActivationSystemdWorkspace;
    }).launcher;
  aosBazelActivationStorageLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelActivationStorageWorkspace;
    }).launcher;
  aosBazelActivationCoreLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelActivationCoreWorkspace;
    }).launcher;
  aosBazelNativeFoundationLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelNativeFoundationWorkspace;
    }).launcher;
  aosBazelContractsLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelContractsWorkspace;
    }).launcher;
  aosBazelFormatsLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelFormatsWorkspace;
    }).launcher;
  aosBazelCrucibleCliLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelCrucibleCliWorkspace;
    }).launcher;
  aosBazelDaemonLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelDaemonWorkspace;
    }).launcher;
  aosBazelStoreS3Launcher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelStoreS3Workspace;
    }).launcher;
  aosBazelQemuHostLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelQemuHostWorkspace;
    }).launcher;
}
