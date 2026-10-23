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
    libraries = {
      openssl = {
        package = pkgs.openssl;
        libraryFile = "lib/libssl.so";
        pkgConfigFiles = ["lib/pkgconfig/openssl.pc" "lib/pkgconfig/libssl.pc"];
        pkgConfigDependencies = ["crypto"];
      };
      crypto = {
        package = pkgs.openssl;
        libraryFile = "lib/libcrypto.so";
        pkgConfigFiles = ["lib/pkgconfig/libcrypto.pc"];
      };
      ssh = {
        package = pkgs.libssh2;
        libraryFile = "lib/libssh2.so";
        pkgConfigFiles = ["lib/pkgconfig/libssh2.pc"];
        pkgConfigDependencies = ["crypto" "zlib"];
      };
      zlib = {
        package = pkgs.zlib;
        libraryFile = "lib/libz.so";
        compilerResponseFile = true;
        pkgConfigFiles = ["lib/pkgconfig/zlib.pc"];
      };
      zstd = {
        package = pkgs.zstdStaticMultithread;
        libraryFile = "lib/libzstd.a";
        linkage = "static";
        pkgConfigFiles = ["lib/pkgconfig/libzstd.pc"];
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
  aosBazelBootTools = import ./boot-tools.nix {inherit pkgs lib;};
  aosBazelRegistryTestTools = import ./registry-test-tools.nix {inherit pkgs lib;};
  aosBazelNixTestTools = import ./nix-test-tools.nix {inherit pkgs;};
  aosBazelCodegenTools = import ./codegen-tools.nix {inherit pkgs;};
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
  aosBazelGuestWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust" "tests/build" "tests/crucible" "docs/rfcs/0010-crucible" "docs/rfcs/0020-crucible-campaigns"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.guest // {aos_native = aosBazelGuestLibraries;};
    dependencyProfile = "guest";
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
    analysisTargets = ["//crates/crucible/guest/crucible-guest:unit"];
  };
  aosBazelQuotaWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["tools/bazel" "third_party/rust" "crates/shared/aos-linux-project-quota"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.quota;
    dependencyProfile = "quota";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/shared/aos-linux-project-quota:unit"];
  };
  aosBazelEngineWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust" "tests/crucible" "docs/rfcs/0014-signal-driven-fault-model" "docs/rfcs/0020-crucible-campaigns" "docs/users/crucible"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.engine // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "engine";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/engine/crucible-engine:unit"];
  };
  aosBazelSessionWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.session // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "session";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/control/crucible-session:unit" "//crates/crucible/control/crucible-control-api:unit"];
  };
  aosBazelControlWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.control // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "control";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/control/crucible-control-client:unit" "//crates/crucible/control/crucible-control-server:unit"];
  };
  aosBazelHubDbWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/aos/modules/aos-module-docs"
      "crates/aos/modules/aos-module-format"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-release-format"
      "crates/hub/aos-hub-db"
      "crates/hub/aos-hub-model"
      "crates/shared/aos-artifact-evidence"
      "crates/shared/aos-core"
      "crates/shared/aos-oci-types"
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
      "crates/aos/modules/aos-module-docs"
      "crates/aos/modules/aos-module-format"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-release-format"
      "crates/hub/aos-hub-db"
      "crates/hub/aos-hub-model"
      "crates/shared/aos-artifact-evidence"
      "crates/shared/aos-core"
      "crates/shared/aos-oci-types"
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
      "crates/aos/activation/aos-activation"
      "crates/aos/boot/aos-platform-metadata"
      "crates/aos/boot/aos-storage-layout"
      "crates/aos/cli/aos-cli-ui"
      "crates/aos/modules/aos-module-docs"
      "crates/aos/modules/aos-module-format"
      "crates/aos/packages/aos-deployment"
      "crates/aos/packages/aos-deployment-format"
      "crates/aos/packages/aos-nix-cache"
      "crates/aos/packages/aos-package-manager"
      "crates/aos/registry/aos-registry-authoring"
      "crates/aos/registry/aos-registry-client"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-release-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-client"
      "crates/shared/aos-artifact-evidence"
      "crates/shared/aos-core"
      "crates/shared/aos-nar"
      "crates/shared/aos-nix"
      "crates/shared/aos-oci"
      "crates/shared/aos-oci-types"
      "crates/shared/aos-transfer"
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
    analysisTargets = ["//crates/aos/packages/aos-package-manager:unit"];
  };
  aosBazelBootPreparationWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/aos/activation/aos-activation"
      "crates/aos/boot/aos-boot-identity"
      "crates/aos/boot/aos-boot-runtime"
      "crates/aos/boot/aos-configuration-image"
      "crates/aos/boot/aos-platform-metadata"
      "crates/aos/boot/aos-storage-layout"
      "crates/aos/modules/aos-module-format"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-release-format"
      "crates/shared/aos-artifact-evidence"
      "crates/shared/aos-core"
      "crates/shared/aos-nar"
      "crates/shared/aos-nix"
      "crates/shared/aos-oci-types"
      "crates/shared/aos-transfer"
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
    analysisTargets = ["//crates/aos/boot/aos-boot-runtime:unit" "//crates/aos/boot/aos-configuration-image:unit" "//crates/aos/boot/aos-platform-metadata:unit"];
  };
  aosBazelReleaseCoordinationWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "crates/aos/boot/aos-boot-identity"
      "crates/aos/cli/aos-cli-ui"
      "crates/aos/modules/aos-module-docs"
      "crates/aos/modules/aos-module-format"
      "crates/aos/packages/aos-deployment-format"
      "crates/aos/packages/aos-nix-cache"
      "crates/aos/registry/aos-registry-client"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-image-finalizer"
      "crates/aos/release/aos-release-coordinator"
      "crates/aos/release/aos-release-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-client"
      "crates/shared/aos-artifact-evidence"
      "crates/shared/aos-core"
      "crates/shared/aos-nar"
      "crates/shared/aos-nix"
      "crates/shared/aos-oci-types"
      "crates/shared/aos-transfer"
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
    analysisTargets = ["//crates/aos/release/aos-release-coordinator:unit"];
  };
  aosBazelRegistryNativeWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "api/proto"
      "crates/hub/aos-hub-native"
      "crates/aos/activation/aos-activation"
      "crates/shared/aos-artifact-evidence"
      "crates/aos/cli/aos-cli-ui"
      "crates/shared/aos-core"
      "crates/aos/packages/aos-deployment"
      "crates/aos/packages/aos-deployment-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-client"
      "crates/aos/modules/aos-module-docs"
      "crates/aos/modules/aos-module-format"
      "crates/shared/aos-nar"
      "crates/shared/aos-nix"
      "crates/aos/packages/aos-nix-cache"
      "crates/shared/aos-oci"
      "crates/shared/aos-oci-types"
      "crates/aos/registry/aos-registry-authoring"
      "crates/aos/registry/aos-registry-client"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-release-format"
      "crates/shared/aos-transfer"
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
      "//crates/aos/packages/aos-nix-cache:unit"
      "//crates/aos/registry/aos-registry-authoring:unit"
      "//crates/aos/registry/aos-registry-client:unit"
    ];
  };
  aosBazelReleasePreparationWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = [
      "tools/bazel"
      "third_party/rust"
      "crates/shared/aos-artifact-evidence"
      "crates/aos/boot/aos-boot-identity"
      "crates/shared/aos-core"
      "crates/aos/packages/aos-deployment-format"
      "crates/aos/release/aos-image-finalizer"
      "crates/aos/modules/aos-module-docs"
      "crates/aos/modules/aos-module-format"
      "crates/shared/aos-oci-types"
      "crates/aos/release/aos-package-maintenance"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-release-format"
      "crates/aos/release/aos-release-signer"
    ];
    repositories = aosBazelRepositories // aosBazelRustRepositories.release-preparation;
    dependencyProfile = "release-preparation";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = [
      "//crates/aos/release/aos-package-maintenance:unit"
      "//crates/aos/release/aos-image-finalizer:unit"
      "//crates/aos/release/aos-release-signer:bin_aos-release-signer"
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
      "crates/aos/registry/aos-registry-format"
      "crates/hub/aos-hub-api"
      "crates/hub/aos-hub-model"
      "crates/shared/aos-core"
      "crates/shared/aos-oci-types"
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
      "crates/aos/activation/aos-activation"
      "crates/aos/modules/aos-module-docs"
      "crates/aos/modules/aos-module-format"
      "crates/aos/packages/aos-deployment"
      "crates/aos/packages/aos-deployment-format"
      "crates/aos/registry/aos-registry-format"
      "crates/aos/release/aos-release-format"
      "crates/shared/aos-artifact-evidence"
      "crates/shared/aos-core"
      "crates/shared/aos-nar"
      "crates/shared/aos-nix"
      "crates/shared/aos-oci-types"
    ];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.deployment
      // {
        aos_nix_test_tools = aosBazelNixTestTools;
      };
    dependencyProfile = "deployment";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/aos/packages/aos-deployment:unit"];
  };
  aosBazelBuildServicesWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/aos/packages/aos-build-api" "crates/aos/packages/aos-build-client" "crates/aos/packages/aos-build-server" "crates/shared/aos-core" "crates/shared/aos-nar" "crates/shared/aos-nix" "api/proto" "tools/bazel" "third_party/rust"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.build-services
      // {
        aos_native = aosBazelStoreLibraries;
        aos_codegen = aosBazelCodegenTools;
      };
    dependencyProfile = "build-services";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/aos/packages/aos-build-api:unit" "//crates/aos/packages/aos-build-client:unit" "//crates/aos/packages/aos-build-server:unit"];
  };
  aosBazelCliSupportWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/aos/cli/aos-cli-ui" "crates/aos/cli/aos-closure-analysis" "crates/aos/cli/aos-nix-docs" "crates/shared/aos-core" "crates/shared/aos-nar" "crates/shared/aos-nix" "crates/shared/aos-transfer" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.cli-support;
    dependencyProfile = "cli-support";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/aos/cli/aos-cli-ui:unit" "//crates/aos/cli/aos-closure-analysis:unit" "//crates/aos/cli/aos-nix-docs:unit"];
  };
  aosBazelActivationCrucibleWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/aos/activation" "crates/aos/modules/aos-module-format" "crates/shared/aos-core" "crates/shared/aos-artifact-evidence" "crates/crucible" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.activation-crucible-tests // {aos_native = aosBazelGuestLibraries;};
    dependencyProfile = "activation-crucible-tests";
    rustcFlags = ["-Copt-level=3" "-Cdebuginfo=0" "-Ctarget-feature=+crt-static" "-Crelocation-model=static"];
    analysisTargets = ["//crates/aos/activation/aos-activation-crucible:unit"];
  };
  aosBazelActivationSystemdWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/aos/activation" "crates/aos/modules/aos-module-format" "crates/shared" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.activation-systemd;
    dependencyProfile = "activation-systemd";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/aos/activation/aos-activation-systemd:bin_aos-systemd-native-resource-provider"];
  };
  aosBazelActivationStorageWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/aos/activation" "crates/aos/boot/aos-storage-layout" "crates/aos/modules/aos-module-format" "crates/shared/aos-core" "crates/shared/aos-artifact-evidence" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.activation-storage;
    dependencyProfile = "activation-storage";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = map (name: "//crates/aos/activation/${name}:unit") [
      "aos-activation-filesystem"
      "aos-activation-nix-store"
      "aos-activation-storage"
    ];
  };
  aosBazelActivationCoreWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/aos/activation" "crates/aos/modules/aos-module-format" "crates/shared/aos-core" "crates/shared/aos-artifact-evidence" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.activation-core-tests;
    dependencyProfile = "activation-core-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = map (name: "//crates/aos/activation/${name}:unit") [
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
    sourceDirectories = ["crates/shared" "crates/aos/registry/aos-registry-format" "tools/bazel" "third_party/rust"];
    repositories =
      aosBazelRepositories
      // aosBazelRustRepositories.native-foundation-tests
      // {
        aos_native = aosBazelNativeFoundationLibraries;
        aos_cli_runtime = aosBazelCrucibleCliRuntime;
      };
    dependencyProfile = "native-foundation-tests";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = map (name: "//crates/shared/${name}:unit") ["aos-nix" "aos-transfer" "aos-oci" "aos-systemd-client"];
  };
  aosBazelContractsWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/shared" "crates/aos/modules" "crates/aos/registry/aos-registry-format" "crates/aos/release/aos-release-format" "crates/aos/packages/aos-deployment-format" "crates/aos/boot/aos-storage-layout" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.formats // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "formats";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/aos/release/aos-release-format:unit" "//crates/aos/modules/aos-module-docs:unit" "//crates/aos/packages/aos-deployment-format:unit" "//crates/aos/boot/aos-storage-layout:unit"];
  };
  aosBazelFormatsWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["crates/shared" "crates/aos/modules/aos-module-format" "crates/aos/registry/aos-registry-format" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.formats // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "formats";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/shared/aos-nar:unit" "//crates/aos/modules/aos-module-format:unit" "//crates/aos/registry/aos-registry-format:unit"];
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
    analysisTargets = ["//crates/crucible/control/crucible-cli:bin_crucible"];
  };
  aosBazelDaemonWorkspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust" "docs/rfcs/0020-crucible-campaigns" "tests/crucible"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.daemon // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "daemon";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/control/crucible-daemon:unit"];
  };
  aosBazelStoreS3Workspace = mkAosBazelWorkspace {
    root = ../../..;
    sourceDirectories = ["BUILD.bazel" "crates" "native" "tools/bazel" "third_party/rust"];
    repositories = aosBazelRepositories // aosBazelRustRepositories.store-s3 // {aos_native = aosBazelStoreLibraries;};
    dependencyProfile = "store-s3";
    rustcFlags = ["-Copt-level=s" "-Cdebuginfo=0" "-Cdebug-assertions=yes" "-Coverflow-checks=yes"];
    analysisTargets = ["//crates/crucible/storage/crucible-store-s3:unit"];
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
    analysisTargets = ["//crates/crucible/qemu/crucible-qemu-host:unit"];
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
  aosBazelQuotaLauncher =
    (import ./development.nix {
      inherit pkgs lib;
      workspace = aosBazelQuotaWorkspace;
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
