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
