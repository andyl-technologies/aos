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
}
