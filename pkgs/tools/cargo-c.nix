##! Build and install Rust libraries with a C ABI.
{
  mkCargoPackage,
  callPackage,
  buildPackages,
  stdenv,
  openssl,
  curl,
  libgit2,
  libssh2,
  zlib,
}: let
  sources = callPackage ./_cargo-c-sources.nix {};
in
  mkCargoPackage {
    pname = "cargo-c";
    inherit (sources) version src cargoDeps;
    passthru.evidenceSources = [sources.archive sources.lockfile sources.cargoDeps];
    buildDeps = [buildPackages.pkg-config buildPackages.cmake];
    runtimeDeps = [openssl curl libgit2 libssh2 zlib];
    doCheck = !stdenv.isCross;
    cargoEnv = {
      OPENSSL_NO_VENDOR = "1";
      LIBSSH2_SYS_USE_PKG_CONFIG = "1";
      LIBGIT2_NO_VENDOR = "1";
    };
    postInstall = ''
      mkdir -p "$out/share/licenses/cargo-c"
      cp LICENSE "$out/share/licenses/cargo-c/"
    '';
    meta = {
      description = "Cargo helpers for building and installing C ABI libraries";
      homepage = "https://github.com/lu-zero/cargo-c";
      license = "MIT";
      mainProgram = "cargo-cbuild";
    };
  }
