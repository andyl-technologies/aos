##! Rust 1.92.0 — bootstrap chain intermediate (built with 1.91)
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  pkg-config,
  python3,
  bash,
  which,
  openssl,
  zlib,
  stdenv,
  buildPackages,
  rust-1_91,
  llvm-21,
}: let
  mkRustBootstrap = import ./_rust-bootstrap.nix {
    inherit
      fetchurl
      mkDerivation
      gnumake
      cmake
      ninja
      pkg-config
      python3
      bash
      which
      openssl
      zlib
      stdenv
      buildPackages
      ;
  };
in
  mkRustBootstrap {
    version = "1.92.0";
    srcHash = "sha256-ng0sp1x+J1/cdYJVv0sDr7PWXRVDYCdGkHyTO2kBw7g=";
    changeId = 0;
    prevRust = rust-1_91;
    llvm = llvm-21;
    needsDownloadRustc = true;
    disableLld = true;
  }
