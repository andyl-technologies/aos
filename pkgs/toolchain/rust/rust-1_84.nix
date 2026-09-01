##! Rust 1.84.1 — bootstrap chain intermediate (built with 1.83)
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
  rust-1_83,
  llvm-19,
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
    version = "1.84.1";
    srcHash = "sha256-Xi+11JYopUn3Zxssz5hVqzef1EKDGnwq8W4M3MMbs3U=";
    changeId = 133207;
    prevRust = rust-1_83;
    llvm = llvm-19;
    needsDownloadRustc = true;
  }
