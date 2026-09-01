##! Rust 1.89.0 — bootstrap chain intermediate (built with 1.88)
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
  rust-1_88,
  llvm-20,
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
    version = "1.89.0";
    srcHash = "sha256-JXb59EDdmbAVG9KPWaoKxhAtXE8+1O+KgQyN0FBXJQ0=";
    changeId = 0;
    prevRust = rust-1_88;
    llvm = llvm-20;
    needsDownloadRustc = true;
    disableLld = true;
  }
