##! Rust 1.83.0 — bootstrap chain intermediate (built with rust-1_82)
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
  rust-1_82,
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
    version = "1.83.0";
    srcHash = "sha256-ci13O9Tqstgo1901tZ8LAX3fmpfuK0bBt/f6xciEHG4=";
    changeId = 131075;
    prevRust = rust-1_82;
    llvm = llvm-19;
  }
