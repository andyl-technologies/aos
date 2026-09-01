##! Rust 1.80.1 — bootstrap chain intermediate (built with rust-1_79)
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
  rust-1_79,
  llvm-18,
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
    version = "1.80.1";
    srcHash = "sha256-LAuPZDlC3LgQy8xQ8pJWSxtuRNtdX0UJEVOZbfldLcQ=";
    changeId = 125535;
    prevRust = rust-1_79;
    llvm = llvm-18;
  }
