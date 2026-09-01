##! Rust 1.77.2 — bootstrap chain intermediate (built with rust-1_76)
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
  rust-1_76,
  llvm-17,
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
    version = "1.77.2";
    srcHash = "sha256-xhRX749ZZjj928dxZ3iy9rmf8SUTo7DxOZTDvFIWOMM=";
    changeId = 102579;
    prevRust = rust-1_76;
    llvm = llvm-17;
  }
