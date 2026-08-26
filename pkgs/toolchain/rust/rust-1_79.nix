##! Rust 1.79.0 — bootstrap chain intermediate (built with rust-1_78)
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
  rust-1_78,
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
    version = "1.79.0";
    srcHash = "sha256-Fy7PPH0fnZ+xbNKmKIaXgmcEFt7QEp5SSoZ1H5YUSMA=";
    changeId = 123711;
    prevRust = rust-1_78;
    llvm = llvm-18;
  }
