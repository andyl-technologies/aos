##! Rust 1.82.0 — bootstrap chain intermediate (built with rust-1_81)
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
  rust-1_81,
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
    version = "1.82.0";
    srcHash = "sha256-fFP0UJ7aGE4XTvprp9XutYZYVobOjt78eBorEafPUSo=";
    changeId = 129295;
    prevRust = rust-1_81;
    llvm = llvm-19;
  }
