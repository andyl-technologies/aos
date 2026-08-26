##! Rust 1.76.0 — bootstrap chain intermediate (built with rust-1_75)
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
  rust-1_75,
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
    version = "1.76.0";
    srcHash = "sha256-nlz/Azp/DSJmgYmCrZDk0+Tvj47hcVd2xuJQc6E2wCE=";
    changeId = 118703;
    prevRust = rust-1_75;
    llvm = llvm-17;
  }
