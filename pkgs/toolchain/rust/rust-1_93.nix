##! Rust 1.93.1 — bootstrap chain intermediate (built with 1.92)
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
  curl,
  openssl,
  zlib,
  stdenv,
  buildPackages,
  rust-1_92,
  llvm,
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
      curl
      openssl
      zlib
      stdenv
      buildPackages
      ;
  };
in
  mkRustBootstrap {
    version = "1.93.1";
    srcHash = "sha256-TCMKRLPZyfPO+VCUNxn4OABY0nyR/aXjapqUfvAT4B8=";
    changeId = 148795;
    prevRust = rust-1_92;
    inherit llvm;
    needsDownloadRustc = true;
    useBootstrapToml = true;
    disableLld = true;
  }
