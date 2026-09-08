##! Rust 1.95.0 — bootstrap chain intermediate (built with 1.94)
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
  rust-1_94,
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
    version = "1.95.0";
    srcHash = "sha256-6puCqD5GlnU3w1ac6db6FoEcBDqW5lE3bDSecCQcpRU=";
    changeId = 148671;
    prevRust = rust-1_94;
    inherit llvm;
    needsDownloadRustc = true;
    useBootstrapToml = true;
    disableLld = true;
  }
