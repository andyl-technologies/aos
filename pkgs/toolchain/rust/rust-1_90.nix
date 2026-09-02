##! Rust 1.90.0 — bootstrap chain intermediate (built with 1.89)
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
  rust-1_89,
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
    version = "1.90.0";
    srcHash = "sha256-eZqfnLpO1TUeBxBIvPa1VgdV2QCWSN7zOkB91JYfm34=";
    changeId = 0;
    prevRust = rust-1_89;
    llvm = llvm-20;
    needsDownloadRustc = true;
    disableLld = true;
  }
