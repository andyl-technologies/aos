##! Rust 1.97.0 — bootstrap chain intermediate (built with 1.96)
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
  rust-1_96,
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
    version = "1.97.0";
    srcHash = "sha256-HAhV2JgqD7HQMhtgVLVbcy07HRfIRoQet/0Ks3vydvg=";
    changeId = 154587;
    prevRust = rust-1_96;
    inherit llvm;
    needsDownloadRustc = true;
    useBootstrapToml = true;
    disableLld = true;
  }
