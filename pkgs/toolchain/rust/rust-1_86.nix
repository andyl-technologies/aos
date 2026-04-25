##! Rust 1.86.0 — bootstrap chain intermediate (built with 1.85)
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
  rust-1_85,
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
      ;
  };
in
  mkRustBootstrap {
    version = "1.86.0";
    srcHash = "sha256-AionKG32eQCgRNIn2dtp1HMuw9gz5P/CWcRCXtce7YA=";
    changeId = 0;
    prevRust = rust-1_85;
    needsDownloadRustc = true;
  }
