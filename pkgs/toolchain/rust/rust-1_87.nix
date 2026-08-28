##! Rust 1.87.0 — bootstrap chain intermediate (built with 1.86)
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
  rust-1_86,
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
    version = "1.87.0";
    srcHash = "sha256-FJu5/Sm+WS2k6HkA/GjwYpo3v2hQtGM53URDTAT9jnY=";
    changeId = 0;
    prevRust = rust-1_86;
    llvm = llvm-20;
    needsDownloadRustc = true;
    disableDarwinLld = true;
  }
