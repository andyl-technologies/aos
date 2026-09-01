##! Rust 1.75.0 — bootstrap chain intermediate (built with rust-1_74)
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
  rust-1_74,
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
    version = "1.75.0";
    srcHash = "sha256-W3OfRbydNB4tHFcNZdI3VZHiLC0j71uKN3EaA4arwIg=";
    changeId = 116881;
    prevRust = rust-1_74;
    llvm = llvm-17;
  }
