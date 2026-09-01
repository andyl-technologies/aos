##! Rust 1.78.0 — bootstrap chain intermediate (built with rust-1_77)
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
  rust-1_77,
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
    version = "1.78.0";
    srcHash = "sha256-/1RII6XLJ/JzgShXfx5+AO6PTIPyo0h4GuT8NV6R1ak=";
    changeId = 121754;
    prevRust = rust-1_77;
    llvm = llvm-18;
  }
