##! Rust 1.85.1 — bootstrap chain intermediate (built with 1.84)
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
  rust-1_84,
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
    version = "1.85.1";
    srcHash = "sha256-DymVygg1mHV6jZopOTnlabA1eZ4HD0GaaGsJlvuUI4o=";
    changeId = 134650;
    prevRust = rust-1_84;
    needsDownloadRustc = true;
  }
