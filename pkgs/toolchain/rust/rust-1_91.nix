##! Rust 1.91.1 — bootstrap chain intermediate (built with 1.90)
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
  rust-1_90,
}:
let
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
  version = "1.91.1";
  srcHash = "sha256-ONziBdOfYVcSYfBEQjehzp7+y5cOdg2OxNlXr1tEVyM=";
  changeId = 0;
  prevRust = rust-1_90;
  needsDownloadRustc = true;
  disableLld = true;
}
