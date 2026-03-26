##! Rust 1.81.0 — bootstrap chain intermediate (built with rust-1_80)
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
  rust-1_80,
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
  version = "1.81.0";
  srcHash = "sha256-hyRI/r3/MuUMPJCn4V+bstsTHRPFiP6QcbDtiIN8z6c=";
  changeId = 127866;
  prevRust = rust-1_80;
}
