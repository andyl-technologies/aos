##! Rust 1.88.0 — bootstrap chain intermediate (built with 1.87)
{ mkDerivation, fetchurl, gnumake, cmake, ninja, pkg-config, python3, bash, which, openssl, zlib, rust-1_87 }:
let
  mkRustBootstrap = import ./_rust-bootstrap.nix {
    inherit fetchurl mkDerivation gnumake cmake ninja pkg-config python3 bash which openssl zlib;
  };
in
mkRustBootstrap {
  version = "1.88.0";
  srcHash = "sha256-OpdURDSEiuPRk9HWvIPW8ky4XCYa2V+VX95H7GTPz74=";
  changeId = 0;
  prevRust = rust-1_87;
  needsDownloadRustc = true;
}
