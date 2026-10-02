##! LLVM — compiler infrastructure (default = LLVM 22)
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
  zstd,
  libxml2,
  libedit,
  bootstrapTools,
  stdenv,
  buildPackages,
}: let
  target = import ./llvm-22.nix {
  inherit
    lib
    mkDerivation
    fetchurl
    gnumake
    cmake
    ninja
    python3
    zlib
    zstd
    libxml2
    libedit
    bootstrapTools
    stdenv
    buildPackages
    ;
  };
in
  target.overrideAttrs (_: {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
  })
