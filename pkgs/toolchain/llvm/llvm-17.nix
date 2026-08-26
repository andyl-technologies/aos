##! LLVM 17 — compiler infrastructure
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
  bootstrapTools,
  stdenv,
  buildPackages,
}: let
  mkLLVM = import ./_llvm.nix {
    inherit
      mkDerivation
      fetchurl
      gnumake
      cmake
      ninja
      python3
      zlib
      bootstrapTools
      stdenv
      buildPackages
      ;
  };
in
  mkLLVM {
    version = "17.0.6";
    srcHash = "sha256-WKiBjGDmYnBk8xLb9GwC2ZSZVlWDQJOLcc9zGti8CBM=";
  }
