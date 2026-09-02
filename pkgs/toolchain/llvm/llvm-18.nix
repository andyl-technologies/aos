##! LLVM 18 — compiler infrastructure
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
    version = "18.1.8";
    srcHash = "sha256-C1hVem0yzu6XyNUzpZuSEth+D8TSgzkk62xhEkfbLyo=";
  }
