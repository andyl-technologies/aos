##! LLVM 19 — compiler infrastructure
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
  python3,
  zlib,
  bootstrapTools,
}:
let
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
      ;
  };
in
mkLLVM {
  version = "19.1.1";
  srcHash = "sha256-1A6TPiogjuFCiY+F2IZCOiF+mRq7zULdghH1B8k+EmY=";
}
