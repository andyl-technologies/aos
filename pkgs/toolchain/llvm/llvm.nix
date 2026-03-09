##! LLVM — compiler infrastructure (default = LLVM 22)
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
import ./llvm-22.nix {
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
}
