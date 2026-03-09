##! LLVM 22 — compiler infrastructure
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
  version = "22.1.0";
  srcHash = "sha256-JdLircQ1bXWEBd2IX8/WRHvOgqkOt4trh84JNL0HcXM=";
}
