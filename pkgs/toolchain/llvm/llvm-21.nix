##! LLVM 21 — compiler infrastructure
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
  version = "21.1.8";
  srcHash = "sha256-RjOiNhf6MaPqUSQlhup/sdpxQOQmvWL8FkJh/gNqoUI=";
}
