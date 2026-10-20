##! SPIR-V translator linked to the LLVM graphics backend set
{
  callPackage,
  mkDerivation,
  llvm-graphics,
}:
callPackage ./spirv-llvm-translator.nix {
  llvm = llvm-graphics;
  mkDerivation = attrs: mkDerivation (attrs // {pname = "spirv-llvm-translator-graphics";});
}
