##! Freestanding source-built x86-64 Linux PID1 and deterministic device initramfs
{
  mkDerivation,
  linux-headers,
  llvm-gem5,
  python3,
  diffutils,
}:
import ./_gem5/linux-device-fixture.nix {
  inherit mkDerivation llvm-gem5 python3 diffutils;
  pname = "gem5-x86-linux-device-fixture";
  architecture = "x86_64";
  targetTriple = "x86_64-linux-gnu";
  kernelHeaders = linux-headers;
  kernelHeaderSource = linux-headers.src;
  kernelHeaderRecipe = ../kernel/linux-headers.nix;
  recipe = ./gem5-x86-linux-device-fixture.nix;
}
