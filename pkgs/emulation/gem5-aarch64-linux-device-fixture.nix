##! Freestanding source-built AArch64 PID1 with Linux device roundtrip probes
{
  mkDerivation,
  gem5-aarch64-linux,
  llvm-gem5,
  python3,
  diffutils,
}:
import ./_gem5/linux-device-fixture.nix {
  inherit mkDerivation llvm-gem5 python3 diffutils;
  pname = "gem5-aarch64-linux-device-fixture";
  architecture = "aarch64";
  targetTriple = "aarch64-linux-gnu";
  kernelHeaders = gem5-aarch64-linux;
  kernelHeaderSource = gem5-aarch64-linux.source;
  kernelHeaderRecipe = ./gem5-aarch64-linux.nix;
  recipe = ./gem5-aarch64-linux-device-fixture.nix;
}
