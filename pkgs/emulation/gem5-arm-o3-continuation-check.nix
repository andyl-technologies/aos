##! gem5 AArch64 O3/cache/DRAM process-image witness — not complete qualification
{
  mkDerivation,
  gem5,
  dmtcp,
  gem5-process-custody,
  coreutils,
  diffutils,
  grep,
  llvm,
}:
import ./_gem5/o3-witness.nix {
  inherit mkDerivation gem5 dmtcp coreutils diffutils grep;
  processCustody = gem5-process-custody;
  pname = "gem5-arm-o3-continuation-check";
  guestIsa = "aarch64";
  additionalBuildDeps = [llvm];
  compileGuest = ''
    ${llvm}/bin/clang --target=aarch64-linux-gnu -nostdlib -static \
      -fuse-ld=lld -Wl,--build-id=none \
      ${./_gem5/o3-memory-workload-aarch64.S} -o workload
  '';
}
