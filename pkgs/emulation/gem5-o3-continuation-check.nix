##! gem5 x86 O3/cache/DRAM process-image witness — not complete qualification
{
  mkDerivation,
  gem5,
  dmtcp,
  gem5-process-custody,
  coreutils,
  diffutils,
  grep,
}:
import ./_gem5/o3-witness.nix {
  inherit mkDerivation gem5 dmtcp coreutils diffutils grep;
  processCustody = gem5-process-custody;
  pname = "gem5-o3-continuation-check";
  guestIsa = "x86_64";
  compileGuest = ''
    cc -nostdlib -static -no-pie -Wl,--build-id=none \
      ${./_gem5/o3-memory-workload.S} -o workload
  '';
}
