# A fresh Linux/x86 SDK workload, separate from the existing ownership guest.
{
  pkgs,
  source,
  cargoDeps,
  runtimeObserver ? null,
}:
import ./_static-sdk-guest.nix {
  inherit pkgs source cargoDeps;
  pname = "crucible-guest-clock-read-initramfs";
  example = "crucible-guest-clock-read";
  rootName = "clock-read";
  extraPackages =
    if runtimeObserver == null
    then []
    else [runtimeObserver];
  extraFiles =
    if runtimeObserver == null
    then {}
    else {
      clock-vvar-observer = "${runtimeObserver}/bin/clock-vvar-observer";
    };
  cargoEnv =
    if runtimeObserver == null
    then {}
    else {
      CRUCIBLE_GUEST_CLOCK_VVAR_OBSERVER = "1";
    };
  evidence = ''
    guest_format=diskless-linux-initramfs
    guest_init=pid1-sdk-clock-read-equivalence
    guest_calls=clock_gettime-realtime,clock_gettime-monotonic,gettimeofday,rdtsc
    guest_read_boundary=typed-semantic-pre-post-markers
    guest_clock_read_batches=2
    guest_idle=original-linux-nanosleep-kernel-idle-wait
    guest_cpu_affinity=0
  '';
}
