# Exercises the real optional consumer with its complete matching runtime.
{pkgs}:
import ./_qemu-focused-unit-builder.nix {inherit pkgs;} {
  attrPath = "checks.crucible.phase7.qemuBoundedThreadUnit";
  pname = "crucible-qemu-bounded-thread-unit";
  gateName = "gate:qemu-bounded-thread-unit";
  description = "Registered QEMU supplied-stack consumer with the matching bounded-thread libc";
  runner = ./qemu-bounded-thread-unit.py;
  compiler = pkgs.crucible-cc;
  testTimeoutSeconds = 30;
  runnerArguments = "--base-runner ${./qemu-startup-source-unit.py} --runtime ${pkgs.glibc-crucible} --runtime-header ${pkgs.glibc-crucible.dev}/include/pthread-bounded.h --readelf ${pkgs.binutils}/bin/readelf";
  identityFileName = "qemu-bounded-thread-build-identity.env";
  boundPhaseName = "bound-bounded-thread-address-space";
  runPhaseName = "build-and-run-bounded-thread-unit";
}
