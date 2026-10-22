# Links ordinary QEMU consumers against the genuine configured common archive.
{pkgs}:
import ./_qemu-focused-unit-builder.nix {inherit pkgs;} {
  attrPath = "checks.crucible.phase7.qemuCommonUnit";
  pname = "crucible-qemu-common-unit";
  gateName = "gate:qemu-common-unit";
  description = "Configured QEMU RCU, JSON and input visitor common-library tests";
  runner = ./qemu-common-unit.py;
  identityFileName = "qemu-common-unit-build-identity.env";
  boundPhaseName = "bound-common-unit-address-space";
  runPhaseName = "build-and-run-common-unit";
  runnerArguments = "--evidence-helper ${./qemu-startup-source-unit.py} --nm ${pkgs.binutils}/bin/nm";
}
