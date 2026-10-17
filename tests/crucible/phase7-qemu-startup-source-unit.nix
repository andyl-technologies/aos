# Builds the registered unit and its real QEMU support without installing a binary.
{pkgs}:
import ./_qemu-focused-unit-builder.nix {inherit pkgs;} {
  attrPath = "checks.crucible.phase7.qemuStartupSourceUnit";
  pname = "crucible-qemu-startup-source-unit";
  gateName = "gate:qemu-startup-source-unit";
  description = "Registered QEMU startup Source unit TAP and build evidence";
  runner = ./qemu-startup-source-unit.py;
  identityFileName = "qemu-startup-unit-build-identity.env";
  boundPhaseName = "bound-startup-unit-address-space";
  runPhaseName = "build-and-run-startup-source-unit";
}
