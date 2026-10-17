# Runs the configured cached-writer suite without publishing native binaries.
{pkgs}:
import ./_qemu-focused-unit-builder.nix {inherit pkgs;} {
  attrPath = "checks.crucible.phase7.qemuCachedWriterUnit";
  pname = "crucible-qemu-cached-writer-unit";
  gateName = "gate:qemu-cached-writer-unit";
  description = "Configured QEMU cached-writer scenarios and causal omissions";
  runner = ./qemu-cached-writer-unit.py;
  identityFileName = "qemu-cached-writer-unit-build-identity.env";
  boundPhaseName = "bound-cached-writer-unit-address-space";
  runPhaseName = "build-and-run-cached-writer-unit";
  runnerArguments = "--evidence-helper ${./qemu-startup-source-unit.py}";
}
