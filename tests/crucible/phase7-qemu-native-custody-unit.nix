# Runs standalone custody controls with real configured support and separate bounds.
{pkgs}:
import ./_qemu-focused-unit-builder.nix {inherit pkgs;} {
  attrPath = "checks.crucible.phase7.qemuNativeCustodyUnit";
  pname = "crucible-qemu-native-custody-unit";
  gateName = "gate:qemu-native-custody-unit";
  description = "Standalone native custody controls with authenticated QEMU inputs";
  runner = ./qemu-native-custody-unit.py;
  runnerArguments = "--base-runner ${./qemu-startup-source-unit.py}";
  identityFileName = "qemu-native-custody-build-identity.env";
  boundPhaseName = "bound-native-custody-address-space";
  runPhaseName = "build-and-run-native-custody-unit";
}
