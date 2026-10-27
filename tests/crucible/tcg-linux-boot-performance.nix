# Repeats the admitted serial-readiness workload in an isolated quota/UFFD kernel.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  pluginPackage ? pkgs.crucible-qemu-plugin,
}:
import ./tcg-managed-performance.nix {
  inherit pkgs lib qemuPackage pluginPackage;
  attrPath = "checks.crucible.phase2.tcgLinuxBootPerformanceDeterminism";
  workloads = ["linux"];
}
