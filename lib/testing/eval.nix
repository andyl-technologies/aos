# lib/testing/eval.nix — Layer 1: Pure Nix evaluation checks
#
# No builds, no VMs. Verifies the system configuration evaluates without
# error. The fact that this derivation can be instantiated proves the
# module graph resolves successfully.
#
# Usage:
#   nix-build -A checks.eval
{
  pkgs,
  lib,
  system,
}:
# Use a raw derivation with /bin/sh so we don't need to build coreutils.
# The real verification happens at Nix eval time: the builtins.toJSON calls
# force the system config, so any module error causes an instantiation
# failure before the builder even runs.
builtins.derivation {
  name = "aos-eval-checks-0";
  system = lib.system;
  builder = "/bin/sh";
  args = [
    "-c"
    ''
      echo "==> AOS Evaluation Checks"
      echo ""

      echo "config keys:    ${builtins.toJSON (builtins.attrNames system.config.aos)}"

      # Force the build attributes to ensure they evaluate
      echo "toplevel:       ${system.config.system.build.toplevel.name}"
      echo "kernel:         ${system.config.system.build.kernel.name}"
      echo "initrd:         ${system.config.system.build.initrd.name}"
      echo "systemPkgs:     ${builtins.toString (builtins.length system.config.environment.systemPackages)}"

      echo ""
      echo "==> All eval checks passed."
      echo "PASS" > $out
    ''
  ];
}
