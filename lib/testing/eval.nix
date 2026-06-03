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
}: let
  # The kernel-lockdown option was removed: SECURITY_LOCKDOWN_LSM selects
  # MODULE_SIG, whose default key generation breaks third-party
  # bit-reproducibility of the public base image. Fail loudly at eval time
  # if the option declaration ever reappears.
  noKernelLockdown =
    if system.options.aos.security.hardening ? kernelLockdown
    then throw "aos.security.hardening.kernelLockdown must not exist; kernel lockdown pulls in module signing and is not part of the reproducible public base"
    else "ok";
in
  # Use a raw derivation with AOS bash so we don't pull in host tools.
  # The real verification happens at Nix eval time: the builtins.toJSON calls
  # force the system config, so any module error causes an instantiation
  # failure before the builder even runs.
  builtins.derivation {
    name = "aos-eval-checks-0";
    system = lib.system;
    builder = "${pkgs.bash}/bin/bash";
    args = [
      "-c"
      ''
        echo "==> AOS Evaluation Checks"
        echo ""

        echo "config keys:    ${builtins.toJSON (builtins.attrNames system.config.aos)}"
        echo "kernelLockdown: removed (${noKernelLockdown})"

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
