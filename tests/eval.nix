# tests/eval.nix — Layer 1: Pure Nix evaluation checks
#
# No builds, no VMs. Verifies all system configurations evaluate without
# error. The fact that this derivation can be instantiated proves every
# system variant's module graph resolves successfully.
#
# Usage:
#   nix-build -A checks.eval
{
  pkgs,
  lib,
  systems,
}:
# Use a raw derivation with /bin/sh so we don't need to build coreutils.
# The real verification happens at Nix eval time: the builtins.toJSON calls
# force every system variant's config, so any module error causes an
# instantiation failure before the builder even runs.
builtins.derivation {
  name = "aos-eval-checks-0";
  system = lib.system;
  builder = "/bin/sh";
  args = [
    "-c"
    ''
      echo "==> AOS Evaluation Checks"
      echo ""

      echo "base config keys:            ${builtins.toJSON (builtins.attrNames systems.base.config.aos)}"
      echo "server config keys:          ${builtins.toJSON (builtins.attrNames systems.server.config.aos)}"
      echo "k8s-worker config keys:      ${builtins.toJSON (builtins.attrNames systems.k8s-worker.config.aos)}"
      echo "k8s-control-plane config keys: ${builtins.toJSON (builtins.attrNames systems.k8s-control-plane.config.aos)}"

      # Force the build attributes to ensure they evaluate
      echo "base toplevel:      ${systems.base.config.system.build.toplevel.name}"
      echo "server toplevel:    ${systems.server.config.system.build.toplevel.name}"
      echo "base kernel:        ${systems.base.config.system.build.kernel.name}"
      echo "base initrd:        ${systems.base.config.system.build.initrd.name}"
      echo "base systemPkgs:    ${builtins.toString (builtins.length systems.base.config.environment.systemPackages)}"
      echo "server systemPkgs:  ${builtins.toString (builtins.length systems.server.config.environment.systemPackages)}"
      echo "k8s systemPkgs:     ${builtins.toString (builtins.length systems.k8s-worker.config.environment.systemPackages)}"

      echo ""
      echo "==> All eval checks passed."
      echo "PASS" > $out
    ''
  ];
}
