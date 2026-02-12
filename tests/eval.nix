# tests/eval.nix — Layer 1: Pure Nix evaluation checks
#
# No builds, no VMs. Verifies all system configurations evaluate without
# error. The fact that this derivation can be instantiated proves every
# system variant's module graph resolves successfully.
#
# Usage:
#   nix-build -A checks.eval

{ pkgs, lib, systems }:

pkgs.mkDerivation {
  pname = "aos-eval-checks";
  version = "0";
  src = null;

  phases = [
    {
      name = "check";
      script = ''
        echo "==> AOS Evaluation Checks"
        echo ""

        # Each system variant must evaluate without error.
        # The Nix evaluator forces these strings at build time, so if
        # any module graph has an error, this derivation will fail to
        # instantiate (before the builder even runs).
        echo "base config keys:            ${builtins.toJSON (builtins.attrNames systems.base.config.aos)}"
        echo "server config keys:          ${builtins.toJSON (builtins.attrNames systems.server.config.aos)}"
        echo "k8s-worker config keys:      ${builtins.toJSON (builtins.attrNames systems.k8s-worker.config.aos)}"
        echo "k8s-control-plane config keys: ${builtins.toJSON (builtins.attrNames systems.k8s-control-plane.config.aos)}"

        echo ""
        echo "==> All eval checks passed."
        mkdir -p $out
        echo "PASS" > $out/result
      '';
    }
  ];
}
