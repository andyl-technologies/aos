# Require both the successful Envoy route and its retained, debuggable failure.
{
  pkgs,
  lib,
}: let
  network = import ./phase9-campaign-envoy-network-vm.nix {inherit pkgs lib;};
  finding = import ./phase9-campaign-known-finding-vm.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-envoy-product-lifecycle";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep network finding];

    phases = [
      {
        name = "authenticate-envoy-product-lifecycle";
        script = ''
          set -eu
          test "$(head -n 1 ${network}/result)" = PASS
          test "$(head -n 1 ${finding}/result)" = PASS

          ${pkgs.grep}/bin/grep -Fxq 'envoy_five_node_failover_and_recovery_authenticated=true' ${network}/result
          ${pkgs.grep}/bin/grep -Fxq 'envoy_five_node_graceful_completion_authenticated=true' ${network}/result
          ${pkgs.grep}/bin/grep -Fxq 'product_finding_debug_authenticated=true' ${finding}/result
          ${pkgs.grep}/bin/grep -Fxq 'product_branch_steering_authenticated=true' ${finding}/result
          ${pkgs.grep}/bin/grep -Fxq 'product_retention_and_cleanup_authenticated=true' ${finding}/result
          ${pkgs.grep}/bin/grep -Fxq 'fresh_packaged_replay_authenticated=true' ${finding}/result

          mkdir -p "$out/evidence"
          cp ${network}/evidence/envoy-network-vm.output "$out/evidence/success-vm.output"
          cp ${finding}/evidence/known-finding-vm.output "$out/evidence/finding-vm.output"
          sha256sum "$out/evidence/success-vm.output" "$out/evidence/finding-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-envoy-product-lifecycle
          task=T-CAM-8.6
          five_vm_failover_and_recovery_authenticated=true
          finding_to_debug_authenticated=true
          branch_steering_authenticated=true
          retention_and_cleanup_authenticated=true
          evidence_retained=true
          RESULT
        '';
      }
    ];

    passthru = {
      successFlight = network;
      findingFlight = finding;
    };
  }
