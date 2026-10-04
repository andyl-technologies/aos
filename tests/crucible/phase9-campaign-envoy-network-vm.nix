# Authenticate the packaged five-guest Envoy campaign before release.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-envoy-network-vm.nix {inherit pkgs lib;};
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-envoy-network-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "authenticate-envoy-network-evidence";
        script = ''
          set -eu
          raw_result=${flight}/result
          raw_serial=${flight}/serial.log
          test -f "$raw_result" && test ! -L "$raw_result"
          test -f "$raw_serial" && test ! -L "$raw_serial"
          test "$(cat "$raw_result")" = PASS

          # Firecracker serial output uses CRLF; preserve the original log below.
          serial="$TMPDIR/campaign-envoy-network-serial.txt"
          tr -d '\r' < "$raw_serial" > "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line TEST_RESULT:PASS
          test "$(grep -Fxc TEST_RESULT:FAIL "$serial" || true)" -eq 0
          require_serial_line gate=gate:campaign-envoy-network-five-vm
          require_serial_line envoy_five_node_failover_and_recovery_authenticated=true
          require_serial_line envoy_five_node_hot_fork_authenticated=true
          require_serial_line envoy_five_node_hot_fork_resource_isolation_authenticated=true
          require_serial_line envoy_five_node_hot_fork_resource_rejection_authenticated=true
          require_serial_line envoy_five_node_thin_replay_authenticated=true
          require_serial_line envoy_five_node_exact_restore_authenticated=true
          require_serial_line envoy_five_node_retention_authenticated=true
          require_serial_line envoy_five_node_graceful_completion_authenticated=true
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$raw_serial" "$out/evidence/envoy-network-vm.output"
          sha256sum "$out/evidence/envoy-network-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-envoy-network-five-vm
          envoy_five_node_failover_and_recovery_authenticated=true
          envoy_five_node_hot_fork_authenticated=true
          envoy_five_node_hot_fork_resource_isolation_authenticated=true
          envoy_five_node_hot_fork_resource_rejection_authenticated=true
          envoy_five_node_thin_replay_authenticated=true
          envoy_five_node_exact_restore_authenticated=true
          envoy_five_node_retention_authenticated=true
          envoy_five_node_graceful_completion_authenticated=true
          evidence_retained=true
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
