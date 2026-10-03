# Authenticate one measured network failure and its packaged replay.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    envoyKnownFinding = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-known-finding-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "authenticate-known-finding-evidence";
        script = ''
          set -eu
          raw_result=${flight}/result
          raw_serial=${flight}/serial.log
          test -f "$raw_result" && test ! -L "$raw_result"
          test -f "$raw_serial" && test ! -L "$raw_serial"
          test "$(cat "$raw_result")" = PASS

          serial="$TMPDIR/campaign-known-finding-serial.txt"
          tr -d '\r' < "$raw_serial" > "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line TEST_RESULT:PASS
          test "$(grep -Fxc TEST_RESULT:FAIL "$serial" || true)" -eq 0
          require_serial_line gate=gate:campaign-envoy-known-finding
          require_serial_line envoy_known_finding_measured_objective=true
          require_serial_line envoy_known_finding_rank_filtered=true
          require_serial_line envoy_known_finding_fresh_packaged_replay=true
          require_serial_line public_product_finding_debug_authenticated=true
          require_serial_line envoy_product_branch_steering_authenticated=true
          require_serial_line envoy_product_retention_and_cleanup_authenticated=true
          require_serial_line envoy_known_finding_authenticated=true
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$raw_serial" "$out/evidence/known-finding-vm.output"
          sha256sum "$out/evidence/known-finding-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-envoy-known-finding
          task=T-CAM-3.6
          measured_objective_authenticated=true
          failed_candidate_filtered=true
          fresh_packaged_replay_authenticated=true
          product_finding_debug_authenticated=true
          product_branch_steering_authenticated=true
          product_retention_and_cleanup_authenticated=true
          envoy_known_finding_authenticated=true
          evidence_retained=true
          RESULT
        '';
      }
    ];

    passthru.rawFlight = flight;
  }
