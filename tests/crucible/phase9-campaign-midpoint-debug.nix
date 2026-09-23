# Public retained-finding to exact-midpoint debug flight with retained evidence.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    campaignMidpoint = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-midpoint-debug";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "retain-midpoint-evidence";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line gate=gate:campaign-midpoint-debug
          require_serial_line public_finding_midpoint_debug=true
          require_serial_line authenticated_exact_checkpoint=true
          require_serial_line authenticated_replay_violation_boundary=true
          require_serial_line authenticated_replay_selection_sequence=fast,q7
          require_serial_line authenticated_replay_marker=selected-fast-q7
          require_serial_line retry_session_identity_stable=true
          require_serial_line imported_production_capture_handoff=true
          test "$(grep -Ec '^authenticated_replay_causal_entries=[1-9][0-9]*$' "$serial" || true)" -eq 1
          test "$(grep -Ec '^minimization_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' "$serial" || true)" -eq 1
          test "$(grep -Ec '^verification_original_replay=crucible\.campaign\.finding-triage-replay@finding-triage-replay\.[0-9]+\.[0-9a-f]{64}$' "$serial" || true)" -eq 1
          test "$(grep -Ec '^read_only_rsp_stop_class=[TSWX]$' "$serial" || true)" -eq 1
          test "$(grep -Ec '^authenticated_restore_bytes=[1-9][0-9]*$' "$serial" || true)" -eq 1
          test "$(grep -Ec '^authenticated_checkpoint_candidates=([2-9]|[1-9][0-9]+)$' "$serial" || true)" -eq 1
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          replay_causal_entries=$(grep -E '^authenticated_replay_causal_entries=' "$serial" | cut -d = -f 2)
          minimization_original=$(grep -E '^minimization_original_replay=' "$serial" | cut -d = -f 2-)
          verification_original=$(grep -E '^verification_original_replay=' "$serial" | cut -d = -f 2-)
          test "$minimization_original" != "$verification_original"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/public-campaign-midpoint-debug.output"
          sha256sum "$out/evidence/public-campaign-midpoint-debug.output" \
            > "$out/evidence.sha256"
          evidence_digest=$(sha256sum "$out/evidence.sha256" | cut -d ' ' -f 1)

          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-midpoint-debug
          tasks=T-CAM-9.3
          public_finding_midpoint_debug=true
          authenticated_exact_checkpoint=true
          authenticated_replay_violation_boundary=true
          authenticated_replay_selection_sequence=fast,q7
          authenticated_replay_marker=selected-fast-q7
          authenticated_replay_causal_entries=$replay_causal_entries
          minimization_original_replay=$minimization_original
          verification_original_replay=$verification_original
          retry_session_identity_stable=true
          imported_production_capture_handoff=true
          evidence_retained=true
          evidence_manifest_sha256=$evidence_digest
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
