# Real-QEMU campaign policy timeout and retained causal evidence.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    policyTimeout = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-policy-timeout-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "retain-policy-timeout-evidence";
        script = ''
          set -eu
          raw_serial=${flight}/serial.log
          test -f "$raw_serial"
          # Firecracker serial output uses CRLF; retain the raw log as evidence.
          serial="$TMPDIR/campaign-policy-timeout-serial.txt"
          tr -d '\r' < "$raw_serial" > "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line gate=gate:campaign-policy-timeout-real-qemu
          require_serial_line proven=typed-policy-timeout,retained-causal-marker
          require_serial_line packaged_policy_timeout_observation_authenticated=true
          require_serial_line packaged_policy_timeout_marker_authenticated=true
          require_serial_line public_packaged_policy_timeout_causal_evidence=true
          require_serial_line TEST_RESULT:PASS
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$raw_serial" "$out/evidence/campaign-policy-timeout-vm.output"
          sha256sum "$out/evidence/campaign-policy-timeout-vm.output" \
            > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-policy-timeout-real-qemu
          tier=real-packaged-qemu
          modeled_campaign_virtual_time_timeout=true
          typed_policy_timeout_authenticated=true
          retained_causal_marker_authenticated=true
          retained_timeout_finding=true
          evidence_retained=true
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
