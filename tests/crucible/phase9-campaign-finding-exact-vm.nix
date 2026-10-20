# Fresh-process exact finding replay and read-only midpoint inspection.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    findingExactBundle = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase9-campaign-finding-exact-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "retain-exact-finding-evidence";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line gate=gate:campaign-finding-exact-read-only
          require_serial_line finding_bundle_fresh_process_exact_qemu=true
          require_serial_line finding_bundle_source_owner_absent=true
          require_serial_line finding_bundle_signature_and_terminal_reproduced=true
          require_serial_line finding_bundle_live_midpoint_read_only=true
          require_serial_line finding_bundle_mutation_rejected_and_checkpoint_unchanged=true
          require_serial_line finding_bundle_tamper_rejected=true
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/finding-exact-vm.output"
          sha256sum "$out/evidence/finding-exact-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-finding-exact-read-only
          finding_bundle_fresh_process_exact_qemu=true
          finding_bundle_source_owner_absent=true
          finding_bundle_signature_and_terminal_reproduced=true
          finding_bundle_live_midpoint_read_only=true
          finding_bundle_mutation_rejected_and_checkpoint_unchanged=true
          finding_bundle_tamper_rejected=true
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
