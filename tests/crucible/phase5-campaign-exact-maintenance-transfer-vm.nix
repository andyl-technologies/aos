# Real-QEMU exact pause and executable maintenance transfer.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    guestChoice = true;
    maintenanceTransfer = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-exact-maintenance-transfer-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "retain-exact-maintenance-transfer-evidence";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line gate=gate:campaign-exact-maintenance-transfer
          require_serial_line tasks=T-CAM-5.8
          require_serial_line tier=real-packaged-qemu
          for claim in \
            source_active_world_exact_pause_restart=true \
            source_exact_resume_progress=true \
            source_nested_qemu_stopped=true \
            recipient_executable_archive_authenticated=true \
            recipient_exact_pin_import_authenticated=true \
            recipient_campaign_resume=true \
            recipient_imported_attempt_running=true \
            recipient_nested_qemu_stopped=true \
            incompatible_provenance_rejected_before_guest=true \
            source_checkpoint_preserved=true
          do
            require_serial_line "$claim"
          done
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/exact-maintenance-transfer-vm.output"
          sha256sum "$out/evidence/exact-maintenance-transfer-vm.output" \
            > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-exact-maintenance-transfer
          tasks=T-CAM-5.8
          tier=real-packaged-qemu
          source_active_world_exact_pause_restart=true
          source_exact_resume_progress=true
          source_nested_qemu_stopped=true
          recipient_executable_archive_authenticated=true
          recipient_exact_pin_import_authenticated=true
          recipient_campaign_resume=true
          recipient_imported_attempt_running=true
          recipient_nested_qemu_stopped=true
          incompatible_provenance_rejected_before_guest=true
          source_checkpoint_preserved=true
          evidence_retained=true
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
