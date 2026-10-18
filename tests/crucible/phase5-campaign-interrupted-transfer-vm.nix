# Real-QEMU executable transfer interruption, journal-root GC and exact resume.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    guestChoice = true;
    interruptedTransfer = true;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-interrupted-transfer-vm";
    version = "0";

    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "retain-interrupted-transfer-evidence";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"

          require_serial_line() {
            line="$1"
            test "$(grep -Fxc "$line" "$serial" || true)" -eq 1
          }

          require_serial_line gate=gate:campaign-interrupted-transfer
          require_serial_line tasks=T-CAM-5.8
          require_serial_line tier=real-packaged-qemu
          for claim in \
            interrupted_transfer_original_corruption_refused=true \
            interrupted_transfer_both_original_journals_retained=true \
            interrupted_transfer_partial_exact_copy_authenticated=true \
            interrupted_transfer_refs_absent_before_completion=true \
            interrupted_transfer_public_gc_preserved_pending_roots=true \
            interrupted_transfer_public_gc_reclaimed_orphans=2 \
            interrupted_transfer_exact_byte_repair=true \
            interrupted_transfer_identical_retry_authenticated=true \
            interrupted_transfer_completed_retry_idempotent=true \
            interrupted_transfer_derived_refs_preserved=2 \
            interrupted_transfer_exact_origin_preserved=true \
            interrupted_transfer_execution_bound_guest_progress=true \
            interrupted_transfer_distinct_authenticated_checkpoint=true \
            interrupted_transfer_selected_outcome_preserved=true \
            interrupted_transfer_owned_guest_cleanup=true
          do
            require_serial_line "$claim"
          done
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/interrupted-transfer-vm.output"
          sha256sum "$out/evidence/interrupted-transfer-vm.output" \
            > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-interrupted-transfer
          tasks=T-CAM-5.8
          tier=real-packaged-qemu
          interrupted_transfer_original_corruption_refused=true
          interrupted_transfer_both_original_journals_retained=true
          interrupted_transfer_partial_exact_copy_authenticated=true
          interrupted_transfer_refs_absent_before_completion=true
          interrupted_transfer_public_gc_preserved_pending_roots=true
          interrupted_transfer_public_gc_reclaimed_orphans=2
          interrupted_transfer_exact_byte_repair=true
          interrupted_transfer_identical_retry_authenticated=true
          interrupted_transfer_completed_retry_idempotent=true
          interrupted_transfer_derived_refs_preserved=2
          interrupted_transfer_exact_origin_preserved=true
          interrupted_transfer_execution_bound_guest_progress=true
          interrupted_transfer_distinct_authenticated_checkpoint=true
          interrupted_transfer_selected_outcome_preserved=true
          interrupted_transfer_owned_guest_cleanup=true
          evidence_retained=true
          RESULT
        '';
      }
    ];

    passthru = {
      rawFlight = flight;
    };
  }
