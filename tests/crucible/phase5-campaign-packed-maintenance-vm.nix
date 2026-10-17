# Real exact-restored guest progress after packed repack, corruption and GC.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    guestChoice = true;
    packedMaintenance = true;
  };
  claims = [
    "packed_maintenance_real_exact_pause=true"
    "packed_maintenance_public_repack_authenticated=true"
    "packed_maintenance_corrupt_index_refused_before_guest=true"
    "packed_maintenance_original_index_restored=true"
    "packed_maintenance_nonempty_gc_preserves_checkpoint=true"
    "packed_maintenance_exact_origin_preserved=true"
    "packed_maintenance_scheduler_observed_guest_progress=true"
    "packed_maintenance_distinct_authenticated_checkpoint=true"
    "packed_maintenance_selected_outcome_preserved=true"
    "packed_maintenance_derived_refs_preserved=2"
    "packed_maintenance_final_guest_cleanup=true"
  ];
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-packed-maintenance-vm";
    version = "0";
    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "authenticate-packed-checkpoint-maintenance";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"
          require_line() {
            test "$(grep -Fxc "$1" "$serial" || true)" -eq 1
          }
          require_line gate=gate:campaign-packed-maintenance
          require_line tasks=T-CAM-5.8
          require_line tier=real-packaged-qemu
          ${builtins.concatStringsSep "\n" (map (claim: "require_line ${lib.escapeShellArg claim}") claims)}
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/packed-maintenance-vm.output"
          sha256sum "$out/evidence/packed-maintenance-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-packed-maintenance
          tasks=T-CAM-5.8
          tier=real-packaged-qemu
          ${builtins.concatStringsSep "\n" claims}
          evidence_retained=true
          RESULT
        '';
      }
    ];
    passthru.rawFlight = flight;
  }
