# Actual exact-restored guest progress after supported S3 service failures.
{
  pkgs,
  lib,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    guestChoice = true;
    storageRecovery = true;
  };
  claims = [
    "storage_recovery_real_exact_pause=true"
    "storage_recovery_outage_refused_before_guest=true"
    "storage_recovery_expired_credentials_refused_before_guest=true"
    "storage_recovery_exact_origin_preserved=true"
    "storage_recovery_scheduler_observed_guest_progress=true"
    "storage_recovery_selected_outcome_preserved=true"
    "storage_recovery_derived_refs_preserved=2"
    "storage_recovery_final_guest_cleanup=true"
  ];
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-storage-recovery-vm";
    version = "0";
    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "authenticate-live-storage-recovery";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"
          require_line() {
            test "$(grep -Fxc "$1" "$serial" || true)" -eq 1
          }
          require_line gate=gate:campaign-storage-recovery
          require_line tasks=T-CAM-5.8,T-CAM-9.3
          require_line tier=real-packaged-qemu-and-garage
          ${builtins.concatStringsSep "\n" (map (claim: "require_line ${lib.escapeShellArg claim}") claims)}
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/storage-recovery-vm.output"
          sha256sum "$out/evidence/storage-recovery-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-storage-recovery
          tasks=T-CAM-5.8,T-CAM-9.3
          tier=real-packaged-qemu-and-garage
          ${builtins.concatStringsSep "\n" claims}
          evidence_retained=true
          RESULT
        '';
      }
    ];
    passthru.rawFlight = flight;
  }
