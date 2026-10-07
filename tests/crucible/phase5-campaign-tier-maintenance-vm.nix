# Real exact-restored guest progress after tier cache eviction and authenticated promotion.
{
  pkgs,
  lib,
  idlePlanDiagnosticMinimumPs ? null,
}: let
  flight = import ./phase4-packaged-campaign-vm.nix {
    inherit pkgs lib;
    guestChoice = true;
    tierMaintenance = true;
    inherit idlePlanDiagnosticMinimumPs;
  };
  claims = [
    "tier_maintenance_real_exact_pause=true"
    "tier_maintenance_stale_gc_refused_before_deletion=true"
    "tier_maintenance_reachable_cache_evicted=true"
    "tier_maintenance_required_restore_preserved=true"
    "tier_maintenance_authenticated_cache_repromoted=true"
    "tier_maintenance_exact_origin_preserved=true"
    "tier_maintenance_scheduler_observed_guest_progress=true"
    "tier_maintenance_distinct_authenticated_checkpoint=true"
    "tier_maintenance_selected_outcome_preserved=true"
    "tier_maintenance_derived_refs_preserved=2"
    "tier_maintenance_final_guest_cleanup=true"
  ];
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-campaign-tier-maintenance-vm${lib.optionalString (idlePlanDiagnosticMinimumPs != null) "-idle-diagnostics"}";
    version = "0";
    buildDeps = [pkgs.coreutils pkgs.grep flight];

    phases = [
      {
        name = "authenticate-tier-checkpoint-maintenance";
        script = ''
          set -eu
          serial=${flight}/serial.log
          test -f "$serial"
          require_line() {
            test "$(grep -Fxc "$1" "$serial" || true)" -eq 1
          }
          require_line gate=gate:campaign-tier-maintenance
          require_line tasks=T-CAM-5.8
          require_line tier=real-packaged-qemu
          ${builtins.concatStringsSep "\n" (map (claim: "require_line ${lib.escapeShellArg claim}") claims)}
          grep -Fq 'test result: ok. 1 passed; 0 failed; 0 ignored;' "$serial"

          mkdir -p "$out/evidence"
          cp "$serial" "$out/evidence/tier-maintenance-vm.output"
          sha256sum "$out/evidence/tier-maintenance-vm.output" > "$out/evidence.sha256"
          cat > "$out/result" <<RESULT
          PASS
          gate=gate:campaign-tier-maintenance
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
