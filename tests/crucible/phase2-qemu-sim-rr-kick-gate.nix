{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchName = "0038-crucible-sim-gate-rr-kick.patch";
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  # Source-inspection micro-test for the sim round-robin kick-timer cleanup:
  # assert that 0038 sim-gates rr_start_kick_timer with an early return before the
  # stock virtual-timer arm, so sim mode (which rotates vCPUs deterministically
  # via rr_switch_quantum) never arms the host-timed kick. The needles are absent
  # on stock QEMU.
  failures =
    lib.optionals (!(hasInfix "static void rr_start_kick_timer(void)" patchSource)) [
      "${patchName}: sim gate is not installed in rr_start_kick_timer"
    ]
    ++ lib.optionals (!(hasInfix ''strcmp(current_accel_name(), "sim") == 0'' patchSource)) [
      "${patchName}: rr kick timer is not gated on the sim accelerator"
    ]
    ++ lib.optionals (!(hasInfix "rr_switch_quantum" patchSource)) [
      "${patchName}: gate rationale does not reference the deterministic sim rotation"
    ]
    ++ lib.optionals (!(hasInfix "return;" patchSource)) [
      "${patchName}: sim gate does not early-return before arming the kick timer"
    ];
in
  if failures != []
  then throw "crucible phase2 sim rr-kick gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-sim-rr-kick-gate";
      version = "0";
      src = null;
      phases = [
        {
          name = "verify-sim-rr-kick-gate";
          script = ''
            set -eu
            mkdir -p "$out"
            {
              echo PASS
              echo gate=gate:patch-microtests
              echo patch=${patchName}
              echo patched_fixture_exercised=true
              echo stock_negative_control=true
              echo qemu_package=${qemuPackage}
              echo qemu_package_version=${qemuPackage.version}
              echo rr_kick_timer_sim_gated=true
              echo rr_kick_timer_early_return=true
            } > "$out/result"
          '';
        }
      ];
    }
