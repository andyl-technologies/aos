{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchName = "0037-crucible-sim-freeze-warp-at-observation-boundary.patch";
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  # Source-inspection micro-test for the terminal-fingerprint determinism root
  # fix: assert that 0037 installs the sim-only warp-freeze clamp gate inside
  # icount_start_warp_timer. The effect is only observable at runtime through the
  # C-trace terminal path (the observer registrant), so a runtime-probe upgrade
  # is tracked separately; the focused source assertions here are absent on stock
  # QEMU (the needles live only in the patch) and pin the gate's exact predicate.
  failures =
    lib.optionals (!(hasInfix "void icount_start_warp_timer(void)" patchSource)) [
      "${patchName}: freeze gate is not installed in icount_start_warp_timer"
    ]
    ++ lib.optionals (!(hasInfix "crucible_sim_observer_registered()" patchSource)) [
      "${patchName}: freeze gate is not guarded on the registered sim observer"
    ]
    ++ lib.optionals (!(hasInfix "icount_get_raw() >= crucible_sim_observer_max_advance_icount()" patchSource)) [
      "${patchName}: freeze gate does not clamp at the observer max-advance boundary"
    ]
    ++ lib.optionals (!(hasInfix ''strcmp(current_accel_name(), "sim")'' patchSource)) [
      "${patchName}: freeze gate is not restricted to the sim accelerator"
    ]
    ++ lib.optionals (!(hasInfix "qemu_clock_notify(QEMU_CLOCK_VIRTUAL)" patchSource)) [
      "${patchName}: freeze gate does not notify the virtual clock before returning"
    ]
    ++ lib.optionals (!(hasInfix ''#include "tcg-accel-ops-sim-shmem.h"'' patchSource)) [
      "${patchName}: observer-helper declarations are not brought into scope"
    ];
in
  if failures != []
  then throw "crucible phase2 sim warp-freeze check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-sim-warp-freeze";
      version = "0";
      src = null;
      phases = [
        {
          name = "verify-sim-warp-freeze";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            freeze_gate_in_warp_timer=true
            freeze_gate_sim_only=true
            freeze_gate_clamped_at_observer_boundary=true
            freeze_gate_notifies_virtual_clock=true
            observer_helpers_in_scope=true
            qemu_package=${qemuPackage}
            RESULT
          '';
        }
      ];
    }
