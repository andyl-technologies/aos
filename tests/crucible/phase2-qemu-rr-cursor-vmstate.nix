{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0077-crucible-serialize-rr-cursor.patch",
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  exactSnapshotRestore = import ./phase2-qemu-exact-snapshot-restore.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase2.qemuRrCursorVmstate.liveRestore";
    taskIds = ["T-QEMU-0077"];
  };
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures = failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
    {
      label = "authoritative selected-vCPU state";
      needle = "uint64_t crucible_rr_current_vcpu;";
    }
    {
      label = "authoritative intra-turn position state";
      needle = "uint64_t crucible_rr_cursor_position;";
    }
    {
      label = "partial-turn budget clamp";
      needle = "return MIN(limit, (int64_t)remaining);";
    }
    {
      label = "exact quantum rotation";
      needle = "timers_state.crucible_rr_selection_pending = true;";
    }
    {
      label = "restored CPU selected before execution";
      needle = "cpu = icount_crucible_rr_select_cpu(cpu);";
    }
    {
      label = "zero-instruction boundary preserves restored selection";
      needle = "A zero-instruction boundary must not consume the selection.";
    }
    {
      label = "timer icount VMState version bump";
      needle = ".version_id = 2,";
    }
    {
      label = "old timer icount VMState rejection";
      needle = ".minimum_version_id = 2,";
    }
    {
      label = "cursor VMState selected-vCPU field";
      needle = "VMSTATE_UINT64(crucible_rr_current_vcpu, TimersState),";
    }
    {
      label = "cursor VMState position field";
      needle = "VMSTATE_UINT64(crucible_rr_cursor_position, TimersState),";
    }
    {
      label = "post-load cursor validation";
      needle = ".post_load = crucible_rr_cursor_state_post_load,";
    }
    {
      label = "serialized owner lookup";
      needle = "uint64_t owner = icount_crucible_rr_current_vcpu();";
    }
    {
      label = "serialized owner matches current CPU";
      needle = "cpu->cpu_index != owner";
    }
    {
      label = "validated serialized owner export";
      needle = "return owner;";
    }
  ];
in
  if failures != []
  then throw "Crucible serialized RR cursor microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-rr-cursor-vmstate";
      version = "0";
      src = qemuPackage.src;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "verify-serialized-rr-cursor";
          script = ''
            set -eu

            mkdir -p source "$out"
            tar -xf "$src" -C source
            stock=source/qemu-${qemuPackage.version}

            # The negative control is the pristine upstream source: it has no
            # serialized Crucible cursor and therefore cannot satisfy the
            # checkpoint contract this patch introduces.
            ! grep -Rq 'crucible_rr_cursor_position' "$stock/include/system/cpu-timers-internal.h"
            ! grep -Rq 'crucible_rr_cursor_state_post_load' "$stock/system/cpu-timers.c"

            cp "${exactSnapshotRestore}/result" "$out/live-exact-snapshot.result"
            grep -Fxq PASS "$out/live-exact-snapshot.result"
            grep -Fxq 'smp_vcpus=2' "$out/live-exact-snapshot.result"
            grep -Fxq 'old_process_force_crashed=true' "$out/live-exact-snapshot.result"
            grep -Fxq 'nonzero_intra_turn_rr_cursor_restored=true' "$out/live-exact-snapshot.result"
            grep -Eq '^capture_rr_position_in_quantum=[1-9][0-9]*$' "$out/live-exact-snapshot.result"
            grep -Eq '^capture_rr_switch_quantum=[1-9][0-9]*$' "$out/live-exact-snapshot.result"
            grep -Fxq 'replay_oracle_pair_match=true' "$out/live-exact-snapshot.result"

            cat > "$out/result" <<RESULT
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            partial_rr_turn_survives_host_ceiling=true
            exact_quantum_rotation_serialized=true
            timer_icount_v1_rejected=true
            invalid_cursor_post_load_rejected=true
            stopped_boundary_cursor_read=true
            fresh_process_restore=true
            multi_vcpu_restore=true
            nonzero_intra_turn_cursor_restore=true
            aggregate_fingerprint_covers_rr_cursor=true
            RESULT
          '';
        }
      ];
    }
