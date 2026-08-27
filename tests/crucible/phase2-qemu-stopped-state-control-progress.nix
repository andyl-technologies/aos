{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0079-crucible-stopped-state-control-progress.patch",
  exactSnapshotRestore ?
    import ./phase2-qemu-exact-snapshot-restore.nix {
      inherit pkgs lib;
      attrPath = "checks.crucible.phase2.qemuStoppedStateControlProgress.liveRestore";
      taskIds = ["T-QEMU-0079"];
    },
}: let
  patchSource = builtins.readFile (../../pkgs/emulation/qemu-patches + "/${patchName}");
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures = failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
    {
      label = "level-triggered stop or unplug recheck";
      needle = "!rr_crucible_sim_stop_or_unplug_pending()";
    }
    {
      label = "all-vCPU queued-work scan";
      needle = "rr_crucible_sim_vcpu_work_pending";
    }
    {
      label = "level-triggered queued-work recheck";
      needle = "!rr_crucible_sim_vcpu_work_pending()";
    }
    {
      label = "bounded BQL-aware control wait";
      needle = "qemu_cond_timedwait_bql(first_cpu->halt_cond, 1)";
    }
    {
      label = "condition signal is not authoritative";
      needle = "the condition signal is a latency hint, never the sole source";
    }
  ];
in
  if failures != []
  then throw "Crucible stopped-state control-progress microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-stopped-state-control-progress";
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
          name = "verify-stopped-state-control-progress";
          script = ''
            set -eu

            mkdir -p source "$out"
            tar -xf "$src" -C source
            stock=source/qemu-${qemuPackage.version}

            ! grep -Rq 'rr_crucible_sim_vcpu_work_pending' "$stock/accel/tcg/tcg-accel-ops-rr.c"
            ! grep -Rq 'qemu_cond_timedwait_bql(first_cpu->halt_cond, 1)' "$stock/accel/tcg/tcg-accel-ops-rr.c"

            cp "${exactSnapshotRestore}/result" "$out/live-exact-snapshot.result"
            grep -Fxq PASS "$out/live-exact-snapshot.result"
            grep -Fxq 'old_process_force_crashed=true' "$out/live-exact-snapshot.result"
            grep -Fxq 'replay_oracle_pair_match=true' "$out/live-exact-snapshot.result"

            cat > "$out/result" <<RESULT
            PASS
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            stop_unplug_recheck=level-triggered-under-bql
            queued_vcpu_work_recheck=all-vcpus-under-bql
            bounded_control_wait_milliseconds=1
            guest_execution_during_wait=false
            fresh_process_exact_restore=true
            RESULT
          '';
        }
      ];
    }
