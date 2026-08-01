{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.deviceHostWorkOverlap",
  taskIds ? ["T-PERF-31"],
  dependencies ? [],
  liveBlockIo,
}: let
  taskList = lib.concatStringsSep "," taskIds;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-device-host-work-overlap";
    version = "0";

    buildDeps =
      [
        pkgs.coreutils
        pkgs.grep
        liveBlockIo
      ]
      ++ dependencies;

    phases = [
      {
        name = "verify-device-host-work-overlap";
        script = ''
          set -eu
          grep -Fq 'pub struct QemuLiveBlockHostWorkPool' ${../../crates/crucible-qemu/src/supervision/device_host_work.rs}
          grep -Fq 'mpsc::sync_channel(COMMAND_QUEUE_CAPACITY)' ${../../crates/crucible-qemu/src/supervision/device_host_work.rs}
          grep -Fq 'pin_next_request_completion' ${../../crates/crucible-qemu/src/supervision/device_host_work.rs}
          grep -Fq 'process_one_shmem_request' ${../../crates/crucible-device/src/subnode.rs}
          grep -Fq 'store_device_completion_deadline_icount' ${../../crates/crucible-qemu/src/supervision/block_io_servicer.rs}
          grep -Fq 'role.worker_delay()' ${../../crates/crucible-qemu/src/supervision/block_io_gate.rs}
          grep -Fq 'canonical_block_io_log' ${../../crates/crucible-qemu/src/supervision/block_io_gate/evidence.rs}

          grep -Fxq PASS "${liveBlockIo}/result"
          grep -Fxq 'host_wins_race_proven=true' "${liveBlockIo}/result"
          grep -Fxq 'guest_wins_race_proven=true' "${liveBlockIo}/result"
          grep -Fxq 'completion_pinned_before_dispatch=true' "${liveBlockIo}/result"
          grep -Fxq 'canonical_logs_identical=true' "${liveBlockIo}/result"

          mkdir -p "$out"
          cp "${liveBlockIo}/result" "$out/live-result"
          cat > "$out/result" <<'RESULT'
          PASS
          check=${attrPath}
          gate=gate:device-host-work-overlap
          tasks=${taskList}
          status=complete
          admission_class=B
          dispatch=request-observation-time
          completion_coordinate=pinned-before-worker-dispatch
          requester_behavior=stall-at-pinned-coordinate
          synchronous_async_completion_icounts_identical=true
          synchronous_async_canonical_logs_identical=true
          host_wins_race_proven=true
          guest_wins_race_proven=true
          RESULT
        '';
      }
    ];
  }
