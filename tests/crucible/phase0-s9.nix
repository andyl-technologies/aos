{
  pkgs,
  lib,
}: let
  s1Fingerprint = import ./phase0-s1.nix {inherit pkgs lib;};
  qemuNixSource = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatch1Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0001-crucible-sim-accel.patch;
  qemuPatch2Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch;
  qemuPatch3Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0003-crucible-icount-no-realtime.patch;
  qemuPatch4Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0004-crucible-no-warp-with-plugin.patch;
  qemuPatch5Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0005-crucible-det-glib-prng.patch;
  qemuPatch6Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0006-crucible-clock-deadline.patch;
  qemuPatch7Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0007-crucible-block-rtc-read.patch;
  qemuPatch8Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0008-crucible-det-getrandom.patch;
  qemuPatch9Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0009-crucible-net-deterministic.patch;
  qemuPatch10Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0010-crucible-plugin-time-advance.patch;
  qemuPatch11Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0011-crucible-plugin-icount-raw.patch;
  qemuPatch12Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0012-crucible-plugin-vcpu-exit.patch;
  qemuPatch13Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0013-crucible-plugin-wake-fd.patch;
  qemuPatch14Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0014-crucible-plugin-tcg-exec-cb.patch;
  qemuPatch15Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0015-crucible-blk-shmem.patch;
  qemuPatch16Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0016-crucible-blk-shmem-io-fixes.patch;
  qemuPatch17Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0017-crucible-blk-write-sentinel.patch;
  qemuPatch18Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0018-crucible-dev-cb-api.patch;
  qemuPatch19Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0019-crucible-9p-shmem.patch;
  qemuPatch20Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0020-crucible-net-tx-callback.patch;
  qemuNixHash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu.nix;
  qemuPatch1Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0001-crucible-sim-accel.patch;
  qemuPatch2Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch;
  qemuPatch3Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0003-crucible-icount-no-realtime.patch;
  qemuPatch4Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0004-crucible-no-warp-with-plugin.patch;
  qemuPatch5Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0005-crucible-det-glib-prng.patch;
  qemuPatch6Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0006-crucible-clock-deadline.patch;
  qemuPatch7Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0007-crucible-block-rtc-read.patch;
  qemuPatch8Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0008-crucible-det-getrandom.patch;
  qemuPatch9Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0009-crucible-net-deterministic.patch;
  qemuPatch10Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0010-crucible-plugin-time-advance.patch;
  qemuPatch11Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0011-crucible-plugin-icount-raw.patch;
  qemuPatch12Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0012-crucible-plugin-vcpu-exit.patch;
  qemuPatch13Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0013-crucible-plugin-wake-fd.patch;
  qemuPatch14Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0014-crucible-plugin-tcg-exec-cb.patch;
  qemuPatch15Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0015-crucible-blk-shmem.patch;
  qemuPatch16Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0016-crucible-blk-shmem-io-fixes.patch;
  qemuPatch17Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0017-crucible-blk-write-sentinel.patch;
  qemuPatch18Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0018-crucible-dev-cb-api.patch;
  qemuPatch19Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0019-crucible-9p-shmem.patch;
  qemuPatch20Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0020-crucible-net-tx-callback.patch;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s9-qemu-build-identity";
    version = "0";
    src = null;

    qemuNix = qemuNixSource;
    qemuPatch1 = qemuPatch1Source;
    qemuPatch2 = qemuPatch2Source;
    qemuPatch3 = qemuPatch3Source;
    qemuPatch4 = qemuPatch4Source;
    qemuPatch5 = qemuPatch5Source;
    qemuPatch6 = qemuPatch6Source;
    qemuPatch7 = qemuPatch7Source;
    qemuPatch8 = qemuPatch8Source;
    qemuPatch9 = qemuPatch9Source;
    qemuPatch10 = qemuPatch10Source;
    qemuPatch11 = qemuPatch11Source;
    qemuPatch12 = qemuPatch12Source;
    qemuPatch13 = qemuPatch13Source;
    qemuPatch14 = qemuPatch14Source;
    qemuPatch15 = qemuPatch15Source;
    qemuPatch16 = qemuPatch16Source;
    qemuPatch17 = qemuPatch17Source;
    qemuPatch18 = qemuPatch18Source;
    qemuPatch19 = qemuPatch19Source;
    qemuPatch20 = qemuPatch20Source;
    passAsFile = [
      "qemuNix"
      "qemuPatch1"
      "qemuPatch2"
      "qemuPatch3"
      "qemuPatch4"
      "qemuPatch5"
      "qemuPatch6"
      "qemuPatch7"
      "qemuPatch8"
      "qemuPatch9"
      "qemuPatch10"
      "qemuPatch11"
      "qemuPatch12"
      "qemuPatch13"
      "qemuPatch14"
      "qemuPatch15"
      "qemuPatch16"
      "qemuPatch17"
      "qemuPatch18"
      "qemuPatch19"
      "qemuPatch20"
    ];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.jq
      pkgs.qemu-crucible
    ];

    S1_RESULT = "${s1Fingerprint}/result";
    QEMU_OUT = builtins.toString pkgs.qemu-crucible;
    QEMU_DRV = builtins.unsafeDiscardStringContext pkgs.qemu-crucible.drvPath;
    QEMU_VERSION = pkgs.qemu-crucible.version;
    QEMU_NIX_HASH = qemuNixHash;
    PATCH_0001_NAME = "0001-crucible-sim-accel.patch";
    PATCH_0001_HASH = qemuPatch1Hash;
    PATCH_0002_NAME = "0002-crucible-rr-fingerprint-helpers.patch";
    PATCH_0002_HASH = qemuPatch2Hash;
    PATCH_0003_NAME = "0003-crucible-icount-no-realtime.patch";
    PATCH_0003_HASH = qemuPatch3Hash;
    PATCH_0004_NAME = "0004-crucible-no-warp-with-plugin.patch";
    PATCH_0004_HASH = qemuPatch4Hash;
    PATCH_0005_NAME = "0005-crucible-det-glib-prng.patch";
    PATCH_0005_HASH = qemuPatch5Hash;
    PATCH_0006_NAME = "0006-crucible-clock-deadline.patch";
    PATCH_0006_HASH = qemuPatch6Hash;
    PATCH_0007_NAME = "0007-crucible-block-rtc-read.patch";
    PATCH_0007_HASH = qemuPatch7Hash;
    PATCH_0008_NAME = "0008-crucible-det-getrandom.patch";
    PATCH_0008_HASH = qemuPatch8Hash;
    PATCH_0009_NAME = "0009-crucible-net-deterministic.patch";
    PATCH_0009_HASH = qemuPatch9Hash;
    PATCH_0010_NAME = "0010-crucible-plugin-time-advance.patch";
    PATCH_0010_HASH = qemuPatch10Hash;
    PATCH_0011_NAME = "0011-crucible-plugin-icount-raw.patch";
    PATCH_0011_HASH = qemuPatch11Hash;
    PATCH_0012_NAME = "0012-crucible-plugin-vcpu-exit.patch";
    PATCH_0012_HASH = qemuPatch12Hash;
    PATCH_0013_NAME = "0013-crucible-plugin-wake-fd.patch";
    PATCH_0013_HASH = qemuPatch13Hash;
    PATCH_0014_NAME = "0014-crucible-plugin-tcg-exec-cb.patch";
    PATCH_0014_HASH = qemuPatch14Hash;
    PATCH_0015_NAME = "0015-crucible-blk-shmem.patch";
    PATCH_0015_HASH = qemuPatch15Hash;
    PATCH_0016_NAME = "0016-crucible-blk-shmem-io-fixes.patch";
    PATCH_0016_HASH = qemuPatch16Hash;
    PATCH_0017_NAME = "0017-crucible-blk-write-sentinel.patch";
    PATCH_0017_HASH = qemuPatch17Hash;
    PATCH_0018_NAME = "0018-crucible-dev-cb-api.patch";
    PATCH_0018_HASH = qemuPatch18Hash;
    PATCH_0019_NAME = "0019-crucible-9p-shmem.patch";
    PATCH_0019_HASH = qemuPatch19Hash;
    PATCH_0020_NAME = "0020-crucible-net-tx-callback.patch";
    PATCH_0020_HASH = qemuPatch20Hash;

    phases = [
      {
        name = "run-s9-qemu-build-identity";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          get_kv() {
            key="$1"
            gawk -F= -v key="$key" '
              $1 == key { print $2; found = 1 }
              END { if (!found) exit 1 }
            ' "$S1_RESULT"
          }

          require_fixed() {
            file="$1"
            text="$2"
            grep -F -q -- "$text" "$file" || fail "missing '$text' in $file"
          }

          first_line=$(sed -n '1p' "$S1_RESULT")
          [ "$first_line" = PASS ] || fail "S1 result is not PASS"
          require_fixed "$S1_RESULT" "spike=single-vm-fingerprint"
          require_fixed "$S1_RESULT" "extended_fingerprint_match=true"
          require_fixed "$S1_RESULT" "aggregate_icount_stream_match=true"
          require_fixed "$S1_RESULT" "s1_complete=true"

          s1_horizon_extended_hash=$(get_kv horizon_extended_hash)
          s1_horizon_register_hash=$(get_kv horizon_register_hash)
          s1_horizon_ram_hash=$(get_kv horizon_ram_hash)
          s1_pause_retired=$(get_kv pause_retired)
          s1_pause_overshoot=$(get_kv pause_overshoot)

          cp "$qemuNixPath" qemu.nix
          cp "$qemuPatch1Path" "$PATCH_0001_NAME"
          cp "$qemuPatch2Path" "$PATCH_0002_NAME"
          cp "$qemuPatch3Path" "$PATCH_0003_NAME"
          cp "$qemuPatch4Path" "$PATCH_0004_NAME"
          cp "$qemuPatch5Path" "$PATCH_0005_NAME"
          cp "$qemuPatch6Path" "$PATCH_0006_NAME"
          cp "$qemuPatch7Path" "$PATCH_0007_NAME"
          cp "$qemuPatch8Path" "$PATCH_0008_NAME"
          cp "$qemuPatch9Path" "$PATCH_0009_NAME"
          cp "$qemuPatch10Path" "$PATCH_0010_NAME"
          cp "$qemuPatch11Path" "$PATCH_0011_NAME"
          cp "$qemuPatch12Path" "$PATCH_0012_NAME"
          cp "$qemuPatch13Path" "$PATCH_0013_NAME"
          cp "$qemuPatch14Path" "$PATCH_0014_NAME"
          cp "$qemuPatch15Path" "$PATCH_0015_NAME"
          cp "$qemuPatch16Path" "$PATCH_0016_NAME"
          cp "$qemuPatch17Path" "$PATCH_0017_NAME"
          cp "$qemuPatch18Path" "$PATCH_0018_NAME"
          cp "$qemuPatch19Path" "$PATCH_0019_NAME"
          cp "$qemuPatch20Path" "$PATCH_0020_NAME"

          require_fixed qemu.nix 'pname ? "qemu"'
          require_fixed qemu.nix 'enablePlugins ? false'
          require_fixed qemu.nix 'pluginFlag ='
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0001-crucible-sim-accel.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0003-crucible-icount-no-realtime.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0004-crucible-no-warp-with-plugin.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0005-crucible-det-glib-prng.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0006-crucible-clock-deadline.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0007-crucible-block-rtc-read.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0008-crucible-det-getrandom.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0009-crucible-net-deterministic.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0010-crucible-plugin-time-advance.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0011-crucible-plugin-icount-raw.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0012-crucible-plugin-vcpu-exit.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0013-crucible-plugin-wake-fd.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0014-crucible-plugin-tcg-exec-cb.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0015-crucible-blk-shmem.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0016-crucible-blk-shmem-io-fixes.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0017-crucible-blk-write-sentinel.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0018-crucible-dev-cb-api.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0019-crucible-9p-shmem.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0020-crucible-net-tx-callback.patch}'
          require_fixed qemu.nix '--target-list=x86_64-softmmu'
          require_fixed qemu.nix 'https://download.qemu.org/qemu-'
          require_fixed qemu.nix '.tar.xz'

          require_fixed "$PATCH_0001_NAME" 'TYPE_SIM_ACCEL'
          require_fixed "$PATCH_0001_NAME" 'ACCEL_OPS_NAME("sim")'
          require_fixed "$PATCH_0001_NAME" '-accel sim requires -icount shift=N'
          if grep -F -q -- 'qemu_plugin_crucible_pause_vm' "$PATCH_0002_NAME"; then
            fail "legacy unvalidated VM pause export remains in patch 0002"
          fi
          require_fixed "$PATCH_0002_NAME" 'qemu_plugin_crucible_ram_hash'
          require_fixed "$PATCH_0002_NAME" 'qemu_plugin_crucible_get_vcpu_registers'
          require_fixed "$PATCH_0002_NAME" 'rr_switch_quantum'
          require_fixed "$PATCH_0002_NAME" 'qemu_opt_get_number(opts, "rr_switch_quantum", 0)'
          require_fixed "$PATCH_0002_NAME" 'icount_start_warp_timer'
          require_fixed "$PATCH_0002_NAME" 'vmstate_info_crucible_icount_host_timer_int64'
          require_fixed "$PATCH_0003_NAME" 'icount_enabled() != ICOUNT_PRECISE'
          require_fixed "$PATCH_0003_NAME" 'strcmp(current_accel_name(), "sim") != 0'
          require_fixed "$PATCH_0003_NAME" 'qemu_clock_deadline_ns_all(QEMU_CLOCK_REALTIME'
          require_fixed "$PATCH_0004_NAME" 'qemu_plugin_has_time_control'
          require_fixed "$PATCH_0004_NAME" 'strcmp(current_accel_name(), "sim") == 0'
          require_fixed "$PATCH_0004_NAME" 'qemu_clock_notify(QEMU_CLOCK_VIRTUAL)'
          require_fixed "$PATCH_0004_NAME" 'static inline bool qemu_plugin_has_time_control(void)'
          require_fixed "$PATCH_0005_NAME" 'deterministic_glib_seed'
          require_fixed "$PATCH_0005_NAME" 'g_random_set_seed(deterministic_glib_seed(seed))'
          require_fixed "$PATCH_0005_NAME" 'seed that global stream from the same run seed'
          require_fixed "$PATCH_0006_NAME" 'qemu_plugin_clock_deadline_ns'
          require_fixed "$PATCH_0007_NAME" 'crucible_guest_rtc_clock'
          require_fixed "$PATCH_0007_NAME" 'qemu_rtc_enable_sim_virtual_clock();'
          require_fixed "$PATCH_0007_NAME" 'rtc_clock = QEMU_CLOCK_VIRTUAL'
          require_fixed "$PATCH_0007_NAME" 'fixed epoch plus'
          require_fixed "$PATCH_0008_NAME" 'crucible_guest_random_sim_requires_seed'
          require_fixed "$PATCH_0008_NAME" 'current_accel_name'
          require_fixed "$PATCH_0008_NAME" '-accel sim requires -seed for deterministic guest random'
          require_fixed "$PATCH_0008_NAME" 'qemu_guest_getrandom'
          require_fixed "$PATCH_0009_NAME" 'qemu_plugin_net_inject'
          require_fixed "$PATCH_0009_NAME" 'qemu_plugin_net_send'
          require_fixed "$PATCH_0009_NAME" 'qemu_plugin_net_flush'
          require_fixed "$PATCH_0009_NAME" 'qemu_plugin_net_can_receive'
          require_fixed "$PATCH_0009_NAME" 'qemu_receive_packet'
          require_fixed "$PATCH_0009_NAME" 'qemu_net_queue_append_lossless'
          require_fixed "$PATCH_0009_NAME" 'qemu_plugin_net_sent_cb'
          require_fixed "$PATCH_0009_NAME" 'qemu_net_queue_flush'
          require_fixed "$PATCH_0009_NAME" 'qemu_notify_event'
          require_fixed "$PATCH_0010_NAME" 'qemu_plugin_has_time_control'
          require_fixed "$PATCH_0010_NAME" 'qemu_plugin_register_time_advance_cb'
          require_fixed "$PATCH_0010_NAME" 'qemu_plugin_advance_time_ns'
          require_fixed "$PATCH_0010_NAME" 'qemu_plugin_advance_time_bh'
          require_fixed "$PATCH_0010_NAME" 'aio_bh_schedule_oneshot(qemu_get_aio_context()'
          require_fixed "$PATCH_0010_NAME" 'icount_advance_virtual_time_to_ns(new_time)'
          require_fixed "$PATCH_0010_NAME" 'qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)'
          require_fixed "$PATCH_0010_NAME" 'qemu_plugin_time_advance_barrier_bh'
          require_fixed "$PATCH_0010_NAME" 'qemu_plugin_time_advance_complete_bh'
          require_fixed "$PATCH_0010_NAME" 'qemu_cpu_kick(first_cpu)'
          require_fixed "$PATCH_0011_NAME" 'qemu_plugin_icount_raw'
          require_fixed "$PATCH_0011_NAME" 'icount_get_raw()'
          require_fixed "$PATCH_0011_NAME" '#include "system/cpu-timers.h"'
          require_fixed "$PATCH_0012_NAME" 'qemu_plugin_force_vcpu_exit'
          require_fixed "$PATCH_0012_NAME" 'current_cpu->exit_request'
          require_fixed "$PATCH_0012_NAME" 'qatomic_set_mb'
          require_fixed "$PATCH_0013_NAME" 'qemu_plugin_register_wake_fd'
          require_fixed "$PATCH_0013_NAME" 'qemu_plugin_crucible_single_threaded_rr'
          require_fixed "$PATCH_0013_NAME" '!qemu_tcg_mttcg_enabled()'
          require_fixed "$PATCH_0013_NAME" 'aio_set_fd_handler(qemu_get_aio_context()'
          require_fixed "$PATCH_0014_NAME" 'qemu_plugin_register_tcg_exec_cb'
          require_fixed "$PATCH_0014_NAME" 'qemu_plugin_tcg_exec_cb_t'
          require_fixed "$PATCH_0014_NAME" 'qemu_plugin_maybe_fire_tcg_exec_cb(cpu)'
          require_fixed "$PATCH_0014_NAME" 'qemu_plugin_icount_raw()'
          require_fixed "$PATCH_0014_NAME" 'qemu_plugin_icount_at_tb_entry'
          require_fixed "$PATCH_0014_NAME" 'icount_get_raw_observed'
          require_fixed "$PATCH_0014_NAME" '*entry_icount = (uint64_t)observed_icount - tb_insns'
          require_fixed "$PATCH_0015_NAME" 'block/crucible-shmem.c'
          require_fixed "$PATCH_0015_NAME" '.format_name            = "crucible-shmem"'
          require_fixed "$PATCH_0015_NAME" "system_ss.add(files('crucible-shmem.c'))"
          require_fixed "$PATCH_0015_NAME" 'qemu_plugin_register_blk_cb'
          require_fixed "$PATCH_0015_NAME" 'qemu_plugin_blk_submit_cb_t'
          require_fixed "$PATCH_0015_NAME" 'qemu_plugin_blk_poll_cb_t'
          require_fixed "$PATCH_0015_NAME" '#include "qemu/cutils.h"'
          require_fixed "$PATCH_0016_NAME" 'aio_co_schedule(bdrv_get_aio_context(bs), qemu_coroutine_self())'
          require_fixed "$PATCH_0016_NAME" 'qemu_coroutine_yield()'
          require_fixed "$PATCH_0017_NAME" '#define QEMU_PLUGIN_BLK_POLL_PENDING (-2)'
          require_fixed "$PATCH_0018_NAME" 'qemu_plugin_register_9p_cb'
          require_fixed "$PATCH_0018_NAME" 'qemu_plugin_9p_submit_cb_t'
          require_fixed "$PATCH_0018_NAME" '#define QEMU_PLUGIN_9P_POLL_PENDING (-2)'
          require_fixed "$PATCH_0019_NAME" 'virtio_9p_forward_crucible'
          require_fixed "$PATCH_0019_NAME" 'crucible_9p_callbacks_ready()'
          require_fixed "$PATCH_0019_NAME" 'next_crucible_9p_request_id'
          require_fixed "$PATCH_0020_NAME" 'qemu_plugin_register_net_tx_cb'
          require_fixed "$PATCH_0020_NAME" 'qemu_plugin_net_tx_cb_t'
          require_fixed "$PATCH_0020_NAME" 'crucible_net_tx_submit'

          patch_count=20
          patch_series_hash=$(
            {
              printf '%s  %s\n' "$PATCH_0001_HASH" "$PATCH_0001_NAME"
              printf '%s  %s\n' "$PATCH_0002_HASH" "$PATCH_0002_NAME"
              printf '%s  %s\n' "$PATCH_0003_HASH" "$PATCH_0003_NAME"
              printf '%s  %s\n' "$PATCH_0004_HASH" "$PATCH_0004_NAME"
              printf '%s  %s\n' "$PATCH_0005_HASH" "$PATCH_0005_NAME"
              printf '%s  %s\n' "$PATCH_0006_HASH" "$PATCH_0006_NAME"
              printf '%s  %s\n' "$PATCH_0007_HASH" "$PATCH_0007_NAME"
              printf '%s  %s\n' "$PATCH_0008_HASH" "$PATCH_0008_NAME"
              printf '%s  %s\n' "$PATCH_0009_HASH" "$PATCH_0009_NAME"
              printf '%s  %s\n' "$PATCH_0010_HASH" "$PATCH_0010_NAME"
              printf '%s  %s\n' "$PATCH_0011_HASH" "$PATCH_0011_NAME"
              printf '%s  %s\n' "$PATCH_0012_HASH" "$PATCH_0012_NAME"
              printf '%s  %s\n' "$PATCH_0013_HASH" "$PATCH_0013_NAME"
              printf '%s  %s\n' "$PATCH_0014_HASH" "$PATCH_0014_NAME"
              printf '%s  %s\n' "$PATCH_0015_HASH" "$PATCH_0015_NAME"
              printf '%s  %s\n' "$PATCH_0016_HASH" "$PATCH_0016_NAME"
              printf '%s  %s\n' "$PATCH_0017_HASH" "$PATCH_0017_NAME"
              printf '%s  %s\n' "$PATCH_0018_HASH" "$PATCH_0018_NAME"
              printf '%s  %s\n' "$PATCH_0019_HASH" "$PATCH_0019_NAME"
              printf '%s  %s\n' "$PATCH_0020_HASH" "$PATCH_0020_NAME"
            } \
              | sha256sum \
              | gawk '{ print $1 }'
          )

          {
            echo "qemu_derivation_path=$QEMU_DRV"
            echo "qemu_output_path=$QEMU_OUT"
            echo "qemu_version=$QEMU_VERSION"
            echo "qemu_nix_hash=$QEMU_NIX_HASH"
            echo "patch_count=$patch_count"
            echo "patch_0001_name=$PATCH_0001_NAME"
            echo "patch_0001_hash=$PATCH_0001_HASH"
            echo "patch_0002_name=$PATCH_0002_NAME"
            echo "patch_0002_hash=$PATCH_0002_HASH"
            echo "patch_0003_name=$PATCH_0003_NAME"
            echo "patch_0003_hash=$PATCH_0003_HASH"
            echo "patch_0004_name=$PATCH_0004_NAME"
            echo "patch_0004_hash=$PATCH_0004_HASH"
            echo "patch_0005_name=$PATCH_0005_NAME"
            echo "patch_0005_hash=$PATCH_0005_HASH"
            echo "patch_0006_name=$PATCH_0006_NAME"
            echo "patch_0006_hash=$PATCH_0006_HASH"
            echo "patch_0007_name=$PATCH_0007_NAME"
            echo "patch_0007_hash=$PATCH_0007_HASH"
            echo "patch_0008_name=$PATCH_0008_NAME"
            echo "patch_0008_hash=$PATCH_0008_HASH"
            echo "patch_0009_name=$PATCH_0009_NAME"
            echo "patch_0009_hash=$PATCH_0009_HASH"
            echo "patch_0010_name=$PATCH_0010_NAME"
            echo "patch_0010_hash=$PATCH_0010_HASH"
            echo "patch_0011_name=$PATCH_0011_NAME"
            echo "patch_0011_hash=$PATCH_0011_HASH"
            echo "patch_0012_name=$PATCH_0012_NAME"
            echo "patch_0012_hash=$PATCH_0012_HASH"
            echo "patch_0013_name=$PATCH_0013_NAME"
            echo "patch_0013_hash=$PATCH_0013_HASH"
            echo "patch_0014_name=$PATCH_0014_NAME"
            echo "patch_0014_hash=$PATCH_0014_HASH"
            echo "patch_0015_name=$PATCH_0015_NAME"
            echo "patch_0015_hash=$PATCH_0015_HASH"
            echo "patch_0016_name=$PATCH_0016_NAME"
            echo "patch_0016_hash=$PATCH_0016_HASH"
            echo "patch_0017_name=$PATCH_0017_NAME"
            echo "patch_0017_hash=$PATCH_0017_HASH"
            echo "patch_0018_name=$PATCH_0018_NAME"
            echo "patch_0018_hash=$PATCH_0018_HASH"
            echo "patch_0019_name=$PATCH_0019_NAME"
            echo "patch_0019_hash=$PATCH_0019_HASH"
            echo "patch_0020_name=$PATCH_0020_NAME"
            echo "patch_0020_hash=$PATCH_0020_HASH"
            echo "patch_series_hash=$patch_series_hash"
            echo "plugins_enabled=true"
            echo "s1_horizon_extended_hash=$s1_horizon_extended_hash"
            echo "s1_horizon_register_hash=$s1_horizon_register_hash"
            echo "s1_horizon_ram_hash=$s1_horizon_ram_hash"
          } > build-id-material.txt

          qemu_build_id=$(sha256sum build-id-material.txt | gawk '{ print $1 }')
          changed_build_id=$(
            {
              cat build-id-material.txt
              printf 'trivial-qemu-change-negative-control=true\n'
            } | sha256sum | gawk '{ print $1 }'
          )
          [ "$qemu_build_id" != "$changed_build_id" ] \
            || fail "negative-control build identity did not change"

          jq -n \
            --arg crucible_version phase0-spike \
            --arg qemu_build_id "$qemu_build_id" \
            --arg qemu_derivation_path "$QEMU_DRV" \
            --arg qemu_output_path "$QEMU_OUT" \
            --arg qemu_version "$QEMU_VERSION" \
            --arg patch_series_hash "$patch_series_hash" \
            --arg s1_horizon_extended_hash "$s1_horizon_extended_hash" \
            '{
              crucible_version: $crucible_version,
              qemu_build_id: $qemu_build_id,
              qemu_derivation_path: $qemu_derivation_path,
              qemu_output_path: $qemu_output_path,
              qemu_version: $qemu_version,
              qemu_patch_series_hash: $patch_series_hash,
              seed: "0x0010c001",
              scenario_hash: "phase0-s1-stock-linux-diskless-initramfs-workload",
              schedule: ["fixed-horizon-s1-cadence"],
              fingerprint_tail: [{
                horizon_extended_hash: $s1_horizon_extended_hash
              }],
              sampling_config: {
                cadence: 100000000,
                horizon_icount: 3200000000
              }
            }' > repro-artifact.json

          artifact_build_id=$(jq -r '.qemu_build_id' repro-artifact.json)
          [ "$artifact_build_id" = "$qemu_build_id" ] \
            || fail "artifact build id does not match current build id"
          if [ "$artifact_build_id" = "$changed_build_id" ]; then
            fail "artifact accepted a changed QEMU build identity"
          fi

          artifact_build_id_match=true
          artifact_mismatch_regates=true
          patch_apply_list_matches=true
          plugin_exports_present=true
          rr_switch_quantum_default_zero=true
          non_sim_icount_patch_present=true
          no_warp_with_plugin_patch_present=true
          qemu_clock_deadline_patch_present=true
          qemu_rtc_patch_present=true
          qemu_internal_entropy_patch_present=true
          qemu_guest_random_patch_present=true
          qemu_network_rx_patch_present=true
          qemu_time_advance_patch_present=true
          qemu_plugin_icount_raw_patch_present=true
          qemu_plugin_vcpu_exit_patch_present=true
          qemu_plugin_wake_fd_patch_present=true
          qemu_plugin_tcg_exec_cb_patch_present=true
          qemu_plugin_tb_entry_icount_patch_present=true
          qemu_block_shmem_patch_present=true
          qemu_block_shmem_io_fixes_patch_present=true
          qemu_block_write_sentinel_patch_present=true
          qemu_dev_cb_api_patch_present=true
          qemu_9p_shmem_patch_present=true
          qemu_net_tx_callback_patch_present=true
          full_upstream_inertness_comparison=false
          qemu_inert_gate_status=fallback_pending_upstream_comparison
          fallback_adopted=pin_build_id_and_regate_on_change

          mkdir -p "$out"
          cp build-id-material.txt "$out/build-id-material.txt"
          cp repro-artifact.json "$out/repro-artifact.json"
          cp qemu.nix "$out/qemu.nix"
          cp "$PATCH_0001_NAME" "$out/$PATCH_0001_NAME"
          cp "$PATCH_0002_NAME" "$out/$PATCH_0002_NAME"
          cp "$PATCH_0003_NAME" "$out/$PATCH_0003_NAME"
          cp "$PATCH_0004_NAME" "$out/$PATCH_0004_NAME"
          cp "$PATCH_0005_NAME" "$out/$PATCH_0005_NAME"
          cp "$PATCH_0006_NAME" "$out/$PATCH_0006_NAME"
          cp "$PATCH_0007_NAME" "$out/$PATCH_0007_NAME"
          cp "$PATCH_0008_NAME" "$out/$PATCH_0008_NAME"
          cp "$PATCH_0009_NAME" "$out/$PATCH_0009_NAME"
          cp "$PATCH_0010_NAME" "$out/$PATCH_0010_NAME"
          cp "$PATCH_0011_NAME" "$out/$PATCH_0011_NAME"
          cp "$PATCH_0012_NAME" "$out/$PATCH_0012_NAME"
          cp "$PATCH_0013_NAME" "$out/$PATCH_0013_NAME"
          cp "$PATCH_0014_NAME" "$out/$PATCH_0014_NAME"
          cp "$PATCH_0015_NAME" "$out/$PATCH_0015_NAME"
          cp "$PATCH_0016_NAME" "$out/$PATCH_0016_NAME"
          cp "$PATCH_0017_NAME" "$out/$PATCH_0017_NAME"
          cp "$PATCH_0018_NAME" "$out/$PATCH_0018_NAME"
          cp "$PATCH_0019_NAME" "$out/$PATCH_0019_NAME"
          cp "$PATCH_0020_NAME" "$out/$PATCH_0020_NAME"
          {
            echo PASS_WITH_FALLBACK
            echo spike=qemu-build-identity-and-inertness
            echo check=checks.crucible.phase0.s9QemuBuildIdentity
            echo qemu_package=qemu-crucible
            echo qemu_version="$QEMU_VERSION"
            echo qemu_derivation_path="$QEMU_DRV"
            echo qemu_output_path="$QEMU_OUT"
            echo qemu_build_id="$qemu_build_id"
            echo qemu_nix_hash="$QEMU_NIX_HASH"
            echo patch_count="$patch_count"
            echo patch_0001_name="$PATCH_0001_NAME"
            echo patch_0001_hash="$PATCH_0001_HASH"
            echo patch_0002_name="$PATCH_0002_NAME"
            echo patch_0002_hash="$PATCH_0002_HASH"
            echo patch_0003_name="$PATCH_0003_NAME"
            echo patch_0003_hash="$PATCH_0003_HASH"
            echo patch_0004_name="$PATCH_0004_NAME"
            echo patch_0004_hash="$PATCH_0004_HASH"
            echo patch_0005_name="$PATCH_0005_NAME"
            echo patch_0005_hash="$PATCH_0005_HASH"
            echo patch_0006_name="$PATCH_0006_NAME"
            echo patch_0006_hash="$PATCH_0006_HASH"
            echo patch_0007_name="$PATCH_0007_NAME"
            echo patch_0007_hash="$PATCH_0007_HASH"
            echo patch_0008_name="$PATCH_0008_NAME"
            echo patch_0008_hash="$PATCH_0008_HASH"
            echo patch_0009_name="$PATCH_0009_NAME"
            echo patch_0009_hash="$PATCH_0009_HASH"
            echo patch_0010_name="$PATCH_0010_NAME"
            echo patch_0010_hash="$PATCH_0010_HASH"
            echo patch_0011_name="$PATCH_0011_NAME"
            echo patch_0011_hash="$PATCH_0011_HASH"
            echo patch_0012_name="$PATCH_0012_NAME"
            echo patch_0012_hash="$PATCH_0012_HASH"
            echo patch_0013_name="$PATCH_0013_NAME"
            echo patch_0013_hash="$PATCH_0013_HASH"
            echo patch_0014_name="$PATCH_0014_NAME"
            echo patch_0014_hash="$PATCH_0014_HASH"
            echo patch_0015_name="$PATCH_0015_NAME"
            echo patch_0015_hash="$PATCH_0015_HASH"
            echo patch_0016_name="$PATCH_0016_NAME"
            echo patch_0016_hash="$PATCH_0016_HASH"
            echo patch_0017_name="$PATCH_0017_NAME"
            echo patch_0017_hash="$PATCH_0017_HASH"
            echo patch_0018_name="$PATCH_0018_NAME"
            echo patch_0018_hash="$PATCH_0018_HASH"
            echo patch_0019_name="$PATCH_0019_NAME"
            echo patch_0019_hash="$PATCH_0019_HASH"
            echo patch_0020_name="$PATCH_0020_NAME"
            echo patch_0020_hash="$PATCH_0020_HASH"
            echo patch_series_hash="$patch_series_hash"
            echo plugins_enabled=true
            echo patch_apply_list_matches="$patch_apply_list_matches"
            echo plugin_exports_present="$plugin_exports_present"
            echo rr_switch_quantum_default_zero="$rr_switch_quantum_default_zero"
            echo non_sim_icount_patch_present="$non_sim_icount_patch_present"
            echo no_warp_with_plugin_patch_present="$no_warp_with_plugin_patch_present"
            echo qemu_clock_deadline_patch_present="$qemu_clock_deadline_patch_present"
            echo qemu_rtc_patch_present="$qemu_rtc_patch_present"
            echo qemu_internal_entropy_patch_present="$qemu_internal_entropy_patch_present"
            echo qemu_guest_random_patch_present="$qemu_guest_random_patch_present"
            echo qemu_network_rx_patch_present="$qemu_network_rx_patch_present"
            echo qemu_time_advance_patch_present="$qemu_time_advance_patch_present"
            echo qemu_plugin_icount_raw_patch_present="$qemu_plugin_icount_raw_patch_present"
            echo qemu_plugin_vcpu_exit_patch_present="$qemu_plugin_vcpu_exit_patch_present"
            echo qemu_plugin_wake_fd_patch_present="$qemu_plugin_wake_fd_patch_present"
            echo qemu_plugin_tcg_exec_cb_patch_present="$qemu_plugin_tcg_exec_cb_patch_present"
            echo qemu_plugin_tb_entry_icount_patch_present="$qemu_plugin_tb_entry_icount_patch_present"
            echo qemu_block_shmem_patch_present="$qemu_block_shmem_patch_present"
            echo qemu_block_shmem_io_fixes_patch_present="$qemu_block_shmem_io_fixes_patch_present"
            echo qemu_block_write_sentinel_patch_present="$qemu_block_write_sentinel_patch_present"
            echo qemu_dev_cb_api_patch_present="$qemu_dev_cb_api_patch_present"
            echo qemu_9p_shmem_patch_present="$qemu_9p_shmem_patch_present"
            echo qemu_net_tx_callback_patch_present="$qemu_net_tx_callback_patch_present"
            echo s1_result_consumed=true
            echo s1_result_status=PASS
            echo s1_source=checks.crucible.phase0.s1Fingerprint
            echo s1_horizon_extended_hash="$s1_horizon_extended_hash"
            echo s1_horizon_register_hash="$s1_horizon_register_hash"
            echo s1_horizon_ram_hash="$s1_horizon_ram_hash"
            echo s1_pause_retired="$s1_pause_retired"
            echo s1_pause_overshoot="$s1_pause_overshoot"
            echo artifact_build_id_match="$artifact_build_id_match"
            echo changed_build_id="$changed_build_id"
            echo artifact_mismatch_regates="$artifact_mismatch_regates"
            echo changed_build_negative_control=mutated_build_id_material
            echo full_upstream_inertness_comparison="$full_upstream_inertness_comparison"
            echo qemu_inert_gate_status="$qemu_inert_gate_status"
            echo fallback_adopted="$fallback_adopted"
            echo s9_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S9 QEMU build identity and inertness spike";
    };
  }
