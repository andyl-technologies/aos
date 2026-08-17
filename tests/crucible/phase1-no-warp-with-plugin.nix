{
  pkgs,
  lib,
  qemuPackage ? null,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0004-crucible-no-warp-with-plugin.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-no-warp-with-plugin.c;
  qemuPackageResultLines =
    if qemuPackage == null
    then ''
      qemu_package=standalone-fixture
      qemu_package_version=standalone-fixture
    ''
    else ''
      qemu_package=${qemuPackage}
      qemu_package_version=${qemuPackage.version}
    '';

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failuresFor = label: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${label}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  qemuNixRequirements = [
    {
      label = "no-warp patch wiring";
      needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
    }
  ];

  patchRequirements = [
    {
      label = "warp function";
      needle = "void icount_start_warp_timer(void)";
    }
    {
      label = "time-control predicate";
      needle = "qemu_plugin_has_time_control()";
    }
    {
      label = "sim accelerator gate";
      needle = ''strcmp(current_accel_name(), "sim") == 0'';
    }
    {
      label = "notify preservation";
      needle = "qemu_clock_notify(QEMU_CLOCK_VIRTUAL)";
    }
    {
      label = "bias warp suppression";
      needle = "advance qemu_icount_bias";
    }
    {
      label = "realtime warp timer suppression";
      needle = "arm the realtime warp timer";
    }
    {
      label = "plugin-disabled inert stub";
      needle = "static inline bool qemu_plugin_has_time_control(void)";
    }
    {
      label = "time-control rationale";
      needle = "In sim mode, a time-control plugin owns idle advancement";
    }
  ];

  microtestRequirements = [
    {
      label = "patched warp fixture include";
      needle = "#include \"accel/tcg/icount-common.c\"";
    }
    {
      label = "patched plugin API fixture include";
      needle = "#include \"plugins/api-system.c\"";
    }
    {
      label = "time-control request";
      needle = "qemu_plugin_request_time_control()";
    }
    {
      label = "time-control predicate assertion";
      needle = "qemu_plugin_has_time_control()";
    }
    {
      label = "sim predicate model";
      needle = "current_accel_name(void)";
    }
    {
      label = "realtime read suppression assertion";
      needle = "virtual_rt_clock_reads != 0";
    }
    {
      label = "deadline read suppression assertion";
      needle = "virtual_deadline_reads != 0";
    }
    {
      label = "plugin-authorized jump";
      needle = "qemu_plugin_update_ns(handle, 4096)";
    }
    {
      label = "non-sim time-control inertness";
      needle = "non_sim_time_control_keeps_upstream_warp=true";
    }
    {
      label = "non-sim sleep-on timer inertness";
      needle = "non_sim_time_control_keeps_upstream_sleep_on_timer=true";
    }
    {
      label = "stock negative control";
      needle = "stock_negative_control_would_warp=%s";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-no-warp-with-plugin.c" microtestSource microtestRequirements;
in
  if failures != []
  then throw "crucible phase1 no-warp-with-plugin check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-no-warp-with-plugin";
      version = "0";
      src = null;

      inherit microtestSource patchSource;
      passAsFile = ["microtestSource" "patchSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
      ];

      phases = [
        {
          name = "run-no-warp-with-plugin-microtest";
          script = ''
            set -eu

            mkdir -p accel/tcg include/qemu plugins qemu system migration qapi hw/core
            : > qemu/osdep.h
            : > qemu/cutils.h
            : > qemu/accel.h
            : > qemu/main-loop.h
            : > qemu/option.h
            : > qemu/seqlock.h
            : > qemu/error-report.h
            : > migration/vmstate.h
            : > qapi/error.h
            : > system/cpus.h
            : > system/replay.h
            : > system/qtest.h
            : > system/runstate.h
            : > system/cpu-timers.h
            : > system/cpu-timers-internal.h
            : > hw/core/cpu.h

            cat > include/qemu/plugin.h <<'PLUGIN_HEADER_FIXTURE'
            #ifndef QEMU_PLUGIN_H
            #define QEMU_PLUGIN_H

            #include <stdbool.h>

            typedef struct GArray GArray;
            typedef struct CPUState CPUState;
            typedef struct QemuPluginList QemuPluginList;

            #ifdef CONFIG_PLUGIN
            void qemu_plugin_flush_cb(void);

            void qemu_plugin_atexit_cb(void);

            void qemu_plugin_add_dyn_cb_arr(GArray *arr);

            static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
            {
              (void)cpu;
            }

            #else /* !CONFIG_PLUGIN */

            static inline void qemu_plugin_add_opts(void)
            { }

            static inline void qemu_plugin_opt_parse(const char *optstr,
                                                     QemuPluginList *head)
            {
              (void)optstr;
              (void)head;
            }
            #endif

            #endif /* QEMU_PLUGIN_H */
            PLUGIN_HEADER_FIXTURE

            cat > plugins/api-system.c <<'PLUGIN_API_FIXTURE'
            /*
             * Time control
             */
            static bool has_control;
            static Error *migration_blocker;

            const void *qemu_plugin_request_time_control(void)
            {
                if (!has_control) {
                    has_control = true;
                    error_setg(&migration_blocker,
                               "TCG plugin time control does not support migration");
                    migrate_add_blocker(&migration_blocker, NULL);
                    return &has_control;
                }
                return NULL;
            }

            static void advance_virtual_time__async(CPUState *cpu, run_on_cpu_data data)
            {
                (void)cpu;
                int64_t new_time = data.host_ulong;
                qemu_clock_advance_virtual_time(new_time);
            }

            void qemu_plugin_update_ns(const void *handle, int64_t new_time)
            {
                if (handle == &has_control) {
                    /* Need to execute out of cpu_exec, so bql can be locked. */
                    async_run_on_cpu(current_cpu,
                                     advance_virtual_time__async,
                                     RUN_ON_CPU_HOST_ULONG(new_time));
                }
            }
            PLUGIN_API_FIXTURE

            cat > accel/tcg/icount-common.c <<'ICOUNT_FIXTURE'
            #include "qemu/osdep.h"
            #include "qemu/cutils.h"
            #include "migration/vmstate.h"
            #include "qapi/error.h"
            #include "qemu/error-report.h"
            #include "system/cpus.h"
            #include "system/qtest.h"
            #include "qemu/main-loop.h"
            #include "qemu/option.h"
            #include "qemu/seqlock.h"
            #include "system/replay.h"
            #include "system/runstate.h"
            #include "hw/core/cpu.h"
            #include "system/cpu-timers.h"
            #include "system/cpu-timers-internal.h"

            static bool icount_sleep = true;

            void icount_start_warp_timer(void)
            {
                int64_t clock;
                int64_t deadline;

                assert(icount_enabled());

                /*
                 * Nothing to do if the VM is stopped: QEMU_CLOCK_VIRTUAL timers
                 * do not fire, so computing the deadline does not make sense.
                 */
                if (!runstate_is_running()) {
                    return;
                }

                if (replay_mode != REPLAY_MODE_PLAY) {
                    if (!all_cpu_threads_idle()) {
                        return;
                    }

                    if (qtest_enabled()) {
                        /* When testing, qtest commands advance icount.  */
                        return;
                    }

                    replay_checkpoint(CHECKPOINT_CLOCK_WARP_START);
                } else {
                    /* warp clock deterministically in record/replay mode */
                    if (!replay_checkpoint(CHECKPOINT_CLOCK_WARP_START)) {
                        /*
                         * vCPU is sleeping and warp can't be started.
                         * It is probably a race condition: notification sent
                         * to vCPU was processed in advance and vCPU went to sleep.
                         * Therefore we have to wake it up for doing something.
                         */
                        if (replay_has_event()) {
                            qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
                        }
                        return;
                    }
                }

                /* We want to use the earliest deadline from ALL vm_clocks */
                clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL_RT);
                deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,
                                                      ~QEMU_TIMER_ATTR_EXTERNAL);
                if (deadline < 0) {
                    if (!icount_sleep) {
                        warn_report_once("icount sleep disabled and no active timers");
                    }
                    return;
                }

                if (deadline > 0) {
                    /*
                     * Ensure QEMU_CLOCK_VIRTUAL proceeds even when the virtual CPU goes to
                     * sleep.  Otherwise, the CPU might be waiting for a future timer
                     * interrupt to wake it up, but the interrupt never comes because
                     * the vCPU isn't running any insns and thus doesn't advance the
                     * QEMU_CLOCK_VIRTUAL.
                     */
                    if (!icount_sleep) {
                        /*
                         * We never let VCPUs sleep in no sleep icount mode.
                         * If there is a pending QEMU_CLOCK_VIRTUAL timer we just advance
                         * to the next QEMU_CLOCK_VIRTUAL event and notify it.
                         * It is useful when we want a deterministic execution time,
                         * isolated from host latencies.
                         */
                        seqlock_write_lock(&timers_state.vm_clock_seqlock,
                                           &timers_state.vm_clock_lock);
                        qatomic_set_i64(&timers_state.qemu_icount_bias,
                                        timers_state.qemu_icount_bias + deadline);
                        seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                                             &timers_state.vm_clock_lock);
                        qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
                    } else {
                        /*
                         * We do stop VCPUs and only advance QEMU_CLOCK_VIRTUAL after some
                         * "real" time, (related to the time left until the next event) has
                         * passed. The QEMU_CLOCK_VIRTUAL_RT clock will do this.
                         * This avoids that the warps are visible externally; for example,
                         * you will not be sending network packets continuously instead of
                         * every 100ms.
                         */
                        seqlock_write_lock(&timers_state.vm_clock_seqlock,
                                           &timers_state.vm_clock_lock);
                        if (timers_state.vm_clock_warp_start == -1
                            || timers_state.vm_clock_warp_start > clock) {
                            timers_state.vm_clock_warp_start = clock;
                        }
                        seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                                             &timers_state.vm_clock_lock);
                        timer_mod_anticipate(timers_state.icount_warp_timer,
                                             clock + deadline);
                    }
                } else if (deadline == 0) {
                    qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
                }
            }
            ICOUNT_FIXTURE

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp include/qemu/plugin.h qemu/plugin.h
            cp "$microtestSourcePath" phase1-no-warp-with-plugin.c
            cc -std=c11 -O2 -Wall -Wextra -Werror -DCONFIG_PLUGIN -DCONFIG_SOFTMMU \
              -I . \
              phase1-no-warp-with-plugin.c \
              -o phase1-no-warp-with-plugin

            mkdir -p "$out"
            ./phase1-no-warp-with-plugin > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^patched_icount_start_warp_timer_fixture=true$' "$out/result"
            grep -q '^time_control_predicate_exercised=true$' "$out/result"
            grep -q '^time_control_suppresses_sleep_off_bias_warp=true$' "$out/result"
            grep -q '^time_control_suppresses_sleep_on_realtime_timer=true$' "$out/result"
            grep -q '^non_sim_time_control_keeps_upstream_warp=true$' "$out/result"
            grep -q '^non_sim_time_control_keeps_upstream_sleep_on_timer=true$' "$out/result"
            grep -q '^notify_preserved_under_time_control=true$' "$out/result"
            grep -q '^virtual_clock_reads_under_time_control=0$' "$out/result"
            grep -q '^realtime_clock_reads_under_time_control=0$' "$out/result"
            grep -q '^plugin_authorized_jump_advances_virtual_time=true$' "$out/result"
            grep -q '^stock_negative_control_would_warp=true$' "$out/result"

            cp "$patchSourcePath" "$out/${patchName}"
            cp accel/tcg/icount-common.c "$out/icount-common.c.patched"
            cp include/qemu/plugin.h "$out/plugin.h.patched"
            cp plugins/api-system.c "$out/api-system.c.patched"
            cat >> "$out/result" <<'RESULT'
            check=checks.crucible.phase1.noWarpWithPlugin
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-3
            patch=0004-crucible-no-warp-with-plugin.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            sim_predicate=current_accel_name==sim
            time_control_predicate=qemu_plugin_has_time_control
            non_sim_time_control_warp=upstream
            non_sim_time_control_sleep_on_timer=upstream
            wall_clock_warp_under_time_control=false
            notify_preserved_under_time_control=true
            RESULT
          '';
        }
      ];
    }
