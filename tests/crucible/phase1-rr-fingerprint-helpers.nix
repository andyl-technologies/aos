{
  pkgs,
  lib,
  qemuPackage ? null,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0002-crucible-rr-fingerprint-helpers.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-rr-fingerprint-helpers.c;
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
      label = "RR fingerprint helper patch wiring";
      needle = "patch -p1 < \${./qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}";
    }
  ];

  patchRequirements = [
    {
      label = "RR switch quantum option";
      needle = "rr_switch_quantum";
    }
    {
      label = "RR switch quantum export";
      needle = "uint64_t icount_crucible_rr_switch_quantum(void)";
    }
    {
      label = "RR cursor export";
      needle = "uint64_t icount_crucible_rr_cursor_position(CPUState *cpu)";
    }
    {
      label = "per-vCPU budget clamp";
      needle = "return MIN(limit, (int64_t)rr_switch_quantum);";
    }
    {
      label = "deadline-safe RR prepare-for-run";
      needle = "cpu->icount_budget = cpu_budget;";
    }
    {
      label = "RR switch quantum sim accelerator guard";
      needle = ''strcmp(current_accel_name(), "sim") != 0'';
    }
    {
      label = "RR idle warp accounting";
      needle = "icount_handle_deadline();";
    }
    {
      label = "migration host-timer normalizer";
      needle = "vmstate_info_crucible_icount_host_timer_int64";
    }
    {
      label = "vCPU register-list plugin export";
      needle = "qemu_plugin_crucible_get_vcpu_registers";
    }
    {
      label = "vCPU register-read plugin export";
      needle = "qemu_plugin_crucible_read_vcpu_register";
    }
    {
      label = "RR current-vCPU sentinel";
      needle = "return UINT64_MAX;";
    }
    {
      label = "RAM hash plugin export";
      needle = "qemu_plugin_crucible_ram_hash";
    }
    {
      label = "pause VM plugin export";
      needle = "qemu_plugin_crucible_pause_vm";
    }
  ];

  microtestRequirements = [
    {
      label = "patched icount fixture include";
      needle = "#include \"accel/tcg/icount-common.c\"";
    }
    {
      label = "patched RR fixture include";
      needle = "#include \"accel/tcg/tcg-accel-ops-rr.c\"";
    }
    {
      label = "patched plugin fixture include";
      needle = "#include \"plugins/api.c\"";
    }
    {
      label = "patched migration fixture include";
      needle = "#include \"system/cpu-timers.c\"";
    }
    {
      label = "RR quantum configured assertion";
      needle = "rr_switch_quantum_configured=true";
    }
    {
      label = "RR budget stock negative control";
      needle = "stock_negative_control_rr_budget_unpinned=true";
    }
    {
      label = "current accelerator fixture";
      needle = "current_accel_name(void)";
    }
    {
      label = "sim-gated RR quantum assertion";
      needle = "rr_switch_quantum_sim_gated=true";
    }
    {
      label = "non-sim stock budget assertion";
      needle = "non_sim_rr_switch_quantum_uses_stock_budget=true";
    }
    {
      label = "deadline-safe prepare-for-run assertion";
      needle = "rr_prepare_for_run_deadline_safe=true";
    }
    {
      label = "pinned RR switch trace assertion";
      needle = "rr_switch_trace_pinned_under_host_jitter=true";
    }
    {
      label = "adaptive RR switch trace negative control";
      needle = "adaptive_rr_switch_trace_negative_control=red";
    }
    {
      label = "configured non-sim RR switch trace negative control";
      needle = "patched_non_sim_rr_switch_trace_negative_control=red";
    }
    {
      label = "symbol stock negative control";
      needle = "stock_negative_control_symbols_absent=true";
    }
    {
      label = "RAM hash assertion";
      needle = "ram_hash_includes_block_id_length_and_bytes=true";
    }
    {
      label = "migration normalizer assertion";
      needle = "migration_host_timer_zeroed_under_icount=true";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-rr-fingerprint-helpers.c" microtestSource microtestRequirements;
in
  if failures != []
  then throw "crucible phase1 RR fingerprint helper check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-rr-fingerprint-helpers";
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
          name = "run-rr-fingerprint-helper-microtest";
          script = ''
            set -eu

            mkdir -p accel/tcg exec hw/boards include/qemu include/system \
              migration plugins qapi qemu sysemu system tcg
            for header in \
              exec/cpu-common.h \
              exec/exec-all.h \
              exec/gdbstub.h \
              exec/ram_addr.h \
              exec/ramblock.h \
              exec/ramlist.h \
              exec/target_page.h \
              exec/translation-block.h \
              exec/translator.h \
              hw/boards.h \
              migration/blocker.h \
              migration/qemu-file-types.h \
              migration/vmstate.h \
              plugins/plugin.h \
              qapi/error.h \
              qemu/accel.h \
              qemu/cutils.h \
              qemu/error-report.h \
              qemu/log.h \
              qemu/main-loop.h \
              qemu/osdep.h \
              qemu/plugin.h \
              qemu/plugin-memory.h \
              qemu/timer.h \
              sysemu/replay.h \
              system/cpus.h \
              system/cpu-timers.h \
              system/runstate.h \
              tcg/tcg.h
            do
              : > "$header"
            done
            mkdir -p disas
            : > disas/disas.h

            cat > accel/tcg/icount-common.c <<'QEMU_FIXTURE'

            #include "qemu/osdep.h"
            #include "qemu/cutils.h"
            #include "migration/vmstate.h"
            #include "qapi/error.h"
            #include "qemu/error-report.h"
            #include "qemu/main-loop.h"
            #include "qemu/timer.h"
            #include "sysemu/replay.h"
            #include "system/cpu-timers.h"

            static bool icount_sleep = true;
            /* Arbitrarily pick 1MIPS as the minimum allowable speed.  */
            #define MAX_ICOUNT_SHIFT 10

            bool icount_align_option;

            /* Do not count executed instructions */
            ICountMode use_icount = ICOUNT_DISABLED;

            static int64_t icount_get_executed(CPUState *cpu)
            {
                return (cpu->icount_budget -
                        (cpu->neg.icount_decr.u16.low + cpu->icount_extra));
            }

            /*
             * Update the global shared timer_state.qemu_icount to take into
             * account executed instructions. This is done by the TCG vCPU
             */

            bool icount_configure(QemuOpts *opts, Error **errp)
            {
                const char *option = qemu_opt_get(opts, "shift");
                bool sleep = qemu_opt_get_bool(opts, "sleep", true);
                bool align = qemu_opt_get_bool(opts, "align", false);
                long time_shift = -1;

                if (!option) {
                    if (qemu_opt_get(opts, "align") != NULL) {
                        error_setg(errp, "Please specify shift option when using align");
                        return false;
                    }
                    return true;
                }

                if (align && !sleep) {
                    error_setg(errp, "align=on and sleep=off are incompatible");
                    return false;
                }

                icount_sleep = sleep;
                if (icount_sleep) {
                    timers_state.icount_warp_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL_RT,
                                                     icount_timer_cb, NULL);
                }
                (void)time_shift;
                use_icount = ICOUNT_PRECISE;
                return true;
            }
            QEMU_FIXTURE

            cat > accel/tcg/tcg-accel-ops-icount.c <<'QEMU_FIXTURE'
            int64_t icount_percpu_budget(int cpu_count)
            {
                int64_t limit = icount_get_limit();
                int64_t timeslice = limit / cpu_count;

                if (timeslice == 0) {
                    timeslice = limit;
                }

                return timeslice;
            }

            void icount_prepare_for_run(CPUState *cpu, int64_t cpu_budget)
            {
                int insns_left;

                /*
                 * These should always be cleared by icount_process_data after
                 * each run.
                 */
                g_assert(cpu->icount_budget == 0);
                g_assert(cpu->icount_extra == 0);

                replay_mutex_lock();

                cpu->icount_budget = MIN(icount_get_limit(), cpu_budget);
                insns_left = MIN(0xffff, cpu->icount_budget);
                cpu->neg.icount_decr.u16.low = insns_left;
                cpu->icount_extra = cpu->icount_budget - insns_left;
                replay_mutex_unlock();
            }
            QEMU_FIXTURE

            cat > accel/tcg/tcg-accel-ops-rr.c <<'QEMU_FIXTURE'
            static void rr_wait_io_event(void)
            {
                CPUState *cpu;

                while (all_cpu_threads_idle()) {
                    rr_stop_kick_timer();
                    qemu_cond_wait_bql(first_cpu->halt_cond);
                }

                rr_start_kick_timer();

                CPU_FOREACH(cpu) {
                    qemu_wait_io_event_common(cpu);
                }
            }
            QEMU_FIXTURE

            cat > system/cpu-timers.c <<'QEMU_FIXTURE'
            #include "qemu/osdep.h"
            #include "qemu/cutils.h"
            #include "migration/vmstate.h"
            #include "qapi/error.h"
            #include "qemu/error-report.h"
            #include "system/cpus.h"

            static const VMStateDescription icount_vmstate_timers = {
                .name = "icount",
                .fields = (const VMStateField[]) {
                    VMSTATE_END_OF_LIST()
                }
            };

            static const VMStateDescription vmstate_timers = {
                .name = "timer",
                .version_id = 2,
                .minimum_version_id = 1,
                .fields = (const VMStateField[]) {
                    VMSTATE_INT64(cpu_ticks_offset, TimersState),
                    VMSTATE_UNUSED(8),
                    VMSTATE_INT64_V(cpu_clock_offset, TimersState, 2),
                    VMSTATE_END_OF_LIST()
                },
                .subsections = (const VMStateDescription * const []) {
                    NULL
                }
            };
            QEMU_FIXTURE

            cat > include/qemu/qemu-plugin.h <<'QEMU_FIXTURE'
            #ifndef QEMU_PLUGIN_H
            #define QEMU_PLUGIN_H
            #include <stdint.h>
            #define QEMU_PLUGIN_API
            QEMU_PLUGIN_API
            int qemu_plugin_read_register(struct qemu_plugin_register *handle,
                                          GByteArray *buf);

            /**
             * qemu_plugin_scoreboard_new() - alloc a new scoreboard
             *
             * @element_size: size (in bytes) for one entry
             */
            struct qemu_plugin_scoreboard;
            QEMU_PLUGIN_API
            struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size);
            #endif
            QEMU_FIXTURE

            cat > include/system/cpu-timers.h <<'QEMU_FIXTURE'
            #ifndef CPU_TIMERS_H
            #define CPU_TIMERS_H
            bool icount_configure(QemuOpts *opts, Error **errp);
            /* used by tcg vcpu thread to calc icount budget */
            int64_t icount_round(int64_t count);

            /* if the CPUs are idle, start accounting real time to virtual clock. */
            void icount_start_warp_timer(void);
            void icount_account_warp_timer(void);
            #endif
            QEMU_FIXTURE

            cat > plugins/api.c <<'QEMU_FIXTURE'
            #include "qemu/main-loop.h"
            #include "qemu/plugin.h"
            #include "qemu/log.h"
            #include "tcg/tcg.h"
            #include "exec/gdbstub.h"
            #include "exec/target_page.h"
            #include "exec/translation-block.h"
            #include "exec/translator.h"
            #include "disas/disas.h"
            #include "plugin.h"

            int qemu_plugin_read_register(struct qemu_plugin_register *reg, GByteArray *buf)
            {
                return gdb_read_register(current_cpu, buf, GPOINTER_TO_INT(reg) - 1);
            }

            struct qemu_plugin_scoreboard *qemu_plugin_scoreboard_new(size_t element_size)
            {
                return plugin_scoreboard_new(element_size);
            }
            QEMU_FIXTURE

            cat > qemu-options.hx <<'QEMU_FIXTURE'
            SRST
            ERST

            DEF("icount", HAS_ARG, QEMU_OPTION_icount, \
                "-icount [shift=N|auto][,align=on|off][,sleep=on|off][,rr=record|replay,rrfile=<filename>[,rrsnapshot=<snapshot>]]\n" \
                "                enable virtual instruction counter with 2^N clock ticks per\n" \
                "                instruction, enable aligning the host and virtual clocks\n" \
                "                or disable real time cpu sleeping, and optionally enable\n" \
                "                record-and-replay mode\n", QEMU_ARCH_ALL)
            SRST
            ``-icount [shift=N|auto][,align=on|off][,sleep=on|off][,rr=record|replay,rrfile=filename[,rrsnapshot=snapshot]]``
                Enable virtual instruction counter. The virtual cpu will execute one
                instruction every 2^N ns of virtual time. If ``auto`` is specified
                then the virtual cpu speed will be automatically adjusted to keep
                option. Whenever the guest clock is behind the host clock and if
                ``align=on`` is specified then we print a message to the user to
                inform about the delay. Currently this option does not work when
                ``shift`` is ``auto``. Note: The sync algorithm will work for those
                shift values for which the guest clock runs ahead of the host clock.
                Typically this happens when the shift value is high (how high
                depends on the host machine). The default if icount is enabled
            QEMU_FIXTURE

            cat > system/vl.c <<'QEMU_FIXTURE'
            static QemuOptsList qemu_icount_opts = {
                .desc = {
                    {
                        .name = "align",
                        .type = QEMU_OPT_BOOL,
                    }, {
                        .name = "sleep",
                        .type = QEMU_OPT_BOOL,
                    }, {
                        .name = "rr",
                        .type = QEMU_OPT_STRING,
                    },
                },
            };
            QEMU_FIXTURE

            cat > stock-rr-fingerprint-helpers-negative.c <<'STOCK_NEGATIVE'
            #include <stddef.h>
            #include <stdint.h>

            typedef struct GByteArray GByteArray;
            struct qemu_plugin_register;

            #include "include/qemu/qemu-plugin.h"

            int main(void)
            {
                uint64_t bytes = 0;
                return (int)qemu_plugin_crucible_ram_hash(&bytes);
            }
            STOCK_NEGATIVE
            if cc -std=c11 -Wall -Werror -I. -Iinclude \
              -c stock-rr-fingerprint-helpers-negative.c \
              -o stock-rr-fingerprint-helpers-negative.o \
              2> stock-rr-fingerprint-helpers-negative.err
            then
              echo "stock RR fingerprint helper API unexpectedly compiled" >&2
              exit 1
            fi
            grep -q 'qemu_plugin_crucible_ram_hash' \
              stock-rr-fingerprint-helpers-negative.err

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp include/qemu/qemu-plugin.h qemu/qemu-plugin.h
            cp include/system/cpu-timers.h system/cpu-timers.h
            cp "$microtestSourcePath" phase1-rr-fingerprint-helpers.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -Wno-unused-parameter -Wno-unused-variable \
              -I. -Iinclude \
              phase1-rr-fingerprint-helpers.c \
              -o phase1-rr-fingerprint-helpers

            mkdir -p "$out"
            ./phase1-rr-fingerprint-helpers > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^rr_switch_quantum_configured=true$' "$out/result"
            grep -q '^rr_switch_quantum_requires_shift=true$' "$out/result"
            grep -q '^rr_switch_quantum_rejects_oversized=true$' "$out/result"
            grep -q '^rr_budget_pinned=true$' "$out/result"
            grep -q '^rr_prepare_for_run_deadline_safe=true$' "$out/result"
            grep -q '^rr_switch_quantum_sim_gated=true$' "$out/result"
            grep -q '^non_sim_rr_switch_quantum_uses_stock_budget=true$' "$out/result"
            grep -q '^rr_switch_trace_pinned_under_host_jitter=true$' "$out/result"
            grep -q '^adaptive_rr_switch_trace_negative_control=red$' "$out/result"
            grep -q '^patched_non_sim_rr_switch_trace_negative_control=red$' "$out/result"
            grep -q '^rr_cursor_clamped=true$' "$out/result"
            grep -q '^rr_idle_boundary_accounts_warp=true$' "$out/result"
            grep -q '^rr_idle_boundary_inert_without_icount=true$' "$out/result"
            grep -q '^vcpu_register_list_requested_by_index=true$' "$out/result"
            grep -q '^vcpu_register_read_requested_by_index=true$' "$out/result"
            grep -q '^rr_current_vcpu_sentinel=UINT64_MAX$' "$out/result"
            grep -q '^ram_hash_includes_block_id_length_and_bytes=true$' "$out/result"
            grep -q '^pause_vm_requests_run_state_paused=true$' "$out/result"
            grep -q '^migration_host_timer_zeroed_under_icount=true$' "$out/result"
            grep -q '^migration_host_timer_preserved_without_icount=true$' "$out/result"
            grep -q '^stock_negative_control_rr_budget_unpinned=true$' "$out/result"
            grep -q '^stock_negative_control_symbols_absent=true$' "$out/result"

            cp "$patchSourcePath" "$out/${patchName}"
            cp accel/tcg/icount-common.c "$out/icount-common.c.patched"
            cp accel/tcg/tcg-accel-ops-icount.c "$out/tcg-accel-ops-icount.c.patched"
            cp accel/tcg/tcg-accel-ops-rr.c "$out/tcg-accel-ops-rr.c.patched"
            cp plugins/api.c "$out/api.c.patched"
            cp system/cpu-timers.c "$out/cpu-timers.c.patched"
            cp stock-rr-fingerprint-helpers-negative.err "$out/stock-negative-control.err"
            cat >> "$out/result" <<'RESULT'
            check=checks.crucible.phase1.rrFingerprintHelpers
            gate=gate:patch-microtests
            tasks=
            open_tasks=T-HARN-20
            status=partial
            patch=0002-crucible-rr-fingerprint-helpers.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            rr_switch_quantum_configured=true
            rr_budget_pinned=true
            rr_prepare_for_run_deadline_safe=true
            rr_switch_quantum_sim_gated=true
            non_sim_rr_switch_quantum_uses_stock_budget=true
            rr_switch_trace_pinned_under_host_jitter=true
            adaptive_rr_switch_trace_negative_control=red
            patched_non_sim_rr_switch_trace_negative_control=red
            rr_cursor_export=true
            rr_idle_boundary_inert_without_icount=true
            plugin_register_exports=true
            plugin_ram_hash_export=true
            plugin_pause_export=true
            migration_host_timer_normalization=true
            RESULT
          '';
        }
      ];
    }
