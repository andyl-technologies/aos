{
  pkgs,
  lib,
  patchName ? "0011-crucible-plugin-icount-raw.patch",
  qemuPackage ? null,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-plugin-runtime-apis.c;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;
  allPatchNames = [
    "0011-crucible-plugin-icount-raw.patch"
    "0012-crucible-plugin-vcpu-exit.patch"
    "0013-crucible-plugin-wake-fd.patch"
    "0014-crucible-plugin-tcg-exec-cb.patch"
  ];
  taskIds = ["T-PATCH-11"];
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

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  patchRequirements =
    if patchName == "0011-crucible-plugin-icount-raw.patch"
    then [
      {
        label = "raw icount export";
        needle = "qemu_plugin_icount_raw";
      }
      {
        label = "bias-excluded raw icount source";
        needle = "icount_get_raw()";
      }
      {
        label = "icount header";
        needle = "#include \"system/cpu-timers.h\"";
      }
    ]
    else if patchName == "0012-crucible-plugin-vcpu-exit.patch"
    then [
      {
        label = "force vCPU exit export";
        needle = "qemu_plugin_force_vcpu_exit";
      }
      {
        label = "exit request write";
        needle = "current_cpu->exit_request";
      }
      {
        label = "ordered exit request write";
        needle = "qatomic_set_mb";
      }
    ]
    else if patchName == "0013-crucible-plugin-wake-fd.patch"
    then [
      {
        label = "wake fd registration export";
        needle = "qemu_plugin_register_wake_fd";
      }
      {
        label = "main-loop wait export";
        needle = "qemu_plugin_main_loop_wait";
      }
      {
        label = "fd handler integration";
        needle = "qemu_set_fd_handler";
      }
      {
        label = "blocking main-loop wait";
        needle = "main_loop_wait(false)";
      }
      {
        label = "BQL guard";
        needle = "bql_locked()";
      }
    ]
    else [
      {
        label = "TCG exec callback export";
        needle = "qemu_plugin_register_tcg_exec_cb";
      }
      {
        label = "TCG exec callback type";
        needle = "qemu_plugin_tcg_exec_cb_t";
      }
      {
        label = "single null-check helper";
        needle = "if (qemu_plugin_tcg_exec_cb)";
      }
      {
        label = "RR loop callback hook";
        needle = "qemu_plugin_maybe_fire_tcg_exec_cb(cpu)";
      }
    ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix (
      map (name: {
        label = "QEMU patch wiring for ${name}";
        needle = "patch -p1 < \${./qemu-patches/${name}}";
      })
      allPatchNames
    )
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-plugin-runtime-apis.c" microtestSource [
      {
        label = "patched fixture include";
        needle = "#include \"plugins/api-system.c\"";
      }
      {
        label = "raw icount exercised";
        needle = "raw_icount_bias_independent=true";
      }
      {
        label = "vCPU exit exercised";
        needle = "first_exit_phase_normalized=true";
      }
      {
        label = "wake fd exercised";
        needle = "wake_fd_drained=true";
      }
      {
        label = "main-loop wait exercised";
        needle = "main_loop_wait_blocking=true";
      }
      {
        label = "TCG exec callback exercised";
        needle = "tcg_exec_callback_after_icount_process=true";
      }
      {
        label = "stock negative control";
        needle = "stock_negative_control_plugin_runtime_symbols_absent=true";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "T-PATCH-11 checklist complete";
        needle = "- [x] **T-PATCH-11**";
      }
      {
        label = "raw icount RFC export";
        needle = "qemu_plugin_icount_raw";
      }
      {
        label = "force vCPU exit RFC export";
        needle = "qemu_plugin_force_vcpu_exit";
      }
      {
        label = "wake fd RFC export";
        needle = "qemu_plugin_register_wake_fd";
      }
      {
        label = "TCG exec callback RFC export";
        needle = "qemu_plugin_register_tcg_exec_cb";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes plugin runtime API check";
        needle = "pluginRuntimeApis = import ./phase1-plugin-runtime-apis.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 plugin-runtime-apis check failed for ${patchName}:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-plugin-runtime-apis-${lib.removeSuffix ".patch" patchName}";
      version = "0";
      src = null;

      inherit microtestSource;
      passAsFile = ["microtestSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.gawk
        pkgs.grep
        pkgs.patch
      ];

      phases = [
        {
          name = "run-plugin-runtime-apis-microtest";
          script = ''
            set -eu

            mkdir -p accel/tcg hw include/qemu include/system migration net plugins qapi qemu
            : > hw/boards.h
            : > migration/blocker.h
            : > net/net.h
            : > qapi/error.h
            : > qemu/plugin-memory.h
            : > qemu/timer.h
            : > qemu/lockable.h
            : > qemu/notify.h
            : > qemu/guest-random.h
            : > exec-cpu-common-placeholder
            mkdir -p exec tcg
            : > exec/cpu-common.h
            : > tcg/startup.h
            : > accel/tcg/tcg-accel-ops.h
            : > accel/tcg/tcg-accel-ops-rr.h
            : > accel/tcg/tcg-accel-ops-icount.h

            cat > qemu/osdep.h <<'OSDEP_FIXTURE'
            #ifndef QEMU_OSDEP_H
            #define QEMU_OSDEP_H

            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <sys/types.h>

            #define qatomic_set_mb(ptr, value) (*(ptr) = (value))

            #endif
            OSDEP_FIXTURE

            cat > qemu/main-loop.h <<'MAIN_LOOP_FIXTURE'
            #ifndef QEMU_MAIN_LOOP_H
            #define QEMU_MAIN_LOOP_H

            #include <stdbool.h>

            #ifndef CRUCIBLE_IOHANDLER_DEFINED
            typedef void IOHandler(void *opaque);
            #endif

            bool bql_locked(void);
            void main_loop_wait(int nonblocking);
            void qemu_set_fd_handler(int fd, IOHandler *fd_read,
                                     IOHandler *fd_write, void *opaque);

            #endif
            MAIN_LOOP_FIXTURE

            cat > include/system/cpu-timers.h <<'CPU_TIMERS_FIXTURE'
            #ifndef SYSTEM_CPU_TIMERS_H
            #define SYSTEM_CPU_TIMERS_H

            #include <stdint.h>

            extern int use_icount;
            #define ICOUNT_DISABLED 0
            #define ICOUNT_PRECISE 1
            #define icount_enabled() (use_icount)

            int64_t icount_get_raw(void);

            #endif
            CPU_TIMERS_FIXTURE

            cat > include/qemu/qemu-plugin.h <<'PLUGIN_HEADER_FIXTURE'
            #ifndef QEMU_QEMU_PLUGIN_H
            #define QEMU_QEMU_PLUGIN_H

            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>

            #define QEMU_PLUGIN_API

            typedef uint64_t qemu_plugin_id_t;

            typedef void (*qemu_plugin_vcpu_simple_cb_t)(qemu_plugin_id_t id,
                                                         unsigned int vcpu_index);

            typedef void (*qemu_plugin_vcpu_udata_cb_t)(unsigned int vcpu_index,
                                                        void *userdata);

            /**
             * qemu_plugin_uninstall() - Uninstall a plugin
             * @id: this plugin's opaque ID
             * @cb: callback to be called once the plugin has been removed
             */
            QEMU_PLUGIN_API
            void qemu_plugin_uninstall(qemu_plugin_id_t id, void *cb);

            QEMU_PLUGIN_API
            const void *qemu_plugin_request_time_control(void);

            QEMU_PLUGIN_API
            void qemu_plugin_update_ns(const void *handle, int64_t time);

            QEMU_PLUGIN_API
            bool qemu_plugin_has_time_control(void);

            /**
             * qemu_plugin_advance_virtual_time_direct() - advance virtual time directly
             * @time: absolute QEMU_CLOCK_VIRTUAL time in nanoseconds
             *
             * Advances virtual time synchronously after plugin time control has been
             * acquired, runs due virtual-clock timers inline, and drains bottom halves
             * scheduled by those timers before returning. If no plugin owns time control
             * or the call is outside QEMU's BQL-held idle/main-loop context, the call
             * fails closed and leaves virtual time unchanged.
             */
            QEMU_PLUGIN_API
            void qemu_plugin_advance_virtual_time_direct(int64_t time);

            /**
             * qemu_plugin_drain_main_loop() - run one non-blocking main-loop pass
             *
             * Processes pending main-loop work without blocking on host file descriptors or
             * timers and without implicitly advancing virtual time. If no plugin owns time
             * control or the call is outside QEMU's BQL-held idle/main-loop context, the
             * call fails closed and does not enter the main loop.
             */
            QEMU_PLUGIN_API
            void qemu_plugin_drain_main_loop(void);

            /**
             * qemu_plugin_net_inject() - inject an inbound frame into the default NIC
             * @data: Ethernet frame bytes
             * @len: byte length of @data
             */
            QEMU_PLUGIN_API
            int qemu_plugin_net_inject(const uint8_t *data, size_t len);

            #endif
            PLUGIN_HEADER_FIXTURE

            cat > include/qemu/plugin.h <<'PLUGIN_INTERNAL_FIXTURE'
            #ifndef QEMU_PLUGIN_H
            #define QEMU_PLUGIN_H

            #include "qemu/qemu-plugin.h"

            typedef struct CPUState CPUState;
            typedef void GArray;

            #ifdef CONFIG_PLUGIN
            void qemu_plugin_flush_cb(void);

            void qemu_plugin_atexit_cb(void);

            void qemu_plugin_add_dyn_cb_arr(GArray *arr);

            static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
            {
                (void)cpu;
            }
            #else
            static inline void qemu_plugin_flush_cb(void)
            { }

            static inline void qemu_plugin_atexit_cb(void)
            { }

            static inline
            void qemu_plugin_add_dyn_cb_arr(GArray *arr)
            { }
            #endif

            #endif
            PLUGIN_INTERNAL_FIXTURE

            cat > plugins/api-system.c <<'PLUGIN_API_SYSTEM_FIXTURE'
            #include "qemu/osdep.h"
            #include "qemu/main-loop.h"
            #include "net/net.h"
            #include "qapi/error.h"
            #include "migration/blocker.h"
            #include "hw/boards.h"
            #include "qemu/timer.h"
            #include "qemu/plugin-memory.h"
            #include "qemu/plugin.h"

            /*
             * In system mode we cannot trace the binary being executed so the
             * system-mode plugin API provides control-plane helpers instead.
             */

            typedef struct AioContext AioContext;
            typedef struct CPUState CPUState;
            typedef struct Error Error;
            typedef struct NetClientState NetClientState;
            typedef struct run_on_cpu_data {
                long host_ulong;
            } run_on_cpu_data;

            #define RUN_ON_CPU_HOST_ULONG(value) \
                ((run_on_cpu_data){.host_ulong = (value)})
            #define QEMU_CLOCK_VIRTUAL 1

            extern CPUState *current_cpu;
            void error_setg(Error **errp, const char *message, ...);
            void migrate_add_blocker(Error **errp, void *unused);
            void async_run_on_cpu(CPUState *cpu,
                                  void (*fn)(CPUState *, run_on_cpu_data),
                                  run_on_cpu_data data);
            int64_t qemu_clock_advance_virtual_time(int64_t new_time);
            bool qemu_clock_run_timers(int clock);
            AioContext *qemu_get_aio_context(void);
            int aio_bh_poll(AioContext *ctx);

            /*
             * Time control
             */
            static bool has_control;
            static Error *migration_blocker;

            bool qemu_plugin_has_time_control(void)
            {
                return has_control;
            }

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
                int64_t new_time = data.host_ulong;

                (void)cpu;
                qemu_clock_advance_virtual_time(new_time);
            }

            void qemu_plugin_update_ns(const void *handle, int64_t new_time)
            {
                if (handle == &has_control) {
                    async_run_on_cpu(current_cpu,
                                     advance_virtual_time__async,
                                     RUN_ON_CPU_HOST_ULONG(new_time));
                }
            }

            static bool qemu_plugin_time_control_call_permitted(void)
            {
                return has_control && bql_locked();
            }

            static void qemu_plugin_drain_bottom_halves(void)
            {
                AioContext *aio_context = qemu_get_aio_context();

                if (aio_context == NULL) {
                    return;
                }

                while (aio_bh_poll(aio_context)) {
                }
            }

            void qemu_plugin_advance_virtual_time_direct(int64_t new_time)
            {
                if (!qemu_plugin_time_control_call_permitted()) {
                    return;
                }

                qemu_clock_advance_virtual_time(new_time);
                qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL);
                qemu_plugin_drain_bottom_halves();
            }

            void qemu_plugin_drain_main_loop(void)
            {
                if (!qemu_plugin_time_control_call_permitted()) {
                    return;
                }

                main_loop_wait(true);
                qemu_plugin_drain_bottom_halves();
            }


            static NetClientState *qemu_plugin_default_nic_queue(void)
            {
                NetClientState *nc;

                nc = NULL;
                return nc;
            }
            PLUGIN_API_SYSTEM_FIXTURE

            cat > accel/tcg/tcg-accel-ops-rr.c <<'TCG_RR_FIXTURE'
            #include "qemu/osdep.h"
            #include "qemu/lockable.h"
            #include "system/cpu-timers.h"
            #include "qemu/main-loop.h"
            #include "qemu/notify.h"
            #include "qemu/guest-random.h"
            #include "exec/cpu-common.h"
            #include "tcg/startup.h"
            #include "tcg-accel-ops.h"
            #include "tcg-accel-ops-rr.h"
            #include "tcg-accel-ops-icount.h"

            typedef struct CPUState CPUState;
            #define EXCP_DEBUG 1
            int tcg_cpu_exec(CPUState *cpu);
            void icount_process_data(CPUState *cpu);
            void bql_lock(void);

            void rr_fixture_exec_once(CPUState *cpu)
            {
                            int r;

                            r = tcg_cpu_exec(cpu);
                            if (icount_enabled()) {
                                icount_process_data(cpu);
                            }
                            bql_lock();

                            if (r == EXCP_DEBUG) {
                            }
            }
            TCG_RR_FIXTURE

            for symbol in \
              qemu_plugin_icount_raw \
              qemu_plugin_force_vcpu_exit \
              qemu_plugin_register_wake_fd \
              qemu_plugin_main_loop_wait \
              qemu_plugin_register_tcg_exec_cb
            do
              cat > "stock-plugin-runtime-negative-$symbol.c" <<STOCK_NEGATIVE
            #include <stddef.h>
            #include <stdint.h>
            #include "qemu/qemu-plugin.h"

            int main(void)
            {
                (void)$symbol;
                return 0;
            }
            STOCK_NEGATIVE
              if cc -std=c11 -Wall -Werror -I include -I . \
                -c "stock-plugin-runtime-negative-$symbol.c" \
                -o "stock-plugin-runtime-negative-$symbol.o" \
                2> "stock-plugin-runtime-negative-$symbol.err"
              then
                echo "stock plugin runtime API unexpectedly compiled for $symbol" >&2
                exit 1
              fi
              grep -q "$symbol" "stock-plugin-runtime-negative-$symbol.err"
              cat "stock-plugin-runtime-negative-$symbol.err" \
                >> stock-plugin-runtime-negative.err
            done

            for patch in ${builtins.concatStringsSep " " allPatchNames}; do
              patch --batch --fuzz=0 -p1 < "${patchDir}/$patch"
            done

            grep -q 'qemu_plugin_icount_raw' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_force_vcpu_exit' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_register_wake_fd' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_main_loop_wait' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_register_tcg_exec_cb' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_maybe_fire_tcg_exec_cb(cpu);' accel/tcg/tcg-accel-ops-rr.c
            awk '
              /icount_process_data\(cpu\);/ { saw_icount = NR }
              /qemu_plugin_maybe_fire_tcg_exec_cb\(cpu\);/ { saw_callback = NR }
              END { exit !(saw_icount && saw_callback && saw_icount < saw_callback) }
            ' accel/tcg/tcg-accel-ops-rr.c

            cp "$microtestSourcePath" phase1-plugin-runtime-apis.c
            cc -std=c11 -O2 -Wall -Wextra -Werror -DCONFIG_PLUGIN \
              -I include \
              -I . \
              phase1-plugin-runtime-apis.c \
              -o phase1-plugin-runtime-apis

            mkdir -p "$out"
            ./phase1-plugin-runtime-apis > "$out/plugin-runtime-apis-microtest"
            grep -q '^PASS$' "$out/plugin-runtime-apis-microtest"
            grep -q '^raw_icount_bias_independent=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^raw_icount_disabled_returns_zero=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^first_exit_phase_normalized=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_registered=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_drained=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^main_loop_wait_blocking=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^main_loop_wait_bql_guard=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^tcg_exec_callback_count=1$' "$out/plugin-runtime-apis-microtest"
            grep -q '^tcg_exec_callback_icount=77$' "$out/plugin-runtime-apis-microtest"
            grep -q '^tcg_exec_callback_after_icount_process=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^tcg_exec_disabled_single_null_check=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^stock_negative_control_plugin_runtime_symbols_absent=true$' "$out/plugin-runtime-apis-microtest"

            cp stock-plugin-runtime-negative.err "$out/stock-negative-control.err"
            cp plugins/api-system.c "$out/api-system.c.patched"
            cp include/qemu/qemu-plugin.h "$out/qemu-plugin.h.patched"
            cp include/qemu/plugin.h "$out/plugin.h.patched"
            cp accel/tcg/tcg-accel-ops-rr.c "$out/tcg-accel-ops-rr.c.patched"

            cat > "$out/result" <<'RESULT'
            PASS
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            raw_icount_symbol=qemu_plugin_icount_raw
            raw_icount_bias_independent=true
            raw_icount_disabled_returns_zero=true
            force_vcpu_exit_symbol=qemu_plugin_force_vcpu_exit
            first_exit_phase_normalized=true
            wake_fd_registration_symbol=qemu_plugin_register_wake_fd
            main_loop_wait_symbol=qemu_plugin_main_loop_wait
            wake_fd_registered=true
            wake_fd_drained=true
            main_loop_wait_blocking=true
            main_loop_wait_bql_guard=true
            tcg_exec_callback_symbol=qemu_plugin_register_tcg_exec_cb
            tcg_exec_callback_count=1
            tcg_exec_callback_after_icount_process=true
            tcg_exec_callback_after_icount_context=true
            tcg_exec_disabled_single_null_check=true
            RESULT
          '';
        }
      ];
    }
