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
    "0025-crucible-sim-idle-callbacks.patch"
    "0028-crucible-det-ipi.patch"
    "0063-crucible-plugin-vmstop.patch"
    "0068-crucible-guest-clock-faults.patch"
    "0073-crucible-device-wait-vmstop.patch"
  ];
  taskIds =
    if patchName == "0063-crucible-plugin-vmstop.patch"
    || patchName == "0073-crucible-device-wait-vmstop.patch"
    then ["T-QEMU-0063"]
    else ["T-PATCH-11"];
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

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

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
        label = "live single-threaded RR proof export";
        needle = "qemu_plugin_crucible_single_threaded_rr";
      }
      {
        label = "sim accelerator discrimination";
        needle = "strcmp(current_accel_name(), \"sim\") == 0";
      }
      {
        label = "MTTCG rejection";
        needle = "!qemu_tcg_mttcg_enabled()";
      }
      {
        label = "main AioContext fd handler integration";
        needle = "aio_set_fd_handler(qemu_get_aio_context()";
      }
      {
        label = "device wake notifier header";
        needle = "include/system/crucible-plugin-wake.h";
      }
      {
        label = "nonblocking descriptor validation";
        needle = "fcntl(fd, F_GETFL)";
      }
      {
        label = "drain through would-block";
        needle = "errno == EAGAIN || errno == EWOULDBLOCK";
      }
      {
        label = "first RR vCPU kick after successful drain";
        needle = "qemu_cpu_kick(first_cpu)";
      }
      {
        label = "spurious readiness does not kick";
        needle = "if (drained && first_cpu)";
      }
      {
        label = "nested block poll wake rationale";
        needle = "nested aio_poll() waits";
      }
      {
        label = "device repoll after successful drain";
        needle = "QEMU_PLUGIN_WAKE_EVENT_DRAINED";
      }
      {
        label = "terminal wake-fd failure event";
        needle = "QEMU_PLUGIN_WAKE_EVENT_FAILED";
      }
      {
        label = "terminal wake-fd shutdown";
        needle = "qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_ERROR)";
      }
      {
        label = "failed descriptor unregistration";
        needle = "qemu_plugin_unregister_wake_fd(fd)";
      }
      {
        label = "plugin shutdown export";
        needle = "qemu_plugin_request_shutdown";
      }
      {
        label = "clean plugin shutdown cause";
        needle = "SHUTDOWN_CAUSE_HOST_QMP_QUIT";
      }
      {
        label = "fail-loud plugin shutdown cause";
        needle = "SHUTDOWN_CAUSE_HOST_ERROR";
      }
    ]
    else if patchName == "0014-crucible-plugin-tcg-exec-cb.patch"
    then [
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
      {
        label = "exact non-mutating TB-entry icount export";
        needle = "qemu_plugin_icount_at_tb_entry";
      }
      {
        label = "non-mutating current-vCPU observation";
        needle = "icount_get_raw_observed";
      }
    ]
    else if patchName == "0063-crucible-plugin-vmstop.patch"
    then [
      {
        label = "native VM stop export";
        needle = "qemu_plugin_request_vmstop";
      }
      {
        label = "current-vCPU boundary validation";
        needle = "if (!current_cpu";
      }
      {
        label = "precise icount validation";
        needle = "icount_enabled() != ICOUNT_PRECISE";
      }
      {
        label = "serialized sim validation";
        needle = "!qemu_plugin_crucible_single_threaded_rr()";
      }
      {
        label = "native paused runstate transition";
        needle = "vm_stop(RUN_STATE_PAUSED)";
      }
      {
        label = "asynchronous stop flush failure retention";
        needle = "qemu_plugin_crucible_vmstop_flush_status";
      }
      {
        label = "QMP stop flush error propagation";
        needle = "Could not flush devices while stopping the VM";
      }
      {
        label = "premature QMP continue rejection";
        needle = "VM stop admission has not reached paused state";
      }
      {
        label = "failed-flush QMP continue rejection";
        needle = "VM stop failed to flush devices";
      }
    ]
    else [
      {
        label = "shared VM-stop admission helper";
        needle = "qemu_plugin_crucible_vmstop_begin";
      }
      {
        label = "synchronous drained-control stop";
        needle = "qemu_plugin_crucible_vmstop_at_control_boundary";
      }
      {
        label = "exact callback scope validation";
        needle = "qemu_plugin_crucible_exact_boundary_depth == 0";
      }
      {
        label = "non-vCPU exact callback admission";
        needle = "qemu_system_vmstop_request_prepare()";
      }
      {
        label = "asynchronous main-loop stop request";
        needle = "qemu_system_vmstop_request(RUN_STATE_PAUSED)";
      }
      {
        label = "vCPU exit preservation";
        needle = "cpu_stop_current()";
      }
      {
        label = "control-boundary coalescing state";
        needle = "qemu_plugin_control_boundary_scheduled";
      }
      {
        label = "atomic duplicate control-boundary coalescing";
        needle = "qatomic_cmpxchg(&qemu_plugin_control_boundary_scheduled, 0, 1)";
      }
      {
        label = "two-pass post-device control barrier";
        needle = "qemu_plugin_control_boundary_barrier_bh";
      }
      {
        label = "idle-time advance overlap deferral";
        needle = "qatomic_load_acquire(&qemu_plugin_time_advance_pending)";
      }
      {
        label = "post-idle-advance control reschedule";
        needle = "qemu_plugin_schedule_control_boundary();";
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
        label = "execution-mode discriminator fixture exercised";
        needle = "single_threaded_rr_mode_discriminator_fixture_exercised=true";
      }
      {
        label = "wake fd failure paths exercised";
        needle = "wake_fd_hard_error_reported_and_unregistered=true";
      }
      {
        label = "wake fd vCPU kick ordering exercised";
        needle = "wake_fd_kicks_first_vcpu_only_after_drain=true";
      }
      {
        label = "TCG exec callback exercised";
        needle = "tcg_exec_callback_after_icount_process=true";
      }
      {
        label = "exact TB-entry callback icount exercised";
        needle = "tb_entry_icount_nonmutating=true";
      }
      {
        label = "chained, early-exit, and RR TB-entry math exercised";
        needle = "tb_entry_icount_chained_early_exit_multi_vcpu=true";
      }
      {
        label = "stock negative control";
        needle = "stock_negative_control_plugin_runtime_symbols_absent=true";
      }
      {
        label = "native VM stop transition exercised";
        needle = "request_vmstop_native_pause_admission=true";
      }
      {
        label = "native VM stop rejection modes exercised";
        needle = "request_vmstop_rejects_nonexact_modes=true";
      }
      {
        label = "unsafe VM stop callback rejection exercised";
        needle = "request_vmstop_rejects_unsafe_callback_context=true";
      }
      {
        label = "duplicate VM stop admission rejection exercised";
        needle = "request_vmstop_rejects_duplicate_admission=true";
      }
      {
        label = "asynchronous VM stop flush failure exercised";
        needle = "request_vmstop_preserves_async_flush_failure=true";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
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

            mkdir -p accel/tcg hw/core include/qemu include/system migration net plugins qapi qemu
            : > hw/boards.h
            cat > hw/core/cpu.h <<'CPU_CORE_FIXTURE'
            #ifndef HW_CORE_CPU_H
            #define HW_CORE_CPU_H

            #include <stdbool.h>

            extern bool mttcg_enabled;
            #define qemu_tcg_mttcg_enabled() (mttcg_enabled)

            extern CPUState *first_cpu;
            void qemu_cpu_kick(CPUState *cpu);

            #endif
            CPU_CORE_FIXTURE
            : > migration/blocker.h
            : > net/net.h
            : > qapi/error.h
            cat > qemu/error-report.h <<'ERROR_REPORT_FIXTURE'
            #ifndef QEMU_ERROR_REPORT_H
            #define QEMU_ERROR_REPORT_H

            void test_error_report(const char *format, ...);
            #define error_report(...) test_error_report(__VA_ARGS__)

            #endif
            ERROR_REPORT_FIXTURE
            : > qemu/plugin-memory.h
            : > qemu/timer.h
            : > qemu/lockable.h
            cat > qemu/notify.h <<'NOTIFY_FIXTURE'
            #ifndef QEMU_NOTIFY_H
            #define QEMU_NOTIFY_H

            typedef struct Notifier Notifier;
            typedef struct NotifierList NotifierList;

            struct Notifier {
                void (*notify)(Notifier *notifier, void *data);
                Notifier *next;
                NotifierList *list;
            };

            struct NotifierList {
                Notifier *head;
            };

            #define NOTIFIER_LIST_INITIALIZER(_head) { .head = NULL }

            static inline void notifier_list_add(NotifierList *list,
                                                 Notifier *notifier)
            {
                notifier->next = list->head;
                notifier->list = list;
                list->head = notifier;
            }

            static inline void notifier_remove(Notifier *notifier)
            {
                Notifier **link;
                if (notifier->list == NULL) {
                    return;
                }
                link = &notifier->list->head;
                while (*link != NULL && *link != notifier) {
                    link = &(*link)->next;
                }
                if (*link == notifier) {
                    *link = notifier->next;
                }
                notifier->next = NULL;
                notifier->list = NULL;
            }

            static inline void notifier_list_notify(NotifierList *list,
                                                    void *data)
            {
                for (Notifier *notifier = list->head; notifier != NULL;
                     notifier = notifier->next) {
                    notifier->notify(notifier, data);
                }
            }

            #endif
            NOTIFY_FIXTURE
            : > qemu/guest-random.h
            : > exec-cpu-common-placeholder
            mkdir -p exec tcg
            : > exec/cpu-common.h
            : > tcg/startup.h
            : > accel/tcg/tcg-accel-ops.h
            : > accel/tcg/tcg-accel-ops-rr.h
            : > accel/tcg/tcg-accel-ops-icount.h

            cat > include/system/runstate.h <<'RUNSTATE_FIXTURE'
            #ifndef SYSTEM_RUNSTATE_H
            #define SYSTEM_RUNSTATE_H

            #define SHUTDOWN_CAUSE_HOST_ERROR 1
            #define SHUTDOWN_CAUSE_HOST_QMP_QUIT 2

            typedef enum RunState {
                RUN_STATE_PAUSED,
                RUN_STATE__MAX,
            } RunState;

            void qemu_system_shutdown_request(int reason);
            int vm_stop(RunState state);

            #endif
            RUNSTATE_FIXTURE

            cat > include/system/cpus.h <<'CPUS_FIXTURE'
            #ifndef SYSTEM_CPUS_H
            #define SYSTEM_CPUS_H

            #include "system/runstate.h"

            void qemu_system_vmstop_request_prepare(void);
            void qemu_system_vmstop_request(RunState state);
            void cpu_stop_current(void);

            #endif
            CPUS_FIXTURE

            cat > qemu/osdep.h <<'OSDEP_FIXTURE'
            #ifndef QEMU_OSDEP_H
            #define QEMU_OSDEP_H

            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <sys/types.h>

            #include <errno.h>
            #include <limits.h>

            #define qatomic_set_mb(ptr, value) (*(ptr) = (value))
            #define qatomic_cmpxchg(ptr, old, value) \
                ((*(ptr) == (old)) ? (*(ptr) = (value), (old)) : *(ptr))
            #define qatomic_read(ptr) (*(ptr))
            #define qatomic_set(ptr, value) (*(ptr) = (value))
            #define qatomic_load_acquire(ptr) (*(ptr))
            #define qatomic_store_release(ptr, value) (*(ptr) = (value))
            #define g_assert(condition) do { if (!(condition)) __builtin_trap(); } while (0)

            #endif
            OSDEP_FIXTURE

            cat > qemu/main-loop.h <<'MAIN_LOOP_FIXTURE'
            #ifndef QEMU_MAIN_LOOP_H
            #define QEMU_MAIN_LOOP_H

            #include <stdbool.h>

            #ifndef CRUCIBLE_IOHANDLER_DEFINED
            typedef void IOHandler(void *opaque);
            #endif

            typedef struct AioContext AioContext;
            typedef bool AioPollFn(void *opaque);
            typedef void QEMUBHFunc(void *opaque);
            AioContext *qemu_get_aio_context(void);
            void aio_bh_schedule_oneshot(AioContext *ctx, QEMUBHFunc *cb,
                                         void *opaque);
            void aio_set_fd_handler(AioContext *ctx, int fd,
                                    IOHandler *fd_read, IOHandler *fd_write,
                                    AioPollFn *io_poll,
                                    IOHandler *io_poll_ready, void *opaque);

            #endif
            MAIN_LOOP_FIXTURE

            cat > qemu/accel.h <<'ACCEL_FIXTURE'
            #ifndef QEMU_ACCEL_H
            #define QEMU_ACCEL_H

            const char *current_accel_name(void);

            #endif
            ACCEL_FIXTURE

            cat > include/system/cpu-timers.h <<'CPU_TIMERS_FIXTURE'
            #ifndef SYSTEM_CPU_TIMERS_H
            #define SYSTEM_CPU_TIMERS_H

            #include <stdint.h>

            extern int use_icount;
            #define ICOUNT_DISABLED 0
            #define ICOUNT_PRECISE 1
            #define icount_enabled() (use_icount)

            typedef struct CPUState CPUState;
            void icount_update(CPUState *cpu);

            /* get raw icount value */
            int64_t icount_get_raw(void);

            /* return the virtual CPU time in ns, based on the instruction counter. */
            int64_t icount_get(void);
            /*
             * Remaining timer declarations are outside this focused fixture.
             */

            #endif
            CPU_TIMERS_FIXTURE

            cat > accel/tcg/icount-common.c <<'ICOUNT_COMMON_FIXTURE'
            struct TestTimersState {
                unsigned vm_clock_seqlock;
                int64_t qemu_icount;
            } timers_state;

            static unsigned seqlock_read_begin(unsigned *seqlock)
            {
                return *seqlock;
            }

            static bool seqlock_read_retry(unsigned *seqlock, unsigned start)
            {
                return *seqlock != start;
            }

            #define qatomic_read_i64(ptr) (*(ptr))

            static int64_t icount_get_executed(CPUState *cpu)
            {
                return cpu->icount_budget -
                    (cpu->neg.icount_decr.u16.low + cpu->icount_extra);
            }

            static int64_t icount_get_raw_locked(void)
            {
                raw_icount_reads++;
                return raw_icount;
            }

            int64_t icount_get_raw(void)
            {
                int64_t icount;
                unsigned start;

                do {
                    start = seqlock_read_begin(&timers_state.vm_clock_seqlock);
                    icount = icount_get_raw_locked();
                } while (seqlock_read_retry(&timers_state.vm_clock_seqlock, start));

                return icount;
            }

            /* Return the virtual CPU time, based on the instruction counter.  */
            int64_t icount_get(void)
            {
                return 0;
            }
            ICOUNT_COMMON_FIXTURE

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
             * typedef qemu_plugin_time_advance_cb_t - queued time-advance completion
             * @status: zero on success or a negative errno-style failure
             * @time: absolute QEMU_CLOCK_VIRTUAL time in nanoseconds
             * @userdata: opaque pointer supplied at registration
             */
            typedef void (*qemu_plugin_time_advance_cb_t)(int status, int64_t time,
                                                          void *userdata);

            QEMU_PLUGIN_API
            int qemu_plugin_register_time_advance_cb(qemu_plugin_time_advance_cb_t cb,
                                                     void *userdata);

            QEMU_PLUGIN_API
            int qemu_plugin_advance_time_ns(int64_t time);

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

            bool qemu_plugin_time_advance_is_pending(void);

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

            typedef struct CPUState CPUState;
            typedef struct Error Error;
            typedef struct NetClientState NetClientState;
            typedef struct run_on_cpu_data {
                long host_ulong;
            } run_on_cpu_data;

            #define RUN_ON_CPU_HOST_ULONG(value) \
                ((run_on_cpu_data){.host_ulong = (value)})
            extern CPUState *current_cpu;
            void async_run_on_cpu(CPUState *cpu,
                                  void (*fn)(CPUState *, run_on_cpu_data),
                                  run_on_cpu_data data);
            int64_t qemu_clock_advance_virtual_time(int64_t new_time);
            /*
             * Time control
             */
            static bool has_control;
            static qemu_plugin_time_advance_cb_t qemu_plugin_time_advance_cb;
            static void *qemu_plugin_time_advance_userdata;
            static int qemu_plugin_time_advance_pending;
            static int qemu_plugin_time_advance_status;
            static int64_t qemu_plugin_time_advance_target;

            static void qemu_plugin_time_advance_barrier_bh(void *opaque);
            static void qemu_plugin_time_advance_complete_bh(void *opaque);

            #define QEMU_PLUGIN_TIME_ADVANCE_RESERVED 1
            #define QEMU_PLUGIN_TIME_ADVANCE_ARMED 2

            bool qemu_plugin_has_time_control(void)
            {
                return has_control;
            }

            const void *qemu_plugin_request_time_control(void)
            {
                if (!has_control) {
                    has_control = true;
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

            int qemu_plugin_register_time_advance_cb(qemu_plugin_time_advance_cb_t cb,
                                                     void *userdata)
            {
                if (qemu_plugin_time_advance_pending) {
                    return -EBUSY;
                }
                qemu_plugin_time_advance_userdata = userdata;
                qemu_plugin_time_advance_cb = cb;
                return 0;
            }

            static void qemu_plugin_time_advance_barrier_bh(void *opaque)
            {
                (void)opaque;
                (void)qemu_plugin_time_advance_complete_bh;
            }

            static void qemu_plugin_time_advance_complete_bh(void *opaque)
            {
                (void)opaque;
                qemu_plugin_time_advance_pending = 0;
                if (qemu_plugin_time_advance_cb != NULL) {
                    qemu_plugin_time_advance_cb(qemu_plugin_time_advance_status,
                                                qemu_plugin_time_advance_target,
                                                qemu_plugin_time_advance_userdata);
                }
                /*
                 * Notify device waiters only after the logical-time commit.
                 */
                notifier_list_notify(&qemu_plugin_wake_notifiers,
                                     (void *)(intptr_t)QEMU_PLUGIN_WAKE_EVENT_DRAINED);
                if (first_cpu) {
                    qemu_cpu_kick(first_cpu);
                }
            }

            int qemu_plugin_advance_time_ns(int64_t new_time)
            {
                if (new_time < 0) {
                    return -EINVAL;
                }
                qemu_plugin_time_advance_pending = 1;
                qemu_plugin_time_advance_status = 0;
                qemu_plugin_time_advance_target = new_time;
                (void)qemu_plugin_time_advance_barrier_bh;
                return 0;
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
              qemu_plugin_icount_at_tb_entry \
              qemu_plugin_force_vcpu_exit \
              qemu_plugin_crucible_single_threaded_rr \
              qemu_plugin_register_wake_fd \
              qemu_plugin_request_shutdown \
              qemu_plugin_request_vmstop \
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
              if [ "$patch" = 0025-crucible-sim-idle-callbacks.patch ]; then
                # Preserve only the public/internal callback API and its
                # implementation. The RR-loop behavior has its own focused
                # microtest and requires the full QEMU scheduler fixture.
                gawk '
                  /^diff --git / {
                    selected_file = ($3 == "a/include/qemu/plugin.h" ||
                                     $3 == "a/plugins/api-system.c")
                  }
                  selected_file { print }
                ' "${patchDir}/$patch" > focused-idle-callbacks.patch
                patch --batch --fuzz=0 -p1 < focused-idle-callbacks.patch
              elif [ "$patch" = 0028-crucible-det-ipi.patch ]; then
                # Patch 0073 is based on the IPI callback globals and function
                # that follow the idle/resume API. Retain those exact preimage
                # contexts without pulling the APIC implementation into this
                # API-only fixture.
                gawk '
                  /^diff --git / {
                    internal_header = ($3 == "a/include/qemu/plugin.h")
                    api_system = ($3 == "a/plugins/api-system.c")
                    selected_file = internal_header || api_system
                    if (selected_file) print
                    next
                  }
                  !selected_file { next }
                  { print }
                ' "${patchDir}/$patch" > focused-det-ipi.patch
                patch --batch --fuzz=0 -p1 < focused-det-ipi.patch
              elif [ "$patch" = 0063-crucible-plugin-vmstop.patch ]; then
                # This focused fixture owns only the public declaration, stop
                # admission implementation, and post-TCG exact callback. The
                # full-source patch gate applies and compiles every RR, sim
                # dispatch, internal-header, and runstate hunk.
                gawk '
                  /^diff --git / {
                    public_header = ($3 == "a/include/qemu/qemu-plugin.h")
                    internal_header = ($3 == "a/include/qemu/plugin.h")
                    api_system = ($3 == "a/plugins/api-system.c")
                    selected_file = public_header || internal_header || api_system
                    in_hunk = 0
                    if (selected_file) print
                    next
                  }
                  !selected_file { next }
                  public_header || internal_header { print; next }
                  /^@@/ {
                    in_hunk = 1
                    selected_hunk = ($0 ~ /qemu_plugin_force_vcpu_exit/ ||
                                     $0 ~ /qemu_plugin_fire_tcg_exec_cb/ ||
                                     $0 ~ /qemu_plugin_fire_vcpu_idle_cb/ ||
                                     $0 ~ /qemu_plugin_fire_vcpu_resume_cb/)
                  }
                  !in_hunk || selected_hunk { print }
                ' "${patchDir}/$patch" > focused-vmstop.patch
                patch --batch --fuzz=0 -p1 < focused-vmstop.patch
              elif [ "$patch" = 0068-crucible-guest-clock-faults.patch ]; then
                # Patch 0068 splits public validation from the reusable VM-stop
                # admission helper. Patch 0073 builds on that boundary.
                gawk '
                  /^diff --git / {
                    selected_file = ($3 == "a/plugins/api-system.c")
                  }
                  selected_file { print }
                ' "${patchDir}/$patch" > focused-vmstop-admission.patch
                patch --batch --fuzz=0 -p1 < focused-vmstop-admission.patch
              elif [ "$patch" = 0073-crucible-device-wait-vmstop.patch ]; then
                # Device callback wrappers are compile-tested with their owning
                # device gates. This fixture compiles every public/internal API
                # hunk and the complete VM-stop/control-boundary implementation.
                gawk '
                  /^diff --git / {
                    internal_header = ($3 == "a/include/qemu/plugin.h")
                    api_system = ($3 == "a/plugins/api-system.c")
                    selected_file = internal_header || api_system
                    if (selected_file) print
                    next
                  }
                  !selected_file { next }
                  { print }
                ' "${patchDir}/$patch" > focused-device-wait-vmstop.patch
                patch --batch --fuzz=0 -p1 < focused-device-wait-vmstop.patch
              else
                patch --batch --fuzz=0 -p1 < "${patchDir}/$patch"
              fi
            done

            grep -q 'qemu_plugin_icount_raw' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_icount_at_tb_entry' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_force_vcpu_exit' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_crucible_single_threaded_rr' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_register_wake_fd' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_request_shutdown' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_request_vmstop' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_register_tcg_exec_cb' include/qemu/qemu-plugin.h
            grep -q 'qemu_plugin_maybe_fire_tcg_exec_cb(cpu);' accel/tcg/tcg-accel-ops-rr.c
            grep -q 'qemu_plugin_crucible_vmstop_pending()' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'qemu_plugin_crucible_vmstop_admission_pending()' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'qemu_plugin_crucible_vmstop_request_stopped' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'qemu_plugin_crucible_vmstop_flush_status()' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'rr_crucible_sim_park_vmstop()' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'rr_crucible_sim_drain_vcpu_work();' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'Could not flush devices while stopping the VM' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'VM stop admission has not reached paused state' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'VM stop failed to flush devices' "${patchDir}/0063-crucible-plugin-vmstop.patch"
            grep -q 'qemu_plugin_crucible_exact_boundary_depth == 0' plugins/api-system.c
            grep -q 'qemu_plugin_crucible_vmstop_begin' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'qemu_plugin_crucible_vmstop_at_control_boundary' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'qemu_plugin_crucible_control_boundary_depth' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'qemu_system_vmstop_request_prepare();' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'qemu_system_vmstop_request(RUN_STATE_PAUSED);' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'cpu_stop_current();' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'qemu_plugin_register_control_boundary_cb' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'qemu_plugin_fire_control_boundary_cb(first_cpu);' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q 'qatomic_load_acquire(&qemu_plugin_time_advance_pending)' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q '^diff --git a/block/crucible-shmem.c ' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q '^diff --git a/hw/9pfs/virtio-9p-device.c ' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            grep -q '^diff --git a/hw/virtio/virtio-crucible-accelerator.c ' "${patchDir}/0073-crucible-device-wait-vmstop.patch"
            test "$(grep -c '^+.*qemu_plugin_crucible_exact_boundary_enter();' "${patchDir}/0073-crucible-device-wait-vmstop.patch")" -eq 5
            test "$(grep -c '^+.*qemu_plugin_crucible_exact_boundary_leave();' "${patchDir}/0073-crucible-device-wait-vmstop.patch")" -eq 5
            awk '
              /icount_process_data\(cpu\);/ { saw_icount = NR }
              /qemu_plugin_maybe_fire_tcg_exec_cb\(cpu\);/ { saw_callback = NR }
              END { exit !(saw_icount && saw_callback && saw_icount < saw_callback) }
            ' accel/tcg/tcg-accel-ops-rr.c

            cp "$microtestSourcePath" phase1-plugin-runtime-apis.c
            cc -std=c11 -O2 -Wall -Wextra -Werror -DCONFIG_PLUGIN \
              -DCRUCIBLE_DEVICE_WAIT_VMSTOP \
              -I include \
              -I . \
              phase1-plugin-runtime-apis.c \
              -o phase1-plugin-runtime-apis

            mkdir -p "$out"
            ./phase1-plugin-runtime-apis > "$out/plugin-runtime-apis-microtest"
            grep -q '^PASS$' "$out/plugin-runtime-apis-microtest"
            grep -q '^raw_icount_bias_independent=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^raw_icount_disabled_returns_zero=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^tb_entry_icount_nonmutating=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^tb_entry_icount_chained_early_exit_multi_vcpu=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^first_exit_phase_normalized=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^single_threaded_rr_mode_discriminator_fixture_exercised=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^request_vmstop_native_pause_admission=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^request_vmstop_rejects_nonexact_modes=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^request_vmstop_rejects_unsafe_callback_context=true$' "$out/plugin-runtime-apis-microtest"
            ${lib.optionalString (patchName == "0073-crucible-device-wait-vmstop.patch") ''
              grep -q '^request_vmstop_accepts_nonvcpu_exact_callback=true$' "$out/plugin-runtime-apis-microtest"
              grep -q '^request_vmstop_control_boundary_synchronous=true$' "$out/plugin-runtime-apis-microtest"
            ''}
            grep -q '^request_vmstop_rejects_duplicate_admission=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^request_vmstop_preserves_async_flush_failure=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_registered=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_single_owner=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_same_descriptor_idempotent=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^plugin_shutdown_clean_exit_cause=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^plugin_shutdown_fail_loud_cause=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_drained=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_requires_nonblocking=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_eintr_retried=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_short_reads_drained_to_eagain=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_kicks_first_vcpu_only_after_drain=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_spurious_eagain_does_not_kick=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_failure_kicks_vcpu_for_shutdown=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_notifies_devices_after_drain=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_failure_requests_host_error_shutdown=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_eof_reported_and_unregistered=true$' "$out/plugin-runtime-apis-microtest"
            grep -q '^wake_fd_hard_error_reported_and_unregistered=true$' "$out/plugin-runtime-apis-microtest"
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
            tb_entry_icount_symbol=qemu_plugin_icount_at_tb_entry
            tb_entry_icount_nonmutating=true
            tb_entry_icount_chained_early_exit_multi_vcpu=true
            force_vcpu_exit_symbol=qemu_plugin_force_vcpu_exit
            first_exit_phase_normalized=true
            single_threaded_rr_symbol=qemu_plugin_crucible_single_threaded_rr
            single_threaded_rr_mode_discriminator_fixture_exercised=true
            request_vmstop_symbol=qemu_plugin_request_vmstop
            request_vmstop_native_pause_admission=true
            request_vmstop_rejects_nonexact_modes=true
            request_vmstop_rejects_unsafe_callback_context=true
            ${lib.optionalString (patchName == "0073-crucible-device-wait-vmstop.patch") "request_vmstop_accepts_nonvcpu_exact_callback=true"}
            ${lib.optionalString (patchName == "0073-crucible-device-wait-vmstop.patch") "request_vmstop_control_boundary_synchronous=true"}
            request_vmstop_rejects_duplicate_admission=true
            request_vmstop_preserves_async_flush_failure=true
            wake_fd_registration_symbol=qemu_plugin_register_wake_fd
            wake_fd_registered=true
            wake_fd_single_owner=true
            wake_fd_same_descriptor_idempotent=true
            wake_fd_drained=true
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
