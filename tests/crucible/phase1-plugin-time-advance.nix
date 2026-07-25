{
  pkgs,
  lib,
  qemuPackage ? null,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0010-crucible-plugin-time-advance.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-plugin-time-advance.c;
  defaultChecks = builtins.readFile ./default.nix;
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

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "plugin time advance patch wiring";
        needle = "patch -p1 < \${./qemu-patches/0010-crucible-plugin-time-advance.patch}";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "public time-control predicate";
        needle = "qemu_plugin_has_time_control";
      }
      {
        label = "callback-safe advance export";
        needle = "qemu_plugin_advance_time_ns";
      }
      {
        label = "completion callback registration";
        needle = "qemu_plugin_register_time_advance_cb";
      }
      {
        label = "exclusive pending guard";
        needle = "qatomic_cmpxchg(&qemu_plugin_time_advance_pending, 0, 1)";
      }
      {
        label = "main-loop bottom-half handoff";
        needle = "aio_bh_schedule_oneshot(qemu_get_aio_context(),";
      }
      {
        # The queued advance MUST use the icount-aware primitive, not the
        # qtest-only qemu_clock_advance_virtual_time: under -accel sim the virtual
        # clock is icount-derived and cpus_set_virtual_clock is unset, so that
        # helper's while (clock < dest) loop never terminates and spins the vCPU
        # thread holding the BQL. icount_advance_virtual_time_to_ns advances by the
        # icount bias instead.
        label = "queued icount virtual-time advance";
        needle = "icount_advance_virtual_time_to_ns(new_time)";
      }
      {
        label = "icount virtual-time advance helper";
        needle = "void icount_advance_virtual_time_to_ns(int64_t dest)";
      }
      {
        label = "advance moves the icount bias to the target";
        needle = "timers_state.qemu_icount_bias + (dest - now)";
      }
      {
        label = "inline virtual timer run";
        needle = "qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)";
      }
      {
        label = "normal main-loop completion handoff";
        needle = "aio_bh_schedule_oneshot(qemu_get_aio_context()";
      }
      {
        label = "two-stage BH ordering barrier";
        needle = "qemu_plugin_time_advance_barrier_bh";
      }
      {
        label = "completion clears pending before callback";
        needle = "qatomic_store_release(&qemu_plugin_time_advance_pending, 0)";
      }
      {
        label = "RR-loop pending predicate";
        needle = "qemu_plugin_time_advance_is_pending";
      }
    ]
    ++ lib.optionals (hasInfix "main_loop_wait(true" patchSource
      || hasInfix "main_loop_wait(false" patchSource) [
      "pkgs/emulation/qemu-patches/${patchName}: callback path re-enters main_loop_wait"
    ]
    ++ lib.optionals (hasInfix "aio_poll(aio_context" patchSource
      || hasInfix "aio_poll(qemu_get_aio_context" patchSource) [
      "pkgs/emulation/qemu-patches/${patchName}: callback path re-enters aio_poll"
    ]
    ++ lib.optionals (hasInfix "aio_bh_poll(aio_context" patchSource
      || hasInfix "aio_bh_poll(qemu_get_aio_context" patchSource) [
      "pkgs/emulation/qemu-patches/${patchName}: callback path re-enters aio_bh_poll"
    ]
    ++ lib.optionals (hasInfix "qemu_clock_advance_virtual_time(new_time)" patchSource) [
      # Regression guard: the qtest-only qemu_clock_advance_virtual_time spins
      # forever under -accel sim icount (set_virtual_clock is unset, so the clock
      # never moves and the while (clock < dest) loop never terminates). The
      # queued advance MUST go through icount_advance_virtual_time_to_ns instead.
      # (An explanatory reference to the bare qemu_clock_advance_virtual_time() in
      # a comment is fine; only the queued-advance call site is forbidden.)
      "pkgs/emulation/qemu-patches/${patchName}: queued advance uses the icount-incompatible qemu_clock_advance_virtual_time"
    ]
    ++ failuresFor "tests/crucible/phase1-plugin-time-advance.c" microtestSource [
      {
        label = "patched fixture include";
        needle = "#include \"plugins/api-system.c\"";
      }
      {
        label = "enqueue-only advance exercised";
        needle = "qemu_plugin_advance_time_ns(5000)";
      }
      {
        label = "normal completion BH exercised";
        needle = "run_normal_main_loop_bottom_halves()";
      }
      {
        label = "icount bias-advance models the sim virtual clock";
        needle = "icount_advance_virtual_time_to_ns(dest)";
      }
      {
        label = "differential vs the qtest set-based advance under icount";
        needle = "test_icount_bias_advance_converges_where_qtest_set_would_hang";
      }
      {
        label = "exclusive owner assertion";
        needle = "single_time_control_owner=true";
      }
      {
        label = "timer BH ordering assertion";
        needle = "timer_bh_precedes_plugin_completion=true";
      }
      {
        label = "enqueue-only assertion";
        needle = "callback_entry_is_enqueue_only=true";
      }
      {
        label = "overlap rejection assertion";
        needle = "overlapping_advance_rejected=true";
      }
      {
        label = "pending registration guard assertion";
        needle = "callback_reconfiguration_while_pending_rejected=true";
      }
      {
        label = "pending lifetime assertion";
        needle = "pending_predicate_tracks_completion_barrier=true";
      }
      {
        label = "negative target assertion";
        needle = "negative_target_rejected_before_queue=true";
      }
      {
        label = "backward target completion assertion";
        needle = "backward_target_reports_completion_failure=true";
      }
      {
        label = "queued timer dispatch assertion";
        needle = "queued_main_loop_worker_runs_virtual_timers=true";
      }
      {
        label = "main-loop BH handoff assertion";
        needle = "completion_uses_normal_main_loop_bh=true";
      }
      {
        label = "main-loop reentry negative assertion";
        needle = "callback_path_main_loop_reentry_absent=true";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes plugin time advance check";
        needle = "pluginTimeAdvance = import ./phase1-plugin-time-advance.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 plugin time-advance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-plugin-time-advance";
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
          name = "run-plugin-time-advance-microtest";
          script = ''
            set -eu

            mkdir -p hw include/qemu migration net plugins qapi qemu
            : > hw/boards.h
            : > migration/blocker.h
            : > net/net.h
            : > qapi/error.h
            : > qemu/main-loop.h
            : > qemu/osdep.h
            : > qemu/plugin-memory.h
            : > qemu/plugin.h
            : > qemu/timer.h

            : > include/qemu/plugin.h
            line=1
            while [ "$line" -lt 174 ]; do
              printf '\n' >> include/qemu/plugin.h
              line=$((line + 1))
            done
            cat >> include/qemu/plugin.h <<'PLUGIN_INTERNAL_HEADER_FIXTURE'
            void qemu_plugin_flush_cb(void);

            void qemu_plugin_atexit_cb(void);

            bool qemu_plugin_has_time_control(void);

            void qemu_plugin_add_dyn_cb_arr(GArray *arr);

            static inline void qemu_plugin_disable_mem_helpers(CPUState *cpu)
            {
              (void)cpu;
            }
            PLUGIN_INTERNAL_HEADER_FIXTURE

            cat > include/qemu/qemu-plugin.h <<'PLUGIN_HEADER_FIXTURE'
            #ifndef QEMU_QEMU_PLUGIN_H
            #define QEMU_QEMU_PLUGIN_H

            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>

            #define QEMU_PLUGIN_API

            typedef uint64_t qemu_plugin_id_t;

            QEMU_PLUGIN_API
            const void *qemu_plugin_request_time_control(void);

            /**
             * qemu_plugin_update_ns() - update system emulation time
             * @handle: opaque handle returned by qemu_plugin_request_time_control()
             * @time: time in nanoseconds
             */
            QEMU_PLUGIN_API
            void qemu_plugin_update_ns(const void *handle, int64_t time);

            /**
             * qemu_plugin_net_inject() - inject an inbound frame into the default NIC
             * @data: Ethernet frame bytes
             * @len: byte length of @data
             */
            QEMU_PLUGIN_API
            int qemu_plugin_net_inject(const uint8_t *data, size_t len);

            /**
             * qemu_plugin_net_send() - queue an inbound frame for the default NIC
             */
            QEMU_PLUGIN_API
            int qemu_plugin_net_send(const uint8_t *data, size_t len);

            /**
             * qemu_plugin_net_flush() - flush queued inbound frames for the default NIC
             */
            QEMU_PLUGIN_API
            int qemu_plugin_net_flush(void);

            /**
             * qemu_plugin_net_can_receive() - report whether the default NIC can receive
             */
            QEMU_PLUGIN_API
            int qemu_plugin_net_can_receive(void);

            typedef void
            (*qemu_plugin_vcpu_syscall_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                                             int64_t num, uint64_t a1, uint64_t a2,
                                             uint64_t a3, uint64_t a4, uint64_t a5,
                                             uint64_t a6, uint64_t a7, uint64_t a8);

            #endif /* QEMU_QEMU_PLUGIN_H */
            PLUGIN_HEADER_FIXTURE

            cat > plugins/api-system.c <<'PLUGIN_API_FIXTURE'
            /*
             * QEMU Plugin API - System specific implementations
             */

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
             * helpers all return NULL/0.
             */
            const char *qemu_plugin_path_to_binary(void)
            {
                return NULL;
            }

            uint64_t qemu_plugin_start_code(void)
            {
                return 0;
            }

            uint64_t qemu_plugin_end_code(void)
            {
                return 0;
            }

            uint64_t qemu_plugin_entry_code(void)
            {
                return 0;
            }

            /*
             * Time control
             */
            static bool has_control;

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


            static NetClientState *qemu_plugin_default_nic_queue(void)
            {
                NetClientState *nc;

                QTAILQ_FOREACH(nc, &net_clients, next) {
                    if (nc->info->type == NET_CLIENT_DRIVER_NIC && nc->queue_index == 0) {
                        return nc;
                    }
                }

                return NULL;
            }

            static bool qemu_plugin_valid_net_payload(const uint8_t *data, size_t len)
            {
                return data != NULL && len > 0 && len <= INT_MAX;
            }

            static void qemu_plugin_net_sent_cb(NetClientState *sender, ssize_t ret)
            {
                (void)sender;
                (void)ret;
            }

            int qemu_plugin_net_inject(const uint8_t *data, size_t len)
            {
                NetClientState *nc;
                ssize_t delivered;

                if (!qemu_plugin_valid_net_payload(data, len)) {
                    return -1;
                }

                nc = qemu_plugin_default_nic_queue();
                if (nc == NULL || nc->link_down) {
                    return -1;
                }

                delivered = qemu_receive_packet(nc, data, (int)len);
                return delivered == (ssize_t)len ? 0 : -1;
            }

            int qemu_plugin_net_send(const uint8_t *data, size_t len)
            {
                NetClientState *nc;
                NetClientState *sender;

                if (!qemu_plugin_valid_net_payload(data, len)) {
                    return -1;
                }

                nc = qemu_plugin_default_nic_queue();
                if (nc == NULL || nc->peer == NULL || nc->incoming_queue == NULL) {
                    return -1;
                }

                sender = nc->peer;
                if (nc->link_down || sender->link_down) {
                    return -1;
                }

                return qemu_net_queue_append_lossless(nc->incoming_queue, sender,
                                                      QEMU_NET_PACKET_FLAG_NONE,
                                                      data, len,
                                                      qemu_plugin_net_sent_cb) ? 0 : -1;
            }

            int qemu_plugin_net_flush(void)
            {
                NetClientState *nc = qemu_plugin_default_nic_queue();
                NetClientState *sender;

                if (nc == NULL || nc->peer == NULL || nc->incoming_queue == NULL) {
                    return -1;
                }

                sender = nc->peer;
                if (nc->link_down || sender->link_down) {
                    return -1;
                }

                nc->receive_disabled = 0;
                if (!qemu_can_receive_packet(nc)) {
                    return -1;
                }

                if (!qemu_net_queue_flush(nc->incoming_queue)) {
                    return -1;
                }

                qemu_notify_event();
                return 0;
            }

            int qemu_plugin_net_can_receive(void)
            {
                NetClientState *nc = qemu_plugin_default_nic_queue();

                if (nc == NULL) {
                    return -1;
                }
                if (nc->link_down) {
                    return 0;
                }
                return qemu_can_receive_packet(nc);
            }

            int64_t qemu_plugin_clock_deadline_ns(void)
            {
                int64_t delta = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,
                                                          QEMU_TIMER_ATTR_ALL);

                if (delta < 0) {
                    return -1;
                }
                return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + delta;
            }
            PLUGIN_API_FIXTURE

            mkdir -p accel/tcg include/system
            # Fixture for the file 0010 now extends with the icount-aware advance
            # primitive's declaration. The context lines match the real header so
            # the patch hunk applies at --fuzz=0.
            cat > include/system/cpu-timers.h <<'CPU_TIMERS_FIXTURE'
            #ifndef SYSTEM_CPU_TIMERS_H
            #define SYSTEM_CPU_TIMERS_H

            #include <stdint.h>

            int64_t icount_get(void);
            int64_t icount_to_ns(int64_t icount);

            void icount_start_warp_timer(void);
            void icount_account_warp_timer(void);
            void icount_notify_exit(void);

            /*
             * CPU Ticks and Clock
             */

            #endif /* SYSTEM_CPU_TIMERS_H */
            CPU_TIMERS_FIXTURE

            # Fixture for the file 0010 now extends with icount_advance_virtual_time_to_ns.
            # icount_get models the icount-derived virtual clock (bias + retired), so
            # the patched helper's bias bump makes icount_get() reach the target while
            # the qtest set-based path (modeled in the C test) would never converge.
            # The context around the insertion point matches the real source so the
            # patch hunk applies at --fuzz=0.
            # The C test #includes this file after defining its icount model
            # (timers_state, crucible_fixture_retired_icount, qatomic_read) and
            # before #including the patched api-system.c, so the helper the patch
            # inserts here is defined before api-system.c calls it.
            cat > accel/tcg/icount-common.c <<'ICOUNT_COMMON_FIXTURE'
            int64_t icount_get(void)
            {
                int64_t icount = timers_state.qemu_icount_bias
                    + (crucible_fixture_retired_icount()
                       << qatomic_read(&timers_state.icount_time_shift));
                return icount;
            }

            int64_t icount_to_ns(int64_t icount)
            {
                return icount << qatomic_read(&timers_state.icount_time_shift);
            }
            ICOUNT_COMMON_FIXTURE

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            ! grep -Eq 'main_loop_wait[[:space:]]*\(|aio_poll[[:space:]]*\(|aio_bh_poll[[:space:]]*\(' plugins/api-system.c
            cp "$microtestSourcePath" phase1-plugin-time-advance.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -I. -Iinclude \
              phase1-plugin-time-advance.c \
              -o phase1-plugin-time-advance

            mkdir -p "$out"
            ./phase1-plugin-time-advance > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^patched_qemu_plugin_time_advance_fixture=true$' "$out/result"
            grep -q '^time_control_predicate_symbol=qemu_plugin_has_time_control$' "$out/result"
            grep -q '^advance_symbol=qemu_plugin_advance_time_ns$' "$out/result"
            grep -q '^completion_symbol=qemu_plugin_register_time_advance_cb$' "$out/result"
            grep -q '^single_time_control_owner=true$' "$out/result"
            grep -q '^callback_entry_is_enqueue_only=true$' "$out/result"
            grep -q '^overlapping_advance_rejected=true$' "$out/result"
            grep -q '^callback_reconfiguration_while_pending_rejected=true$' "$out/result"
            grep -q '^pending_predicate_tracks_completion_barrier=true$' "$out/result"
            grep -q '^negative_target_rejected_before_queue=true$' "$out/result"
            grep -q '^backward_target_reports_completion_failure=true$' "$out/result"
            grep -q '^queued_main_loop_worker_runs_virtual_timers=true$' "$out/result"
            grep -q '^icount_bias_advance_converges_where_qtest_set_hangs=true$' "$out/result"
            grep -q '^completion_uses_normal_main_loop_bh=true$' "$out/result"
            grep -q '^completion_uses_two_stage_bh_barrier=true$' "$out/result"
            grep -q '^timer_bh_precedes_plugin_completion=true$' "$out/result"
            grep -q '^completion_kicks_first_vcpu=true$' "$out/result"
            grep -q '^callback_path_main_loop_reentry_absent=true$' "$out/result"

            cp "$patchSourcePath" "$out/${patchName}"
            cp include/qemu/qemu-plugin.h "$out/qemu-plugin.h.patched"
            cp plugins/api-system.c "$out/api-system.c.patched"
            cat >> "$out/result" <<'RESULT'
            check=checks.crucible.phase1.pluginTimeAdvance
            gate=gate:patch-microtests
            gate.layer0=gate:layer0-determinism
            gate.layer1=gate:layer1-injection
            gate.divergence=gate:divergence-bisect
            tasks=T-PATCH-9
            patch=0010-crucible-plugin-time-advance.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            stock_negative_control_mode=callback-return-before-queued-work
            ${qemuPackageResultLines}
            qemu_time_control_public_predicate=true
            qemu_time_control_single_owner=true
            qemu_time_advance_callback_enqueue_only=true
            qemu_time_advance_main_loop_handoff=true
            qemu_time_advance_runs_virtual_timers=true
            qemu_time_advance_completion_bh=true
            qemu_time_advance_two_stage_bh_barrier=true
            qemu_time_advance_overlap_rejected=true
            qemu_time_advance_pending_lifetime_observed=true
            qemu_time_advance_backward_failure_reported=true
            qemu_main_loop_reentry_from_callback=false
            aio_poll_from_callback=false
            aio_bh_poll_from_callback=false
            RESULT
          '';
        }
      ];
    }
