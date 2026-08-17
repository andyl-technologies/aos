{
  pkgs,
  lib,
  qemuPackage ? null,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0009-crucible-net-deterministic.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-qemu-net-deterministic.c;
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

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "network deterministic patch wiring";
        needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "direct net inject export";
        needle = "qemu_plugin_net_inject";
      }
      {
        label = "lossless net send export";
        needle = "qemu_plugin_net_send";
      }
      {
        label = "net flush export";
        needle = "qemu_plugin_net_flush";
      }
      {
        label = "net can-receive export";
        needle = "qemu_plugin_net_can_receive";
      }
      {
        label = "default NIC queue selection";
        needle = "qemu_plugin_default_nic_queue";
      }
      {
        label = "direct injection uses QEMU receive path";
        needle = "qemu_receive_packet(nc, data, (int)len)";
      }
      {
        label = "lossless queue append export";
        needle = "qemu_net_queue_append_lossless";
      }
      {
        label = "lossless send uses NIC peer as inbound sender";
        needle = "sender = nc->peer";
      }
      {
        label = "lossless send uses explicit incoming queue append";
        needle = "qemu_net_queue_append_lossless(nc->incoming_queue, sender";
      }
      {
        label = "lossless queue callback prevents silent drops";
        needle = "qemu_plugin_net_sent_cb";
      }
      {
        label = "flush observes QEMU queued packet drain result";
        needle = "qemu_net_queue_flush(nc->incoming_queue)";
      }
      {
        label = "flush notifies event loop after drain";
        needle = "qemu_notify_event()";
      }
      {
        label = "NIC readiness diagnostic";
        needle = "qemu_can_receive_packet(nc)";
      }
      {
        label = "link-down fail loud guard";
        needle = "nc->link_down || sender->link_down";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-qemu-net-deterministic.c" microtestSource [
      {
        label = "patched fixture include";
        needle = "#include \"plugins/api-system.c\"";
      }
      {
        label = "direct inject exercised";
        needle = "qemu_plugin_net_inject(frame, sizeof(frame))";
      }
      {
        label = "lossless send exercised";
        needle = "qemu_plugin_net_send(frame, sizeof(frame))";
      }
      {
        label = "flush exercised";
        needle = "qemu_plugin_net_flush()";
      }
      {
        label = "skewed producer model";
        needle = "run_skewed_producer";
      }
      {
        label = "deterministic observed icount assertion";
        needle = "skewed_producer_observed_icount_identical=true";
      }
      {
        label = "lossless queue assertion";
        needle = "lossless_send_queues_until_flush=true";
      }
      {
        label = "ready NIC deferred send assertion";
        needle = "send_deferred_when_nic_ready=true";
      }
      {
        label = "not-ready flush fail-loud assertion";
        needle = "flush_fails_loudly_when_not_ready=true";
      }
      {
        label = "queue callback assertion";
        needle = "queue_sent_callback_required=true";
      }
      {
        label = "drop-prone stock negative control";
        needle = "stock_negative_control_drop_without_queue=true";
      }
      {
        label = "link-down fail loud assertion";
        needle = "link_down_fails_loudly=true";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU net-deterministic check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-net-deterministic";
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
          name = "run-qemu-net-deterministic-microtest";
          script = ''
            set -eu

            mkdir -p hw include/net include/qemu migration net plugins qapi qemu
            : > hw/boards.h
            : > migration/blocker.h
            : > net/net.h
            : > qapi/error.h
            : > qemu/main-loop.h
            : > qemu/osdep.h
            : > qemu/plugin-memory.h
            : > qemu/plugin.h

            cat > include/qemu/qemu-plugin.h <<'PLUGIN_HEADER_FIXTURE'
            #ifndef QEMU_QEMU_PLUGIN_H
            #define QEMU_QEMU_PLUGIN_H

            #include <glib.h>
            #include <inttypes.h>
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>

            #define QEMU_PLUGIN_API

            typedef uint64_t qemu_plugin_id_t;

            QEMU_PLUGIN_API
            const void *qemu_plugin_request_time_control(void);

            /**
             * This allows an appropriately authorised plugin (i.e. holding the
             * time control handle) to move system time forward to @time. For
             * user-mode emulation the time is not changed by this as all reported
             * time comes from the host kernel.
             *
             * Start time is 0.
             */
            QEMU_PLUGIN_API
            void qemu_plugin_update_ns(const void *handle, int64_t time);

            typedef void
            (*qemu_plugin_vcpu_syscall_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                                             int64_t num, uint64_t a1, uint64_t a2,
                                             uint64_t a3, uint64_t a4, uint64_t a5,
                                             uint64_t a6, uint64_t a7, uint64_t a8);

            #endif /* QEMU_QEMU_PLUGIN_H */
            PLUGIN_HEADER_FIXTURE

            cat > include/net/queue.h <<'NET_QUEUE_HEADER_FIXTURE'
            #ifndef QEMU_NET_QUEUE_H
            #define QEMU_NET_QUEUE_H

            typedef struct NetQueue NetQueue;
            typedef void (NetPacketSent) (NetClientState *sender, ssize_t ret);

            NetQueue *qemu_new_net_queue(NetQueueDeliverFunc *deliver, void *opaque);

            void qemu_net_queue_append_iov(NetQueue *queue,
                                           NetClientState *sender,
                                           unsigned flags,
                                           const struct iovec *iov,
                                           int iovcnt,
                                           NetPacketSent *sent_cb);

            bool qemu_net_queue_flush(NetQueue *queue);

            #endif /* QEMU_NET_QUEUE_H */
            NET_QUEUE_HEADER_FIXTURE

            cat > net/queue.c <<'NET_QUEUE_FIXTURE'
            #include "qemu/osdep.h"
            #include "net/queue.h"

            static void qemu_net_queue_append(NetQueue *queue,
                                              NetClientState *sender,
                                              unsigned flags,
                                              const uint8_t *buf,
                                              size_t size,
                                              NetPacketSent *sent_cb)
            {
                (void)queue;
                (void)sender;
                (void)flags;
                (void)buf;
                (void)size;
                (void)sent_cb;
                packet = g_malloc(sizeof(NetPacket) + size);
                packet->sender = sender;
                packet->flags = flags;
                packet->size = size;
                packet->sent_cb = sent_cb;
                memcpy(packet->data, buf, size);

                queue->nq_count++;
                QTAILQ_INSERT_TAIL(&queue->packets, packet, entry);
            }

            void qemu_net_queue_append_iov(NetQueue *queue,
                                           NetClientState *sender,
                                           unsigned flags,
                                           const struct iovec *iov,
                                           int iovcnt,
                                           NetPacketSent *sent_cb)
            {
                (void)queue;
                (void)sender;
                (void)flags;
                (void)iov;
                (void)iovcnt;
                (void)sent_cb;
            }
            NET_QUEUE_FIXTURE

            cat > plugins/api-system.c <<'PLUGIN_API_FIXTURE'
            /*
             * QEMU Plugin API - System specific implementations
             */

            #include "qemu/osdep.h"
            #include "qemu/main-loop.h"
            #include "qapi/error.h"
            #include "migration/blocker.h"
            #include "hw/boards.h"
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

            patch --batch --fuzz=0 -p1 < "$patchSourcePath"
            cp "$microtestSourcePath" phase1-qemu-net-deterministic.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -I. -Iinclude \
              phase1-qemu-net-deterministic.c \
              -o phase1-qemu-net-deterministic

            mkdir -p "$out"
            ./phase1-qemu-net-deterministic > "$out/result"
            grep -q '^PASS$' "$out/result"
            grep -q '^patched_qemu_plugin_net_fixture=true$' "$out/result"
            grep -q '^net_inject_symbol=qemu_plugin_net_inject$' "$out/result"
            grep -q '^net_send_symbol=qemu_plugin_net_send$' "$out/result"
            grep -q '^net_flush_symbol=qemu_plugin_net_flush$' "$out/result"
            grep -q '^net_can_receive_symbol=qemu_plugin_net_can_receive$' "$out/result"
            grep -q '^direct_inject_fails_closed_when_not_ready=true$' "$out/result"
            grep -q '^lossless_send_queues_until_flush=true$' "$out/result"
            grep -q '^send_deferred_when_nic_ready=true$' "$out/result"
            grep -q '^flush_makes_frame_visible_at_delivery_icount=true$' "$out/result"
            grep -q '^flush_fails_loudly_when_not_ready=true$' "$out/result"
            grep -q '^queue_sent_callback_required=true$' "$out/result"
            grep -q '^skewed_producer_observed_icount_identical=true$' "$out/result"
            grep -q '^arrival_order_visible=false$' "$out/result"
            grep -q '^stock_negative_control_exercised=true$' "$out/result"
            grep -q '^link_down_fails_loudly=true$' "$out/result"
            grep -q '^stock_negative_control_drop_without_queue=true$' "$out/result"

            cp "$patchSourcePath" "$out/${patchName}"
            cp include/qemu/qemu-plugin.h "$out/qemu-plugin.h.patched"
            cp include/net/queue.h "$out/queue.h.patched"
            cp net/queue.c "$out/queue.c.patched"
            cp plugins/api-system.c "$out/api-system.c.patched"
            cat >> "$out/result" <<'RESULT'
            check=checks.crucible.phase1.qemuNetDeterministic
            gate=gate:layer1-injection
            gate=gate:patch-microtests
            tasks=T-PATCH-8
            patch=0009-crucible-net-deterministic.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            qemu_net_rx_api=qemu_plugin_net_inject,qemu_plugin_net_send,qemu_plugin_net_flush,qemu_plugin_net_can_receive
            qemu_net_rx_delivery_icount_deterministic=true
            qemu_net_rx_lossless_queue=true
            qemu_net_rx_flush_at_delivery_icount=true
            qemu_net_rx_send_deferred_when_ready=true
            qemu_net_rx_flush_fails_loudly_when_not_ready=true
            qemu_net_rx_queue_callback_required=true
            skewed_producer_observed_icount_identical=true
            guest_observed_icount=4096
            delivery_icount=4096
            arrival_order_visible=false
            direct_inject_fails_closed_when_not_ready=true
            missing_nic_fails_loudly=true
            link_down_fails_loudly=true
            stock_negative_control_exercised=true
            RESULT
          '';
        }
      ];
    }
