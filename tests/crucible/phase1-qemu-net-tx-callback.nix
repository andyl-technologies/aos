{
  pkgs,
  lib,
  patchName ? "0020-crucible-net-tx-callback.patch",
  qemuPackage ? null,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-qemu-net-tx-callback.c;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginNetworkTx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_tx.rs;
  pluginNetworkRx = builtins.readFile ../../crates/crucible-qemu-plugin/src/network_rx.rs;
  defaultChecks = builtins.readFile ./default.nix;
  qemuNetDeterministic = import ./phase1-qemu-net-deterministic.nix {
    inherit pkgs lib qemuPackage;
  };
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
  taskIds = ["T-PATCH-14"];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "QEMU net TX callback patch wiring";
        needle = "patch -p1 < \${./qemu-patches/0020-crucible-net-tx-callback.patch}";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "network TX callback registration symbol";
        needle = "qemu_plugin_register_net_tx_cb";
      }
      {
        label = "network TX callback type";
        needle = "qemu_plugin_net_tx_cb_t";
      }
      {
        label = "network TX callback readiness guard";
        needle = "crucible_net_tx_callback_ready";
      }
      {
        label = "guest NIC sender guard";
        needle = "sender->info->type == NET_CLIENT_DRIVER_NIC";
      }
      {
        label = "flat packet TX intercept";
        needle = "qemu_send_packet_async_with_flags";
      }
      {
        label = "iov packet TX intercept";
        needle = "qemu_sendv_packet_async";
      }
      {
        label = "iov coalescing";
        needle = "iov_to_buf(iov, iovcnt, 0, buf, size)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-qemu-net-tx-callback.c" microtestSource [
      {
        label = "patched net include";
        needle = "#include \"net/net.c\"";
      }
      {
        label = "upstream fallback evidence";
        needle = "net_tx_callback_upstream_fallback=true";
      }
      {
        label = "flat intercept evidence";
        needle = "net_tx_callback_intercepts_flat_frame=true";
      }
      {
        label = "iov intercept evidence";
        needle = "net_tx_callback_intercepts_iov_frame=true";
      }
      {
        label = "backend bypass evidence";
        needle = "net_tx_callback_bypasses_backend_when_registered=true";
      }
      {
        label = "guest-only callback evidence";
        needle = "net_tx_callback_guest_only=true";
      }
      {
        label = "oversized iov loud failure evidence";
        needle = "net_tx_oversized_iov_fails_loudly=true";
      }
      {
        label = "failure evidence";
        needle = "net_tx_callback_failure_fails_loudly=true";
      }
      {
        label = "stock negative evidence";
        needle = "stock_negative_control_net_tx_symbol_absent=true";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "network TX register resolver exported";
        needle = "resolve_qemu_register_net_tx_cb_symbol";
      }
      {
        label = "network RX send resolver exported";
        needle = "resolve_qemu_net_send_symbol";
      }
      {
        label = "network RX flush resolver exported";
        needle = "resolve_qemu_net_flush_symbol";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_tx.rs" pluginNetworkTx [
      {
        label = "network TX register symbol";
        needle = "QEMU_PLUGIN_REGISTER_NET_TX_CB_SYMBOL";
      }
      {
        label = "network TX callback type";
        needle = "pub type QemuNetTxCbFn";
      }
      {
        label = "network TX register resolver";
        needle = "pub fn resolve_qemu_register_net_tx_cb_symbol";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/network_rx.rs" pluginNetworkRx [
      {
        label = "network RX send resolver";
        needle = "pub fn resolve_qemu_net_send_symbol";
      }
      {
        label = "network RX flush resolver";
        needle = "pub fn resolve_qemu_net_flush_symbol";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "T-PATCH-14 checklist complete";
        needle = "- [x] **T-PATCH-14**";
      }
      {
        label = "network TX patch catalog";
        needle = "crucible-net-tx-callback";
      }
      {
        label = "network flush API catalog";
        needle = "crucible-net-flush-api";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes QEMU net TX callback check";
        needle = "qemuNetTxCallback = import ./phase1-qemu-net-tx-callback.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU net-TX callback check failed for ${patchName}:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-net-tx-callback-${lib.removeSuffix ".patch" patchName}";
      version = "0";
      src = null;

      inherit microtestSource;
      passAsFile = ["microtestSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
      ];

      phases = [
        {
          name = "run-qemu-net-tx-callback-microtest";
          script = ''
            set -eu

            mkdir -p include/qemu include/net net qemu hw

            cat > include/qemu/qemu-plugin.h <<'PLUGIN_HEADER_FIXTURE'
            #ifndef QEMU_QEMU_PLUGIN_H
            #define QEMU_QEMU_PLUGIN_H

            #include <inttypes.h>
            #include <stddef.h>
            #include <stdint.h>

            #define QEMU_PLUGIN_API

            typedef uint64_t qemu_plugin_id_t;

            QEMU_PLUGIN_API
            int qemu_plugin_net_inject(const uint8_t *data, size_t len);
            QEMU_PLUGIN_API
            int qemu_plugin_net_send(const uint8_t *data, size_t len);
            QEMU_PLUGIN_API
            int qemu_plugin_net_flush(void);
            QEMU_PLUGIN_API
            int qemu_plugin_net_can_receive(void);

            typedef void
            (*qemu_plugin_vcpu_syscall_cb_t)(qemu_plugin_id_t id, unsigned int vcpu_index,
                                             int64_t num, uint64_t a1, uint64_t a2,
                                             uint64_t a3, uint64_t a4, uint64_t a5);

            #endif
            PLUGIN_HEADER_FIXTURE

            cat > stock-net-tx-negative.c <<'STOCK_NEGATIVE'
            #include <stddef.h>
            #include <stdint.h>
            #include "qemu/qemu-plugin.h"

            int main(void)
            {
                (void)qemu_plugin_register_net_tx_cb;
                return 0;
            }
            STOCK_NEGATIVE

            if cc -std=c11 -Wall -Werror -I include \
              -c stock-net-tx-negative.c \
              -o stock-net-tx-negative.o \
              2> stock-net-tx-negative.err
            then
              echo "stock QEMU unexpectedly exposed net TX callback symbols" >&2
              exit 1
            fi
            grep -q 'qemu_plugin_register_net_tx_cb' stock-net-tx-negative.err

            cat > qemu/osdep.h <<'OSDEP_FIXTURE'
            #ifndef QEMU_OSDEP_H
            #define QEMU_OSDEP_H

            #include <limits.h>
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/types.h>
            #include <sys/uio.h>

            #define g_autofree
            #define QSIMPLEQ_ENTRY(type) struct { struct type *sqe_next; }
            #define QSIMPLEQ_HEAD(name, type) struct name { struct type *sqh_first; }
            #define QSIMPLEQ_HEAD_INITIALIZER(head) { NULL }
            #ifndef SSIZE_MAX
            #define SSIZE_MAX ((ssize_t)(SIZE_MAX / 2))
            #endif

            typedef struct GHashTable {
                int unused;
            } GHashTable;
            typedef struct Location {
                int unused;
            } Location;
            typedef struct Netdev {
                int unused;
            } Netdev;
            typedef struct NICInfo {
                int unused;
            } NICInfo;

            static inline void *g_malloc(size_t size)
            {
                return malloc(size == 0 ? 1 : size);
            }

            static inline void g_free(void *ptr)
            {
                free(ptr);
            }

            #endif
            OSDEP_FIXTURE

            cat > qemu/iov.h <<'IOV_FIXTURE'
            #ifndef QEMU_IOV_H
            #define QEMU_IOV_H

            #include <stddef.h>
            #include <stdint.h>
            #include <string.h>
            #include <sys/uio.h>

            static inline size_t iov_size(const struct iovec *iov, int iovcnt)
            {
                size_t total = 0;
                for (int index = 0; index < iovcnt; index++) {
                    total += iov[index].iov_len;
                }
                return total;
            }

            static inline size_t iov_to_buf(const struct iovec *iov, int iovcnt,
                                            size_t offset, void *buf, size_t bytes)
            {
                uint8_t *out = buf;
                size_t copied = 0;
                for (int index = 0; index < iovcnt && copied < bytes; index++) {
                    if (offset >= iov[index].iov_len) {
                        offset -= iov[index].iov_len;
                        continue;
                    }
                    size_t available = iov[index].iov_len - offset;
                    size_t take = available < bytes - copied ? available : bytes - copied;
                    memcpy(out + copied, (const uint8_t *)iov[index].iov_base + offset, take);
                    copied += take;
                    offset = 0;
                }
                return copied;
            }

            #endif
            IOV_FIXTURE

            for header in qemu/qemu-print.h qemu/main-loop.h qemu/option.h qemu/keyval.h qapi/error.h qapi/opts-visitor.h qemu/sockets.h qemu/cutils.h qemu/config-file.h qemu/ctype.h qemu/id.h qemu/help_option.h monitor/monitor.h qapi/qapi-commands-net.h qapi/qapi-visit-net.h qobject/qdict.h qapi/qmp/qerror.h qemu/error-report.h system/runstate.h net/colo-compare.h net/filter.h qapi/string-output-visitor.h qapi/qobject-input-visitor.h standard-headers/linux/virtio_net.h; do
              mkdir -p "$(dirname "$header")"
              : > "$header"
            done
            : > net/slirp.h
            : > net/eth.h
            : > clients.h
            : > hub.h
            : > hw/qdev-properties.h
            : > util.h

            cat > include/net/net.h <<'NET_HEADER_FIXTURE'
            #ifndef QEMU_NET_H
            #define QEMU_NET_H

            #include <stddef.h>
            #include <stdint.h>
            #include <sys/types.h>
            #include <sys/uio.h>

            #define NET_BUFSIZE 65536
            #define MAX_NICS 8
            #define QEMU_NET_PACKET_FLAG_NONE 0u
            #define NET_FILTER_DIRECTION_TX 0
            #define NET_FILTER_DIRECTION_RX 1

            typedef struct NetClientState NetClientState;
            typedef struct NetQueue NetQueue;
            typedef void(NetPacketSent)(NetClientState *sender, ssize_t ret);

            typedef enum NetClientDriver {
                NET_CLIENT_DRIVER_USER = 0,
                NET_CLIENT_DRIVER_NIC = 1,
            } NetClientDriver;

            typedef struct NetClientInfo {
                NetClientDriver type;
            } NetClientInfo;

            struct NetQueue {
                int unused;
            };

            struct NetClientState {
                NetClientInfo *info;
                int link_down;
                NetClientState *peer;
                NetQueue *incoming_queue;
            };

            int filter_receive(NetClientState *nc, int direction,
                               NetClientState *sender, unsigned flags,
                               const uint8_t *buf, int size,
                               NetPacketSent *sent_cb);
            int filter_receive_iov(NetClientState *nc, int direction,
                                   NetClientState *sender, unsigned flags,
                                   const struct iovec *iov, int iovcnt,
                                   NetPacketSent *sent_cb);
            ssize_t qemu_net_queue_send(NetQueue *queue, NetClientState *sender,
                                        unsigned flags, const uint8_t *data,
                                        size_t size, NetPacketSent *sent_cb);
            ssize_t qemu_net_queue_send_iov(NetQueue *queue,
                                            NetClientState *sender,
                                            unsigned flags,
                                            const struct iovec *iov,
                                            int iovcnt,
                                            NetPacketSent *sent_cb);

            #endif
            NET_HEADER_FIXTURE

            cat > net/net.c <<'NET_FIXTURE'
            #include "qemu/osdep.h"

            #include "net/net.h"
            #include "clients.h"
            #include "hub.h"
            #include "hw/qdev-properties.h"
            #include "net/slirp.h"
            #include "net/eth.h"
            #include "util.h"

            #include "monitor/monitor.h"
            #include "qemu/help_option.h"
            #include "qapi/qapi-commands-net.h"
            #include "qapi/qapi-visit-net.h"
            #include "qobject/qdict.h"
            #include "qapi/qmp/qerror.h"
            #include "qemu/error-report.h"
            #include "qemu/sockets.h"
            #include "qemu/cutils.h"
            #include "qemu/config-file.h"
            #include "qemu/ctype.h"
            #include "qemu/id.h"
            #include "qemu/iov.h"
            #include "qemu/qemu-print.h"
            #include "qemu/main-loop.h"
            #include "qemu/option.h"
            #include "qemu/keyval.h"
            #include "qapi/error.h"
            #include "qapi/opts-visitor.h"
            #include "system/runstate.h"
            #include "net/colo-compare.h"
            #include "net/filter.h"
            #include "qapi/string-output-visitor.h"
            #include "qapi/qobject-input-visitor.h"
            #include "standard-headers/linux/virtio_net.h"

            typedef struct NetdevQueueEntry {
                Netdev *nd;
                Location loc;
                QSIMPLEQ_ENTRY(NetdevQueueEntry) entry;
            } NetdevQueueEntry;

            typedef QSIMPLEQ_HEAD(, NetdevQueueEntry) NetdevQueue;

            static NetdevQueue nd_queue = QSIMPLEQ_HEAD_INITIALIZER(nd_queue);

            static GHashTable *nic_model_help;

            static int nb_nics;
            static NICInfo nd_table[MAX_NICS];

            static ssize_t qemu_send_packet_async_with_flags(NetClientState *sender,
                                                             unsigned flags,
                                                             const uint8_t *buf, int size,
                                                             NetPacketSent *sent_cb)
            {
                NetQueue *queue;
                int ret;

                if (sender->link_down || !sender->peer) {
                    return size;
                }

                /* Let filters handle the packet first */
                ret = filter_receive(sender, NET_FILTER_DIRECTION_TX,
                                     sender, flags, buf, size, sent_cb);
                if (ret) {
                    return ret;
                }

                ret = filter_receive(sender->peer, NET_FILTER_DIRECTION_RX,
                                     sender, flags, buf, size, sent_cb);
                if (ret) {
                    return ret;
                }

                queue = sender->peer->incoming_queue;

                return qemu_net_queue_send(queue, sender, flags, buf, size, sent_cb);
            }

            ssize_t qemu_send_packet_async(NetClientState *sender,
                                           const uint8_t *buf, int size,
                                           NetPacketSent *sent_cb)
            {
                return qemu_send_packet_async_with_flags(sender, QEMU_NET_PACKET_FLAG_NONE,
                                                         buf, size, sent_cb);
            }

            ssize_t qemu_send_packet(NetClientState *nc, const uint8_t *buf, int size)
            {
                return qemu_send_packet_async(nc, buf, size, NULL);
            }

            ssize_t qemu_sendv_packet_async(NetClientState *sender,
                                            const struct iovec *iov, int iovcnt,
                                            NetPacketSent *sent_cb)
            {
                NetQueue *queue;
                size_t size = iov_size(iov, iovcnt);
                int ret;

                if (size > NET_BUFSIZE) {
                    return size;
                }

                if (sender->link_down || !sender->peer) {
                    return size;
                }

                /* Let filters handle the packet first */
                ret = filter_receive_iov(sender, NET_FILTER_DIRECTION_TX, sender,
                                         QEMU_NET_PACKET_FLAG_NONE, iov, iovcnt, sent_cb);
                if (ret) {
                    return ret;
                }

                ret = filter_receive_iov(sender->peer, NET_FILTER_DIRECTION_RX, sender,
                                         QEMU_NET_PACKET_FLAG_NONE, iov, iovcnt, sent_cb);
                if (ret) {
                    return ret;
                }

                queue = sender->peer->incoming_queue;

                return qemu_net_queue_send_iov(queue, sender,
                                               QEMU_NET_PACKET_FLAG_NONE,
                                               iov, iovcnt, sent_cb);
            }

            ssize_t
            qemu_sendv_packet(NetClientState *nc, const struct iovec *iov, int iovcnt)
            {
                return qemu_sendv_packet_async(nc, iov, iovcnt, NULL);
            }
            NET_FIXTURE

            patch --batch --fuzz=0 -p1 < "${patchDir}/${patchName}"
            grep -q 'qemu_plugin_register_net_tx_cb' include/qemu/qemu-plugin.h
            grep -q 'crucible_net_tx_submit' net/net.c

            cp "$microtestSourcePath" phase1-qemu-net-tx-callback.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -Wno-unused-function -Wno-unused-variable \
              -I. -Iinclude \
              phase1-qemu-net-tx-callback.c \
              -o phase1-qemu-net-tx-callback

            mkdir -p "$out"
            ./phase1-qemu-net-tx-callback > "$out/qemu-net-tx-callback-microtest"
            grep -q '^PASS$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^qemu_plugin_register_net_tx_cb_symbol=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_callback_upstream_fallback=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_callback_intercepts_flat_frame=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_callback_intercepts_iov_frame=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_callback_bypasses_backend_when_registered=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_callback_guest_only=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_oversized_iov_fails_loudly=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_callback_failure_fails_loudly=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_link_down_keeps_upstream_drop=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^net_tx_callback_userdata_exercised=true$' "$out/qemu-net-tx-callback-microtest"
            grep -q '^stock_negative_control_net_tx_symbol_absent=true$' "$out/qemu-net-tx-callback-microtest"

            rx_result="${qemuNetDeterministic}/result"
            grep -q '^qemu_net_rx_lossless_queue=true$' "$rx_result"
            grep -q '^qemu_net_rx_flush_at_delivery_icount=true$' "$rx_result"
            grep -q '^qemu_net_rx_flush_fails_loudly_when_not_ready=true$' "$rx_result"
            grep -q '^skewed_producer_observed_icount_identical=true$' "$rx_result"
            cp "$rx_result" "$out/qemu-net-rx-lossless.result"
            cp stock-net-tx-negative.err "$out/stock-negative-control.err"
            cp include/qemu/qemu-plugin.h "$out/qemu-plugin.h.patched"
            cp net/net.c "$out/net.c.patched"

            cat > "$out/result" <<RESULT
            PASS
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            qemu_net_tx_callback_registration_exercised=true
            qemu_net_tx_upstream_fallback=true
            qemu_net_tx_flat_frame_intercept=true
            qemu_net_tx_iov_frame_intercept=true
            qemu_net_tx_backend_bypassed_when_registered=true
            qemu_net_tx_callback_guest_only=true
            qemu_net_tx_oversized_iov_fails_loudly=true
            qemu_net_tx_callback_failure_fails_loudly=true
            qemu_net_tx_link_down_keeps_upstream_drop=true
            qemu_net_rx_lossless_queue=true
            qemu_net_rx_flush_at_delivery_icount=true
            qemu_net_rx_flush_fails_loudly_when_not_ready=true
            qemu_net_rx_skewed_producer_observed_icount_identical=true
            apply_clean_patch_fuzz=0
            RESULT
          '';
        }
      ];
    }
