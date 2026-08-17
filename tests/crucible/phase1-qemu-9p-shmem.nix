{
  pkgs,
  lib,
  patchName ? "0018-crucible-dev-cb-api.patch",
  qemuPackage ? null,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-qemu-9p-shmem.c;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;
  qemuSource =
    if qemuPackage == null
    then pkgs.qemu-crucible.src
    else qemuPackage.src;
  qemuVersion =
    if qemuPackage == null
    then pkgs.qemu-crucible.version
    else qemuPackage.version;
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
  tPatch13PatchNames = [
    "0018-crucible-dev-cb-api.patch"
    "0019-crucible-9p-shmem.patch"
  ];
  patchContextNames = [
    "0001-crucible-sim-accel.patch"
    "0002-crucible-rr-fingerprint-helpers.patch"
    "0003-crucible-icount-no-realtime.patch"
    "0004-crucible-no-warp-with-plugin.patch"
    "0005-crucible-det-glib-prng.patch"
    "0006-crucible-clock-deadline.patch"
    "0007-crucible-block-rtc-read.patch"
    "0008-crucible-det-getrandom.patch"
    "0009-crucible-net-deterministic.patch"
    "0010-crucible-plugin-time-advance.patch"
    "0011-crucible-plugin-icount-raw.patch"
    "0012-crucible-plugin-vcpu-exit.patch"
    "0013-crucible-plugin-wake-fd.patch"
    "0014-crucible-plugin-tcg-exec-cb.patch"
    "0015-crucible-blk-shmem.patch"
    "0016-crucible-blk-shmem-io-fixes.patch"
    "0017-crucible-blk-write-sentinel.patch"
    "0018-crucible-dev-cb-api.patch"
    "0019-crucible-9p-shmem.patch"
  ] ++ lib.optionals (patchName == "0076-crucible-9p-completion-wake-registration.patch") [
    "0076-crucible-9p-completion-wake-registration.patch"
  ];
  taskIds =
    if patchName == "0076-crucible-9p-completion-wake-registration.patch"
    then ["T-PATCH-20"]
    else ["T-PATCH-13"];
  notifierCompileFlag =
    if patchName == "0076-crucible-9p-completion-wake-registration.patch"
    then "-DEXPECT_UNCONDITIONAL_9P_WAKE_REGISTRATION"
    else "";
  notifierResultLine =
    if patchName == "0076-crucible-9p-completion-wake-registration.patch"
    then "late_plugin_9p_wake_notifier_registered=true"
    else "sim_off_9p_has_no_wake_notifier=true";

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  patchRequirements =
    if patchName == "0018-crucible-dev-cb-api.patch"
    then [
      {
        label = "9p callback registration symbol";
        needle = "qemu_plugin_register_9p_cb";
      }
      {
        label = "9p burst callback type";
        needle = "qemu_plugin_9p_burst_cb_t";
      }
      {
        label = "9p submit callback type";
        needle = "qemu_plugin_9p_submit_cb_t";
      }
      {
        label = "9p poll callback type";
        needle = "qemu_plugin_9p_poll_cb_t";
      }
      {
        label = "9p pending sentinel";
        needle = "#define QEMU_PLUGIN_9P_POLL_PENDING (-2)";
      }
    ]
    else if patchName == "0019-crucible-9p-shmem.patch"
    then [
      {
        label = "virtio 9p forwarder";
        needle = "virtio_9p_forward_crucible";
      }
      {
        label = "upstream fallback guard";
        needle = "crucible_9p_callbacks_ready()";
      }
      {
        label = "raw 9p request copy";
        needle = "iov_to_buf(elem->out_sg, elem->out_num, 0, request, request_len)";
      }
      {
        label = "raw 9p response delivery";
        needle = "iov_from_buf(elem->in_sg, elem->in_num, 0, response";
      }
      {
        label = "burst finish";
        needle = "crucible_9p_finish_burst";
      }
      {
        label = "forwarding failure clears pdu slot";
        needle = "v->elems[pdu->idx] = NULL;";
      }
      {
        label = "per-device request id";
        needle = "next_crucible_9p_request_id";
      }
      {
        label = "event-driven wake notifier";
        needle = "virtio_9p_crucible_wake";
      }
      {
        label = "sim-off wake-notifier registration guard";
        needle = "crucible_9p_wake_registered";
      }
      {
        label = "pending PDU retention";
        needle = "crucible_9p_pending_pdu";
      }
      {
        label = "terminal pending cleanup";
        needle = "virtio_9p_abandon_crucible_pending";
      }
      {
        label = "pending callback teardown guard";
        needle = "crucible 9p callbacks disappeared with a request pending";
      }
      {
        label = "pending reset cleanup";
        needle = "virtio-9p reset with a Crucible request pending";
      }
      {
        label = "terminal host-error shutdown";
        needle = "qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_ERROR)";
      }
      {
        label = "shutdown-aware pending cleanup";
        needle = "crucible_9p_shutdown_underway()";
      }
      {
        label = "response length validation";
        needle = "le32_to_cpu(response_header.size_le)";
      }
      {
        label = "response tag validation";
        needle = "le16_to_cpu(response_header.tag_le) != pdu->tag";
      }
      {
        label = "completion clears pending ownership before PDU release";
        needle = "v->crucible_9p_pending_pdu = NULL;";
      }
    ]
    else [
      {
        label = "unconditional device-lifetime notifier registration";
        needle = "qemu_plugin_wake_notifier_add(&v->crucible_9p_wake_notifier);";
      }
      {
        label = "registered notifier ownership state";
        needle = "v->crucible_9p_wake_registered = true;";
      }
    ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix (
      map (name: {
        label = "QEMU patch wiring for ${name}";
        needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
      })
      tPatch13PatchNames
    )
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-qemu-9p-shmem.c" microtestSource [
      {
        label = "patched virtio 9p include";
        needle = "#include \"hw/9pfs/virtio-9p-device.c\"";
      }
      {
        label = "9p callback registration exercised";
        needle = "plugin_9p_callback_registration_exercised=true";
      }
      {
        label = "9p upstream fallback exercised";
        needle = "upstream_9p_fallback_without_callbacks=true";
      }
      {
        label = "sim-off notifier inertness exercised";
        needle = "sim_off_9p_has_no_wake_notifier=true";
      }
      {
        label = "9p pending poll exercised";
        needle = "pending_9p_poll_event_driven=true";
      }
      {
        label = "scheduler wake repoll exercised";
        needle = "scheduler_wake_repolls_pending_9p=true";
      }
      {
        label = "duplicate output deferral exercised";
        needle = "duplicate_output_waits_for_pending_9p=true";
      }
      {
        label = "exactly-once burst completion exercised";
        needle = "pending_9p_burst_finishes_exactly_once=true";
      }
      {
        label = "terminal wake cleanup exercised";
        needle = "wake_failure_does_not_strand_9p=true";
      }
      {
        label = "wake-fd owner remains the single shutdown authority";
        needle = "wake_failure_defers_shutdown_to_wake_fd_owner=true";
      }
      {
        label = "callback teardown cleanup exercised";
        needle = "callback_removal_does_not_call_stale_9p=true";
      }
      {
        label = "reset cleanup exercised";
        needle = "reset_does_not_strand_9p=true";
      }
      {
        label = "unrealize cleanup exercised";
        needle = "unrealize_does_not_strand_9p=true";
      }
      {
        label = "shutdown unrealize cleanup exercised";
        needle = "shutdown_unrealize_reclaims_9p_without_redundant_shutdown=true";
      }
      {
        label = "malformed response size rejection exercised";
        needle = "malformed_9p_response_size_fails_closed=true";
      }
      {
        label = "mismatched response tag rejection exercised";
        needle = "mismatched_9p_response_tag_fails_closed=true";
      }
      {
        label = "9p burst callbacks exercised";
        needle = "burst_callbacks_exercised=true";
      }
      {
        label = "multi-request burst exercised";
        needle = "multi_request_burst_exercised=true";
      }
      {
        label = "failure path clears pdu slot";
        needle = "failure_path_clears_pdu_slot=true";
      }
      {
        label = "stock negative control";
        needle = "stock_negative_control_9p_symbols_absent=true";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "9p shmem patch catalog";
        needle = "crucible-9p-shmem";
      }
      {
        label = "device callback API patch catalog";
        needle = "crucible-dev-cb-api";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes QEMU 9p shmem check";
        needle = "qemuNinePShmem = import ./phase1-qemu-9p-shmem.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU 9p-shmem check failed for ${patchName}:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-9p-shmem-${lib.removeSuffix ".patch" patchName}";
      version = "0";
      src = null;

      inherit microtestSource;
      passAsFile = ["microtestSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "run-qemu-9p-shmem-microtest";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            mkdir -p qemu-source
            tar -xf ${qemuSource} -C qemu-source
            cd qemu-source/qemu-${qemuVersion}

            mkdir -p fixture/include/glib
            cat > fixture/include/glib.h <<'GLIB_FIXTURE'
            #ifndef GLIB_H
            #define GLIB_H

            typedef struct GArray GArray;
            typedef struct GByteArray GByteArray;
            typedef struct GHashTable GHashTable;

            #endif
            GLIB_FIXTURE

            cat > stock-9p-negative.c <<'STOCK_NEGATIVE'
            #include <stddef.h>
            #include <stdint.h>
            #include "qemu/qemu-plugin.h"

            int main(void)
            {
                (void)qemu_plugin_register_9p_cb;
                return QEMU_PLUGIN_9P_POLL_PENDING;
            }
            STOCK_NEGATIVE

            if cc -std=c11 -Wall -Werror -I fixture/include -I include -I . \
              -c stock-9p-negative.c \
              -o stock-9p-negative.o \
              2> stock-9p-negative.err
            then
              echo "stock QEMU unexpectedly exposed crucible 9p symbols" >&2
              exit 1
            fi
            grep -q 'qemu_plugin_register_9p_cb' stock-9p-negative.err

            for patch in ${builtins.concatStringsSep " " patchContextNames}; do
              patch --batch --fuzz=0 -p1 < "${patchDir}/$patch"
            done

            grep -q 'qemu_plugin_register_9p_cb' include/qemu/qemu-plugin.h
            grep -q '#define QEMU_PLUGIN_9P_POLL_PENDING (-2)' include/qemu/qemu-plugin.h
            grep -q 'virtio_9p_forward_crucible' hw/9pfs/virtio-9p-device.c
            grep -q 'crucible_9p_callbacks_ready()' hw/9pfs/virtio-9p-device.c
            grep -q 'next_crucible_9p_request_id' hw/9pfs/virtio-9p.h
            grep -q 'virtio_9p_crucible_wake' hw/9pfs/virtio-9p-device.c
            grep -q 'crucible_9p_pending_pdu' hw/9pfs/virtio-9p.h
            grep -q 'virtio-9p reset with a Crucible request pending' hw/9pfs/virtio-9p-device.c
            grep -q 'qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_ERROR)' hw/9pfs/virtio-9p-device.c
            ! grep -Eq 'main_loop_wait|aio_poll|aio_bh_poll' hw/9pfs/virtio-9p-device.c

            mkdir -p fixture-src/hw/9pfs fixture/include/fsdev fixture/include/hw/virtio fixture/include/hw fixture/include/qemu fixture/include/system
            cp hw/9pfs/virtio-9p-device.c fixture-src/hw/9pfs/virtio-9p-device.c

            cat > fixture/include/qemu/osdep.h <<'OSDEP_FIXTURE'
            #ifndef QEMU_OSDEP_H
            #define QEMU_OSDEP_H

            #include <assert.h>
            #include <errno.h>
            #include <limits.h>
            #include <stdarg.h>
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/types.h>
            #include <sys/uio.h>

            #define g_autofree
            #define g_assert assert
            #define QEMU_PACKED __attribute__((packed))
            #define QEMU_BUILD_BUG_ON(condition) \
                typedef char qemu_build_bug_on[(condition) ? -1 : 1] __attribute__((unused))
            #define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
            #define container_of(ptr, type, member) \
                ((type *)((char *)(ptr) - offsetof(type, member)))
            #define le32_to_cpu(value) (value)
            #define le16_to_cpu(value) (value)
            #define ERRP_GUARD()

            typedef struct Error {
                const char *message;
            } Error;

            static inline void *g_malloc(size_t size)
            {
                return malloc(size == 0 ? 1 : size);
            }

            static inline void *g_malloc0(size_t size)
            {
                return calloc(1, size == 0 ? 1 : size);
            }

            static inline void g_free(void *ptr)
            {
                free(ptr);
            }

            static inline const char *g_strerror(int errnum)
            {
                return strerror(errnum);
            }

            static inline char *g_strdup_printf(const char *format, ...)
            {
                va_list args;
                va_list copy;
                int length;
                char *message;

                va_start(args, format);
                va_copy(copy, args);
                length = vsnprintf(NULL, 0, format, copy);
                va_end(copy);
                if (length < 0) {
                    va_end(args);
                    return NULL;
                }
                message = malloc((size_t)length + 1);
                if (message != NULL) {
                    (void)vsnprintf(message, (size_t)length + 1, format, args);
                }
                va_end(args);
                return message;
            }

            static inline void error_setg(Error **errp, const char *fmt, ...)
            {
                static Error error;
                (void)fmt;
                error.message = "fixture error";
                if (errp != 0) {
                    *errp = &error;
                }
            }

            #endif
            OSDEP_FIXTURE

            cat > fixture/include/qemu/sockets.h <<'SOCKETS_FIXTURE'
            #ifndef QEMU_SOCKETS_H
            #define QEMU_SOCKETS_H
            #endif
            SOCKETS_FIXTURE

            cat > fixture/include/qemu/iov.h <<'IOV_FIXTURE'
            #ifndef QEMU_IOV_H
            #define QEMU_IOV_H

            #include <stddef.h>
            #include <string.h>
            #include <sys/uio.h>

            static inline size_t iov_size(const struct iovec *iov,
                                          unsigned int iov_cnt)
            {
                size_t total = 0;
                for (unsigned int index = 0; index < iov_cnt; index++) {
                    total += iov[index].iov_len;
                }
                return total;
            }

            static inline size_t iov_to_buf(const struct iovec *iov,
                                            unsigned int iov_cnt,
                                            size_t offset, void *buf,
                                            size_t bytes)
            {
                uint8_t *out = buf;
                size_t copied = 0;
                for (unsigned int index = 0; index < iov_cnt && copied < bytes; index++) {
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

            static inline size_t iov_from_buf(const struct iovec *iov,
                                              unsigned int iov_cnt,
                                              size_t offset, const void *buf,
                                              size_t bytes)
            {
                const uint8_t *in = buf;
                size_t copied = 0;
                for (unsigned int index = 0; index < iov_cnt && copied < bytes; index++) {
                    if (offset >= iov[index].iov_len) {
                        offset -= iov[index].iov_len;
                        continue;
                    }
                    size_t available = iov[index].iov_len - offset;
                    size_t take = available < bytes - copied ? available : bytes - copied;
                    memcpy((uint8_t *)iov[index].iov_base + offset, in + copied, take);
                    copied += take;
                    offset = 0;
                }
                return copied;
            }

            #endif
            IOV_FIXTURE

            cat > fixture/include/qemu/module.h <<'MODULE_FIXTURE'
            #ifndef QEMU_MODULE_H
            #define QEMU_MODULE_H
            #define type_init(function) \
                static void (*function##_fixture_ref)(void) __attribute__((unused)) = function;
            #endif
            MODULE_FIXTURE

            cat > fixture/include/qemu/notify.h <<'NOTIFY_FIXTURE'
            #ifndef QEMU_NOTIFY_H
            #define QEMU_NOTIFY_H

            typedef struct Notifier Notifier;
            struct Notifier {
                void (*notify)(Notifier *notifier, void *data);
            };

            #endif
            NOTIFY_FIXTURE

            cat > fixture/include/system/runstate.h <<'RUNSTATE_FIXTURE'
            #ifndef SYSTEM_RUNSTATE_H
            #define SYSTEM_RUNSTATE_H

            #include <stdbool.h>

            typedef enum RunState {
                RUN_STATE_RUNNING = 0,
                RUN_STATE_SHUTDOWN = 1,
            } RunState;

            #define SHUTDOWN_CAUSE_NONE 0
            #define SHUTDOWN_CAUSE_HOST_ERROR 1

            bool runstate_check(RunState state);
            int qemu_shutdown_requested_get(void);
            void qemu_system_shutdown_request(int reason);

            #endif
            RUNSTATE_FIXTURE

            cat > fixture/include/hw/virtio/virtio.h <<'VIRTIO_FIXTURE'
            #ifndef HW_VIRTIO_VIRTIO_H
            #define HW_VIRTIO_VIRTIO_H

            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <sys/uio.h>

            typedef struct VirtIODevice {
                int unused;
            } VirtIODevice;

            typedef struct DeviceState {
                int unused;
            } DeviceState;

            typedef struct VirtQueue {
                int unused;
            } VirtQueue;

            typedef struct VirtQueueElement {
                struct iovec *in_sg;
                unsigned int in_num;
                struct iovec *out_sg;
                unsigned int out_num;
            } VirtQueueElement;

            typedef struct Property Property;

            typedef struct VMStateField {
                const char *name;
            } VMStateField;

            typedef struct VMStateDescription {
                const char *name;
                int minimum_version_id;
                int version_id;
                const VMStateField *fields;
            } VMStateDescription;

            typedef struct DeviceClass {
                const VMStateDescription *vmsd;
                unsigned long categories[1];
            } DeviceClass;

            typedef struct VirtioDeviceClass {
                void (*realize)(DeviceState *dev, Error **errp);
                void (*unrealize)(DeviceState *dev);
                uint64_t (*get_features)(VirtIODevice *vdev, uint64_t features, Error **errp);
                void (*get_config)(VirtIODevice *vdev, uint8_t *config);
                void (*reset)(VirtIODevice *vdev);
            } VirtioDeviceClass;

            typedef struct ObjectClass {
                int unused;
            } ObjectClass;

            typedef struct TypeInfo {
                const char *name;
                const char *parent;
                size_t instance_size;
                void (*class_init)(ObjectClass *klass, void *data);
            } TypeInfo;

            #define TYPE_VIRTIO_DEVICE "virtio-device"
            #define VIRTIO_ID_9P 9
            #define VIRTIO_9P_MOUNT_TAG 0
            #define DEVICE_CATEGORY_STORAGE 0
            #define VIRTIO_DEVICE(obj) ((VirtIODevice *)(obj))
            #define VIRTIO_DEVICE_CLASS(klass) ((VirtioDeviceClass *)(klass))
            #define DEVICE_CLASS(klass) ((DeviceClass *)(klass))
            #define VMSTATE_VIRTIO_DEVICE { .name = "virtio-device" }
            #define VMSTATE_END_OF_LIST() { .name = NULL }

            VirtQueueElement *virtqueue_pop(VirtQueue *vq, size_t sz);
            void virtqueue_push(VirtQueue *vq, VirtQueueElement *elem, uint32_t len);
            void virtqueue_detach_element(VirtQueue *vq, VirtQueueElement *elem, uint32_t len);
            void virtio_notify(VirtIODevice *vdev, VirtQueue *vq);
            void virtio_error(VirtIODevice *vdev, const char *fmt, ...);
            void virtio_add_feature(uint64_t *features, unsigned int feature);
            void virtio_stw_p(VirtIODevice *vdev, uint16_t *dst, uint16_t value);
            void virtio_init(VirtIODevice *vdev, uint16_t device_id, size_t config_size);
            VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                                        void (*handler)(VirtIODevice *, VirtQueue *));
            void virtio_delete_queue(VirtQueue *vq);
            void virtio_cleanup(VirtIODevice *vdev);
            void device_class_set_props(DeviceClass *dc, const Property *props);
            void set_bit(int bit, unsigned long *addr);
            void type_register_static(const TypeInfo *info);

            #endif
            VIRTIO_FIXTURE

            cat > fixture/include/hw/virtio/virtio-access.h <<'VIRTIO_ACCESS_FIXTURE'
            #ifndef HW_VIRTIO_VIRTIO_ACCESS_H
            #define HW_VIRTIO_VIRTIO_ACCESS_H
            #endif
            VIRTIO_ACCESS_FIXTURE

            cat > fixture/include/hw/qdev-properties.h <<'QDEV_FIXTURE'
            #ifndef HW_QDEV_PROPERTIES_H
            #define HW_QDEV_PROPERTIES_H

            typedef struct Property {
                const char *name;
            } Property;

            #define DEFINE_PROP_STRING(_name, state, field) { .name = _name }
            #define DEFINE_PROP_END_OF_LIST() { .name = NULL }

            #endif
            QDEV_FIXTURE

            cat > fixture/include/fsdev/qemu-fsdev.h <<'FSDEV_FIXTURE'
            #ifndef FSDEV_QEMU_FSDEV_H
            #define FSDEV_QEMU_FSDEV_H

            #define V9FS_NO_PERF_WARN 1u

            typedef struct FsDriverEntry {
                unsigned int export_flags;
                const char *path;
            } FsDriverEntry;

            FsDriverEntry *get_fsdev_fsentry(char *id);

            #endif
            FSDEV_FIXTURE

            cat > fixture-src/hw/9pfs/coth.h <<'COTH_FIXTURE'
            #ifndef HW_9PFS_COTH_H
            #define HW_9PFS_COTH_H
            #endif
            COTH_FIXTURE

            cat > fixture/include/system/qtest.h <<'QTEST_FIXTURE'
            #ifndef SYSTEM_QTEST_H
            #define SYSTEM_QTEST_H
            #include <stdbool.h>
            bool qtest_enabled(void);
            #endif
            QTEST_FIXTURE

            cat > fixture-src/hw/9pfs/virtio-9p.h <<'VIRTIO_9P_FIXTURE'
            #ifndef QEMU_VIRTIO_9P_H
            #define QEMU_VIRTIO_9P_H

            #include <stdarg.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <sys/types.h>
            #include <sys/uio.h>
            #include "hw/virtio/virtio.h"
            #include "qemu/notify.h"

            #define MAX_REQ 4
            #define TYPE_VIRTIO_9P "virtio-9p-device"
            #define VIRTIO_9P(dev) ((V9fsVirtioState *)(dev))

            typedef struct V9fsPDU V9fsPDU;
            typedef struct V9fsState V9fsState;
            typedef struct V9fsTransport V9fsTransport;
            typedef struct V9fsVirtioState V9fsVirtioState;

            typedef struct {
                uint32_t size_le;
                uint8_t id;
                uint16_t tag_le;
            } QEMU_PACKED P9MsgHeader;
            QEMU_BUILD_BUG_ON(sizeof(P9MsgHeader) != 7);

            typedef struct V9fsConf {
                char *tag;
                char *fsdev_id;
            } V9fsConf;

            struct V9fsState {
                char *tag;
                V9fsConf fsconf;
                const V9fsTransport *transport;
            };

            struct V9fsPDU {
                uint32_t size;
                uint16_t tag;
                uint8_t id;
                uint8_t cancelled;
                V9fsState *s;
                uint32_t idx;
            };

            struct V9fsTransport {
                ssize_t (*pdu_vmarshal)(V9fsPDU *pdu, size_t offset,
                                        const char *fmt, va_list ap);
                ssize_t (*pdu_vunmarshal)(V9fsPDU *pdu, size_t offset,
                                          const char *fmt, va_list ap);
                void (*init_in_iov_from_pdu)(V9fsPDU *pdu,
                                             struct iovec **piov,
                                             unsigned int *pniov, size_t size);
                void (*init_out_iov_from_pdu)(V9fsPDU *pdu,
                                              struct iovec **piov,
                                              unsigned int *pniov, size_t size);
                void (*push_and_notify)(V9fsPDU *pdu);
            };

            struct V9fsVirtioState {
                VirtIODevice parent_obj;
                VirtQueue *vq;
                size_t config_size;
                uint32_t next_crucible_9p_request_id;
                bool crucible_9p_burst_active;
                bool crucible_9p_wake_registered;
                V9fsPDU *crucible_9p_pending_pdu;
                uint32_t crucible_9p_pending_request_id;
                size_t crucible_9p_pending_response_capacity;
                Notifier crucible_9p_wake_notifier;
                VirtQueueElement *elems[MAX_REQ];
                V9fsState state;
            };

            struct virtio_9p_config {
                uint16_t tag_len;
                char tag[];
            };

            V9fsPDU *pdu_alloc(V9fsState *s);
            void pdu_free(V9fsPDU *pdu);
            void pdu_submit(V9fsPDU *pdu, P9MsgHeader *hdr);
            int v9fs_device_realize_common(V9fsState *s,
                                           const V9fsTransport *transport,
                                           Error **errp);
            void v9fs_device_unrealize_common(V9fsState *s);
            void v9fs_reset(V9fsState *s);
            ssize_t v9fs_iov_vmarshal(const struct iovec *iov,
                                      unsigned int iov_cnt, size_t offset,
                                      int bswap, const char *fmt, va_list ap);
            ssize_t v9fs_iov_vunmarshal(const struct iovec *iov,
                                        unsigned int iov_cnt, size_t offset,
                                        int bswap, const char *fmt, va_list ap);

            #endif
            VIRTIO_9P_FIXTURE

            cp "$microtestSourcePath" fixture-src/phase1-qemu-9p-shmem.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              -Wno-unused-parameter -Wno-unused-function \
              -DCONFIG_PLUGIN \
              ${notifierCompileFlag} \
              -I fixture-src \
              -I fixture/include \
              -I include \
              -I . \
              fixture-src/phase1-qemu-9p-shmem.c \
              -o phase1-qemu-9p-shmem

            mkdir -p "$out"
            ./phase1-qemu-9p-shmem > "$out/qemu-9p-shmem-microtest"
            grep -q '^PASS$' "$out/qemu-9p-shmem-microtest"
            grep -q '^virtio_9p_forwarding_path_exercised=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^plugin_9p_callback_registration_exercised=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^upstream_9p_fallback_without_callbacks=true$' "$out/qemu-9p-shmem-microtest"
            grep -Fxq '${notifierResultLine}' "$out/qemu-9p-shmem-microtest"
            grep -q '^partial_9p_registration_falls_back=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^raw_9p_request_round_trip=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^raw_9p_response_delivered=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^burst_callbacks_exercised=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^multi_request_burst_exercised=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^pending_9p_poll_event_driven=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^scheduler_wake_repolls_pending_9p=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^duplicate_output_waits_for_pending_9p=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^pending_9p_burst_finishes_exactly_once=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^wake_failure_does_not_strand_9p=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^wake_failure_defers_shutdown_to_wake_fd_owner=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^callback_removal_does_not_call_stale_9p=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^reset_does_not_strand_9p=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^unrealize_does_not_strand_9p=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^shutdown_unrealize_reclaims_9p_without_redundant_shutdown=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^ninep_pending_sentinel=-2$' "$out/qemu-9p-shmem-microtest"
            grep -q '^malformed_9p_response_size_fails_closed=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^mismatched_9p_response_tag_fails_closed=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^oversized_9p_response_fails_closed=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^oversized_9p_request_fails_closed=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^request_id_overflow_fails_closed=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^failure_path_clears_pdu_slot=true$' "$out/qemu-9p-shmem-microtest"
            grep -q '^stock_negative_control_9p_symbols_absent=true$' "$out/qemu-9p-shmem-microtest"

            cp stock-9p-negative.err "$out/stock-negative-control.err"
            cp hw/9pfs/virtio-9p-device.c "$out/virtio-9p-device.c.patched"
            cp hw/9pfs/virtio-9p.h "$out/virtio-9p.h.patched"
            cp include/qemu/qemu-plugin.h "$out/qemu-plugin.h.patched"

            cat > "$out/result" <<'RESULT'
            PASS
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            virtio_9p_fixture_includes_patched_source=true
            plugin_9p_callback_registration_exercised=true
            upstream_9p_fallback_without_callbacks=true
            ${notifierResultLine}
            partial_9p_registration_falls_back=true
            raw_9p_request_round_trip=true
            raw_9p_response_delivered=true
            burst_callbacks_exercised=true
            multi_request_burst_exercised=true
            pending_9p_poll_event_driven=true
            scheduler_wake_repolls_pending_9p=true
            duplicate_output_waits_for_pending_9p=true
            pending_9p_burst_finishes_exactly_once=true
            wake_failure_does_not_strand_9p=true
            wake_failure_defers_shutdown_to_wake_fd_owner=true
            callback_removal_does_not_call_stale_9p=true
            reset_does_not_strand_9p=true
            unrealize_does_not_strand_9p=true
            shutdown_unrealize_reclaims_9p_without_redundant_shutdown=true
            ninep_pending_sentinel=-2
            malformed_9p_response_size_fails_closed=true
            mismatched_9p_response_tag_fails_closed=true
            fail_closed_9p_microtests=true
            failure_path_clears_pdu_slot=true
            apply_clean_patch_fuzz=0
            RESULT
          '';
        }
      ];
    }
