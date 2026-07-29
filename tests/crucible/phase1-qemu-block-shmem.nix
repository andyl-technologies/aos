{
  pkgs,
  lib,
  patchName ? "0015-crucible-blk-shmem.patch",
  qemuPackage ? null,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-qemu-block-shmem.c;
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
  tPatch12PatchNames = [
    "0015-crucible-blk-shmem.patch"
    "0016-crucible-blk-shmem-io-fixes.patch"
    "0017-crucible-blk-write-sentinel.patch"
  ];
  patchContextNames =
    [
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
    ]
    ++ tPatch12PatchNames;
  taskIds = ["T-PATCH-12"];

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  patchRequirements =
    if patchName == "0015-crucible-blk-shmem.patch"
    then [
      {
        label = "crucible shmem driver";
        needle = "block/crucible-shmem.c";
      }
      {
        label = "driver format name";
        needle = ".format_name            = \"crucible-shmem\"";
      }
      {
        label = "system-emulator-only Meson integration";
        needle = "system_ss.add(files('crucible-shmem.c'))";
      }
      {
        label = "block driver registration";
        needle = "block_init(bdrv_crucible_shmem_init)";
      }
      {
        label = "plugin block callback registration";
        needle = "qemu_plugin_register_blk_cb";
      }
      {
        label = "block submit callback type";
        needle = "qemu_plugin_blk_submit_cb_t";
      }
      {
        label = "block poll callback type";
        needle = "qemu_plugin_blk_poll_cb_t";
      }
      {
        label = "pstrcpy declaration include";
        needle = "#include \"qemu/cutils.h\"";
      }
    ]
    else if patchName == "0016-crucible-blk-shmem-io-fixes.patch"
    then [
      {
        label = "bounded poll reschedule";
        needle = "aio_co_schedule(bdrv_get_aio_context(bs), qemu_coroutine_self())";
      }
      {
        label = "coroutine yield after reschedule";
        needle = "qemu_coroutine_yield()";
      }
    ]
    else [
      {
        label = "pending sentinel distinct from zero";
        needle = "#define QEMU_PLUGIN_BLK_POLL_PENDING (-2)";
      }
      {
        label = "old conflated sentinel removed";
        needle = "-#define QEMU_PLUGIN_BLK_POLL_PENDING 0";
      }
    ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix (
      map (name: {
        label = "QEMU patch wiring for ${name}";
        needle = "patch -p1 < \${./qemu-patches/${name}}";
      })
      tPatch12PatchNames
    )
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ failuresFor "tests/crucible/phase1-qemu-block-shmem.c" microtestSource [
      {
        label = "patched driver include";
        needle = "#include \"block/crucible-shmem.c\"";
      }
      {
        label = "plugin callback registration exercised";
        needle = "plugin_callback_registration_exercised=true";
      }
      {
        label = "pending sentinel exercised";
        needle = "zero_length_success_distinct_from_pending=true";
      }
      {
        label = "poll cadence exercised";
        needle = "poll_sleep_cadence_scheduled=true";
      }
      {
        label = "deterministic completion exercised";
        needle = "deterministic_completion_offsets=true";
      }
      {
        label = "stock negative control";
        needle = "stock_negative_control_block_symbols_absent=true";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "T-PATCH-12 checklist complete";
        needle = "- [x] **T-PATCH-12**";
      }
      {
        label = "block shmem patch catalog";
        needle = "crucible-blk-shmem";
      }
      {
        label = "block IO fixes patch catalog";
        needle = "crucible-blk-shmem-io-fixes";
      }
      {
        label = "write sentinel patch catalog";
        needle = "crucible-blk-write-sentinel";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes QEMU block shmem check";
        needle = "qemuBlockShmem = import ./phase1-qemu-block-shmem.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU block-shmem check failed for ${patchName}:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-block-shmem-${lib.removeSuffix ".patch" patchName}";
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
          name = "run-qemu-block-shmem-microtest";
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

            #endif
            GLIB_FIXTURE

            cat > stock-block-negative.c <<'STOCK_NEGATIVE'
            #include <stddef.h>
            #include <stdint.h>
            #include "qemu/qemu-plugin.h"

            int main(void)
            {
                (void)qemu_plugin_register_blk_cb;
                return QEMU_PLUGIN_BLK_POLL_PENDING;
            }
            STOCK_NEGATIVE

            if cc -std=c11 -Wall -Werror -I fixture/include -I include -I . \
              -c stock-block-negative.c \
              -o stock-block-negative.o \
              2> stock-block-negative.err
            then
              echo "stock QEMU unexpectedly exposed crucible block shmem symbols" >&2
              exit 1
            fi
            grep -q 'qemu_plugin_register_blk_cb' stock-block-negative.err
            test ! -e block/crucible-shmem.c

            for patch in ${builtins.concatStringsSep " " patchContextNames}; do
              patch --batch --fuzz=0 -p1 < "${patchDir}/$patch"
            done

            grep -F -q "system_ss.add(files('crucible-shmem.c'))" block/meson.build
            grep -F -q 'block_init(bdrv_crucible_shmem_init)' block/crucible-shmem.c
            grep -q 'qemu_plugin_register_blk_cb' include/qemu/qemu-plugin.h
            grep -q '#define QEMU_PLUGIN_BLK_POLL_PENDING (-2)' include/qemu/qemu-plugin.h
            grep -q 'aio_co_schedule(bdrv_get_aio_context(bs), qemu_coroutine_self())' block/crucible-shmem.c

            mkdir -p fixture/include/block fixture/include/qapi fixture/include/qemu fixture/include/qobject
            cat > fixture/include/qemu/osdep.h <<'OSDEP_FIXTURE'
            #ifndef QEMU_OSDEP_H
            #define QEMU_OSDEP_H

            #include <errno.h>
            #include <limits.h>
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            #define g_autofree

            static inline void *g_malloc(size_t size)
            {
                return malloc(size == 0 ? 1 : size);
            }

            #endif
            OSDEP_FIXTURE

            cat > fixture/include/qemu/cutils.h <<'CUTILS_FIXTURE'
            #ifndef QEMU_CUTILS_H
            #define QEMU_CUTILS_H

            void pstrcpy(char *dst, int dst_size, const char *src);

            #endif
            CUTILS_FIXTURE

            cat > fixture/include/qapi/error.h <<'ERROR_FIXTURE'
            #ifndef QAPI_ERROR_H
            #define QAPI_ERROR_H

            typedef struct Error {
                const char *message;
            } Error;

            static Error *error_abort;

            static inline void error_setg(Error **errp, const char *message)
            {
                static Error error;
                error.message = message;
                if (errp != 0) {
                    *errp = &error;
                }
            }

            #endif
            ERROR_FIXTURE

            cat > fixture/include/qobject/qdict.h <<'QDICT_FIXTURE'
            #ifndef QOBJECT_QDICT_H
            #define QOBJECT_QDICT_H

            #include <stdbool.h>
            #include <stdint.h>

            typedef struct QDict {
                bool has_size;
                uint64_t size;
            } QDict;

            #endif
            QDICT_FIXTURE

            cat > fixture/include/qemu/coroutine.h <<'COROUTINE_FIXTURE'
            #ifndef QEMU_COROUTINE_H
            #define QEMU_COROUTINE_H

            #define coroutine_fn

            void *qemu_coroutine_self(void);
            void qemu_coroutine_yield(void);

            #endif
            COROUTINE_FIXTURE

            cat > fixture/include/qemu/iov.h <<'IOV_FIXTURE'
            #ifndef QEMU_IOV_H
            #define QEMU_IOV_H

            #include <stddef.h>
            #include <stdint.h>

            typedef struct QEMUIOVector {
                uint8_t *base;
                size_t size;
            } QEMUIOVector;

            void qemu_iovec_to_buf(const QEMUIOVector *qiov, size_t offset,
                                   void *buf, size_t bytes);
            void qemu_iovec_from_buf(QEMUIOVector *qiov, size_t offset,
                                     const void *buf, size_t bytes);

            #endif
            IOV_FIXTURE

            cat > fixture/include/qemu/module.h <<'MODULE_FIXTURE'
            #ifndef QEMU_MODULE_H
            #define QEMU_MODULE_H

            #define block_init(function) \
                static void (*function##_fixture_ref)(void) __attribute__((unused)) = function

            #endif
            MODULE_FIXTURE

            cat > fixture/include/qemu/option.h <<'OPTION_FIXTURE'
            #ifndef QEMU_OPTION_H
            #define QEMU_OPTION_H

            #include <stdint.h>
            #include <stdlib.h>

            #define BLOCK_OPT_SIZE "size"
            #define QEMU_OPT_SIZE 1
            #define QTAILQ_HEAD_INITIALIZER(head) 0

            typedef struct QemuOptDesc {
                const char *name;
                int type;
                const char *help;
            } QemuOptDesc;

            typedef struct QemuOptsList {
                const char *name;
                int head;
                QemuOptDesc desc[4];
            } QemuOptsList;

            typedef struct QemuOpts {
                uint64_t size;
            } QemuOpts;

            static inline QemuOpts *qemu_opts_create(QemuOptsList *list,
                                                     const char *id,
                                                     int fail_if_exists,
                                                     Error **errp)
            {
                (void)list;
                (void)id;
                (void)fail_if_exists;
                (void)errp;
                return calloc(1, sizeof(QemuOpts));
            }

            static inline void qemu_opts_absorb_qdict(QemuOpts *opts,
                                                      QDict *options,
                                                      Error **errp)
            {
                (void)errp;
                if (options != 0 && options->has_size) {
                    opts->size = options->size;
                }
            }

            static inline uint64_t qemu_opt_get_size(QemuOpts *opts,
                                                     const char *name,
                                                     uint64_t default_value)
            {
                (void)name;
                return opts->size == 0 ? default_value : opts->size;
            }

            static inline void qemu_opts_del(QemuOpts *opts)
            {
                free(opts);
            }

            #endif
            OPTION_FIXTURE

            cat > fixture/include/block/aio.h <<'AIO_FIXTURE'
            #ifndef BLOCK_AIO_H
            #define BLOCK_AIO_H

            typedef struct AioContext {
                int unused;
            } AioContext;

            void aio_co_schedule(AioContext *ctx, void *co);

            #endif
            AIO_FIXTURE

            cat > fixture/include/block/block-io.h <<'BLOCK_IO_FIXTURE'
            #ifndef BLOCK_BLOCK_IO_H
            #define BLOCK_BLOCK_IO_H
            #endif
            BLOCK_IO_FIXTURE

            cat > fixture/include/block/block_int.h <<'BLOCK_INT_FIXTURE'
            #ifndef BLOCK_BLOCK_INT_H
            #define BLOCK_BLOCK_INT_H

            #include <stddef.h>
            #include <stdint.h>

            #define GRAPH_RDLOCK

            typedef unsigned int BdrvRequestFlags;

            typedef struct BlockDriverState {
                void *opaque;
                struct {
                    uint32_t request_alignment;
                } bl;
                char exact_filename[128];
            } BlockDriverState;

            typedef struct BlockDriver {
                const char *format_name;
                const char *protocol_name;
                size_t instance_size;
                int (*bdrv_open)(BlockDriverState *bs, QDict *options,
                                  int flags, Error **errp);
                int64_t (*bdrv_co_getlength)(BlockDriverState *bs);
                int (*bdrv_co_preadv)(BlockDriverState *bs, int64_t offset,
                                      int64_t bytes, QEMUIOVector *qiov,
                                      BdrvRequestFlags flags);
                int (*bdrv_co_pwritev)(BlockDriverState *bs, int64_t offset,
                                       int64_t bytes, QEMUIOVector *qiov,
                                       BdrvRequestFlags flags);
                int (*bdrv_co_flush_to_disk)(BlockDriverState *bs);
                void (*bdrv_refresh_filename)(BlockDriverState *bs);
            } BlockDriver;

            AioContext *bdrv_get_aio_context(BlockDriverState *bs);
            void bdrv_register(BlockDriver *driver);

            #endif
            BLOCK_INT_FIXTURE

            cp "$microtestSourcePath" phase1-qemu-block-shmem.c
            cc -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter -DCONFIG_PLUGIN \
              -I fixture/include \
              -I include \
              -I . \
              phase1-qemu-block-shmem.c \
              -o phase1-qemu-block-shmem

            mkdir -p "$out"
            ./phase1-qemu-block-shmem > "$out/qemu-block-shmem-microtest"
            grep -q '^PASS$' "$out/qemu-block-shmem-microtest"
            grep -q '^block_driver_registered=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^plugin_callback_registration_exercised=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^read_payload_round_trip=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^write_submit_payload_captured=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^flush_zero_length_success=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^zero_length_success_distinct_from_pending=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^pending_sentinel=-2$' "$out/qemu-block-shmem-microtest"
            grep -q '^poll_sleep_cadence_scheduled=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^poll_sleep_cadence_yielded=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^deterministic_completion_offsets=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^error_completion_fails_closed=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^oversized_completion_fails_closed=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^range_checks_fail_closed=true$' "$out/qemu-block-shmem-microtest"
            grep -q '^stock_negative_control_block_symbols_absent=true$' "$out/qemu-block-shmem-microtest"

            cp stock-block-negative.err "$out/stock-negative-control.err"
            cp block/crucible-shmem.c "$out/crucible-shmem.c.patched"
            cp include/qemu/qemu-plugin.h "$out/qemu-plugin.h.patched"
            cp block/meson.build "$out/block-meson.build.patched"

            cat > "$out/result" <<'RESULT'
            PASS
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:patch-microtests
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            block_driver_fixture_includes_patched_source=true
            block_shmem_driver_registered=true
            block_shmem_driver_scope=system-emulator-only
            block_shmem_callback_registration_exercised=true
            deterministic_completion_microtest=true
            bounded_poll_cadence_microtest=true
            zero_length_success_distinct_from_pending=true
            pending_sentinel=-2
            apply_clean_patch_fuzz=0
            RESULT
          '';
        }
      ];
    }
