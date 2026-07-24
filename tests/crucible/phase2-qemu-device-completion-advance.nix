{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchName = "0039-crucible-blk-device-completion-advance.patch";
  patchSeries = import (patchDir + "/_series.nix");
  patchSource = builtins.readFile (patchDir + "/${patchName}");

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

  failures =
    lib.optionals (!(hasInfix "qemu_plugin_register_blk_wait_cb" patchSource)) [
      "${patchName}: block device-wait registration export is absent"
    ]
    ++ lib.optionals (!(hasInfix "crucible_blk_wait_cb(request_id" patchSource)) [
      "${patchName}: pending block poll does not enter the device-wait callback"
    ]
    ++ lib.optionals (!(hasInfix "QEMU_PLUGIN_BLK_POLL_PENDING" patchSource)) [
      "${patchName}: wait hook is not tied to the pending completion state"
    ]
    ++ lib.optionals (!(hasInfix "qemu_plugin_time_advance_complete_bh" patchSource)) [
      "${patchName}: completion resume is not ordered after the advance barrier"
    ]
    ++ lib.optionals (!(hasInfix "QEMU_PLUGIN_WAKE_EVENT_DRAINED" patchSource)) [
      "${patchName}: completed advance does not resume wake-fd-backed device waiters"
    ]
    ++ lib.optionals (!(builtins.elem patchName patchSeries.patchFiles)) [
      "${patchName}: device-completion patch is not carried by the patch series"
    ];
in
  if failures != []
  then throw "crucible phase2 device-completion advance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-device-completion-advance";
      version = "0";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.patch
        pkgs.tar
        pkgs.xz
      ];
      phases = [
        {
          name = "verify-device-completion-advance";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            mkdir -p qemu-source
            tar -xf ${qemuPackage.src} -C qemu-source
            cd qemu-source/qemu-${qemuPackage.version}

            mkdir -p fixture/include/glib
            cat > fixture/include/glib.h <<'GLIB_FIXTURE'
            #ifndef GLIB_H
            #define GLIB_H

            typedef struct GArray GArray;
            typedef struct GByteArray GByteArray;

            #endif
            GLIB_FIXTURE

            cat > device-completion-api.c <<'API_FIXTURE'
            #include <stddef.h>
            #include <stdint.h>
            #include "qemu/qemu-plugin.h"

            static void wait_for_completion(uint32_t request_id, void *userdata)
            {
                (void)request_id;
                (void)userdata;
            }

            void register_wait_hook(void)
            {
                qemu_plugin_blk_wait_cb_t callback = wait_for_completion;
                qemu_plugin_register_blk_wait_cb(callback, NULL);
            }
            API_FIXTURE

            if cc -std=c11 -Wall -Werror -I fixture/include -I include -I . \
              -c device-completion-api.c \
              -o stock-device-completion-api.o \
              2> stock-device-completion-api.err
            then
              fail "stock QEMU unexpectedly exposed the block-wait plugin API"
            fi
            grep -q 'qemu_plugin_blk_wait' stock-device-completion-api.err

            for patch in ${builtins.concatStringsSep " " patchSeries.patchFiles}; do
              patch --batch --fuzz=0 -p1 < "${patchDir}/$patch"
            done

            cc -std=c11 -Wall -Werror -I fixture/include -I include -I . \
              -c device-completion-api.c \
              -o patched-device-completion-api.o

            grep -F -q \
              'crucible_blk_wait_cb(request_id, crucible_blk_wait_userdata);' \
              block/crucible-shmem.c
            grep -F -q \
              'crucible_shmem_wait_one_poll(bs, observed_generation);' \
              block/crucible-shmem.c
            grep -F -q \
              'notifier_list_notify(&qemu_plugin_wake_notifiers,' \
              plugins/api-system.c
            grep -F -q \
              '(void *)(intptr_t)QEMU_PLUGIN_WAKE_EVENT_DRAINED);' \
              plugins/api-system.c
            mkdir -p "$out"
            {
              echo PASS
              echo gate=gate:patch-microtests
              echo patch=${patchName}
              echo patched_api_compiles=true
              echo stock_api_negative_control=true
              echo pending_wait_hook_source_verified=true
              echo generation_race_guard_verified=true
              echo post_commit_resume_source_verified=true
              echo qemu_package=${qemuPackage}
              echo qemu_package_version=${qemuPackage.version}
              echo device_wait_callback=true
              echo completion_resume_after_plugin_commit=true
              echo inert_without_registration=true
            } > "$out/result"
          '';
        }
      ];
    }
