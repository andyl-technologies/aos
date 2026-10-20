{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  patchSource = builtins.readFile (patchDir + "/${atomicPatch.file}");

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failures =
    lib.optionals (!(hasInfix "diff --git a/hw/virtio/virtio.c" patchSource)) [
      "${atomicPatch.file}: generic virtio queue-notify patch surface is absent"
    ]
    ++ lib.optionals (!(hasInfix "vdev->device_id == VIRTIO_ID_9P" patchSource)) [
      "${atomicPatch.file}: virtio-9p device selection is absent"
    ]
    ++ lib.optionals (!(hasInfix "vq->host_notifier_enabled &&" patchSource)) [
      "${atomicPatch.file}: host-notifier bypass is absent"
    ]
    ++ lib.optionals (!(hasInfix "Every non-sim launch retains its existing notifier" patchSource)) [
      "${atomicPatch.file}: non-9p preservation rationale is absent"
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU 9p synchronous-kick check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-9p-sync-kick";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.gawk
        pkgs.grep
        pkgs.patch
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "run-qemu-9p-sync-kick-microtest";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            mkdir -p qemu-source "$out"
            tar -xf ${qemuPackage.src} -C qemu-source
            cd qemu-source/qemu-${qemuPackage.version}

            extract_notify_function() {
              source="$1"
              destination="$2"
              gawk '
                /^void virtio_queue_notify\(/ { capture = 1 }
                capture {
                  print
                  opens = gsub(/\{/, "{")
                  closes = gsub(/\}/, "}")
                  depth += opens - closes
                  if (opens > 0) {
                    saw_open = 1
                  }
                  if (saw_open && depth == 0) {
                    exit
                  }
                }
              ' "$source" > "$destination"
              test -s "$destination"
            }

            write_fixture() {
              function_source="$1"
              fixture_source="$2"
              cat > "$fixture_source.head" <<'FIXTURE_HEAD'
            #include <stdbool.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>

            #define unlikely(value) (value)
            #define VIRTIO_ID_BLOCK 2
            #define VIRTIO_ID_RNG 4
            #define VIRTIO_ID_9P 9

            typedef struct EventNotifier {
                unsigned unused;
            } EventNotifier;

            typedef struct VirtIODevice VirtIODevice;
            typedef struct VirtQueue VirtQueue;
            typedef void (*VirtQueueHandler)(VirtIODevice *, VirtQueue *);

            struct VirtQueue {
                struct {
                    void *desc;
                } vring;
                bool host_notifier_enabled;
                EventNotifier host_notifier;
                VirtQueueHandler handle_output;
            };

            struct VirtIODevice {
                VirtQueue *vq;
                bool broken;
                bool start_on_kick;
                uint16_t device_id;
            };

            static bool fixture_icount_enabled;
            static const char *fixture_accel_name;
            static unsigned fixture_notifier_calls;
            static unsigned fixture_handler_calls;

            static bool icount_enabled(void)
            {
                return fixture_icount_enabled;
            }

            static const char *current_accel_name(void)
            {
                return fixture_accel_name;
            }

            static void trace_virtio_queue_notify(
                VirtIODevice *vdev, long index, VirtQueue *vq)
            {
                (void)vdev;
                (void)index;
                (void)vq;
            }

            static void event_notifier_set(EventNotifier *notifier)
            {
                (void)notifier;
                fixture_notifier_calls++;
            }

            static void fixture_handle_output(VirtIODevice *vdev, VirtQueue *vq)
            {
                (void)vdev;
                (void)vq;
                fixture_handler_calls++;
            }

            static void virtio_set_started(VirtIODevice *vdev, bool started)
            {
                (void)vdev;
                (void)started;
            }
            FIXTURE_HEAD

              cat > "$fixture_source.suffix" <<'FIXTURE_SUFFIX'
            int main(int argc, char **argv)
            {
                VirtQueue queue = {
                    .vring = { .desc = &queue },
                    .host_notifier_enabled = true,
                    .handle_output = fixture_handle_output,
                };
                VirtIODevice device = {
                    .vq = &queue,
                };
                unsigned expected_notifier;
                unsigned expected_handler;

                if (argc != 6) {
                    fputs(
                        "usage: fixture ACCEL ICOUNT DEVICE NOTIFIER HANDLER\n",
                        stderr);
                    return 2;
                }
                fixture_accel_name = argv[1];
                fixture_icount_enabled = strcmp(argv[2], "1") == 0;
                if (strcmp(argv[3], "9p") == 0) {
                    device.device_id = VIRTIO_ID_9P;
                } else if (strcmp(argv[3], "rng") == 0) {
                    device.device_id = VIRTIO_ID_RNG;
                } else if (strcmp(argv[3], "block") == 0) {
                    device.device_id = VIRTIO_ID_BLOCK;
                } else {
                    fputs("unknown device\n", stderr);
                    return 2;
                }
                expected_notifier = (unsigned)(argv[4][0] - '0');
                expected_handler = (unsigned)(argv[5][0] - '0');
                virtio_queue_notify(&device, 0);
                if (fixture_notifier_calls != expected_notifier
                    || fixture_handler_calls != expected_handler) {
                    fprintf(
                        stderr,
                        "unexpected dispatch notifier=%u handler=%u\n",
                        fixture_notifier_calls,
                        fixture_handler_calls);
                    return 1;
                }
                printf(
                    "notifier_calls=%u handler_calls=%u\n",
                    fixture_notifier_calls,
                    fixture_handler_calls);
                return 0;
            }
            FIXTURE_SUFFIX

              cat "$fixture_source.head" "$function_source" \
                "$fixture_source.suffix" > "$fixture_source"
              cc -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
                "$fixture_source" -o "$fixture_source.bin"
            }

            extract_notify_function hw/virtio/virtio.c \
              "$TMPDIR/notify-stock.function.c"
            write_fixture "$TMPDIR/notify-stock.function.c" \
              "$TMPDIR/notify-stock.c"

            patch --batch --fuzz=0 -p1 < "${patchDir}/${atomicPatch.file}"
            grep -F -q 'vdev->device_id == VIRTIO_ID_9P' hw/virtio/virtio.c
            extract_notify_function hw/virtio/virtio.c \
              "$TMPDIR/notify-patched.function.c"
            write_fixture "$TMPDIR/notify-patched.function.c" \
              "$TMPDIR/notify-patched.c"

            "$TMPDIR/notify-stock.c.bin" sim 1 9p 1 0 > "$out/stock-sim-9p.txt"
            "$TMPDIR/notify-patched.c.bin" sim 1 9p 0 1 > "$out/patched-sim-9p.txt"
            "$TMPDIR/notify-stock.c.bin" sim 1 rng 1 0 > "$out/stock-sim-rng.txt"
            "$TMPDIR/notify-patched.c.bin" sim 1 rng 1 0 > "$out/patched-sim-rng.txt"
            "$TMPDIR/notify-stock.c.bin" sim 1 block 1 0 > "$out/stock-sim-block.txt"
            "$TMPDIR/notify-patched.c.bin" sim 1 block 0 1 > "$out/patched-sim-block.txt"
            "$TMPDIR/notify-stock.c.bin" tcg 1 9p 1 0 > "$out/stock-tcg-9p.txt"
            "$TMPDIR/notify-patched.c.bin" tcg 1 9p 1 0 > "$out/patched-tcg-9p.txt"
            "$TMPDIR/notify-stock.c.bin" sim 0 9p 1 0 > "$out/stock-sim-no-icount-9p.txt"
            "$TMPDIR/notify-patched.c.bin" sim 0 9p 1 0 > "$out/patched-sim-no-icount-9p.txt"

            cmp -s "$out/stock-sim-9p.txt" "$out/patched-sim-9p.txt" \
              && fail "patched sim 9p dispatch did not differ from stock QEMU"
            cmp -s "$out/stock-sim-block.txt" "$out/patched-sim-block.txt" \
              && fail "patched sim block dispatch did not differ from stock QEMU"
            diff -u "$out/stock-sim-rng.txt" "$out/patched-sim-rng.txt"
            diff -u "$out/stock-tcg-9p.txt" "$out/patched-tcg-9p.txt"
            diff -u "$out/stock-sim-no-icount-9p.txt" "$out/patched-sim-no-icount-9p.txt"
            grep -Fxq 'notifier_calls=1 handler_calls=0' "$out/stock-sim-9p.txt"
            grep -Fxq 'notifier_calls=0 handler_calls=1' "$out/patched-sim-9p.txt"
            grep -Fxq 'notifier_calls=1 handler_calls=0' "$out/stock-sim-block.txt"
            grep -Fxq 'notifier_calls=0 handler_calls=1' "$out/patched-sim-block.txt"

            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:patch-microtests
            atomic_patch=${atomicPatch.file}
            patched_fixture_exercised=true
            stock_negative_control=true
            stock_source_negative_control=true
            patched_exact_source_fixture=true
            sim_icount_9p_kick_synchronous=true
            rng_dispatch_preserved=true
            sim_icount_block_kick_synchronous=true
            plain_tcg_9p_upstream_equivalent=true
            sim_without_icount_9p_upstream_equivalent=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
