{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchName = "0040-crucible-9p-sync-kick.patch";
  series = import (patchDir + "/_series.nix");
  prefixPatchFiles =
    builtins.genList
    (index: builtins.elemAt series.patchFiles index)
    39;
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
    lib.optionals (!(hasInfix "vdev->device_id == VIRTIO_ID_9P" patchSource)) [
      "${patchName}: virtio-9p device selection is absent"
    ]
    ++ lib.optionals (!(hasInfix "vdev->device_id == VIRTIO_ID_RNG" patchSource)) [
      "${patchName}: existing deterministic virtio-rng selection is not preserved"
    ]
    ++ lib.optionals (!(hasInfix "Block I/O keeps the" patchSource)) [
      "${patchName}: block-I/O asynchronous-kick rationale is absent"
    ]
    ++ lib.optionals (
      builtins.length series.patchFiles <= 39
      || builtins.elemAt series.patchFiles 39 != patchName
    ) [
      "${patchName}: 9p synchronous-kick patch is not patch-series entry 40"
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

            for patch in ${builtins.concatStringsSep " " prefixPatchFiles}; do
              patch --batch --fuzz=0 -p1 < "${patchDir}/$patch"
            done

            extract_ioeventfd_function() {
              source="$1"
              destination="$2"
              gawk '
                /^static bool virtio_pci_ioeventfd_enabled\(/ { capture = 1 }
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
              cat > "$fixture_source.prefix" <<'FIXTURE_PREFIX'
            #include <stdbool.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>

            enum {
                VIRTIO_ID_BLOCK = 2,
                VIRTIO_ID_RNG = 4,
                VIRTIO_ID_9P = 9,
                VIRTIO_PCI_FLAG_USE_IOEVENTFD = 1,
            };

            typedef struct VirtIODevice {
                uint16_t device_id;
            } VirtIODevice;

            typedef struct VirtioBusState {
                VirtIODevice *device;
            } VirtioBusState;

            typedef struct VirtIOPCIProxy {
                unsigned flags;
                VirtioBusState bus;
            } VirtIOPCIProxy;

            typedef struct DeviceState {
                VirtIOPCIProxy *proxy;
            } DeviceState;

            static bool fixture_icount_enabled;
            static const char *fixture_accel_name;

            static VirtIOPCIProxy *to_virtio_pci_proxy(DeviceState *device)
            {
                return device->proxy;
            }

            static VirtIODevice *virtio_bus_get_device(VirtioBusState *bus)
            {
                return bus->device;
            }

            static bool icount_enabled(void)
            {
                return fixture_icount_enabled;
            }

            static const char *current_accel_name(void)
            {
                return fixture_accel_name;
            }
            FIXTURE_PREFIX

              cat > "$fixture_source.suffix" <<'FIXTURE_SUFFIX'
            int main(int argc, char **argv)
            {
                VirtIODevice virtio_device = { 0 };
                VirtIOPCIProxy proxy = {
                    .flags = VIRTIO_PCI_FLAG_USE_IOEVENTFD,
                    .bus = { .device = &virtio_device },
                };
                DeviceState device = { .proxy = &proxy };
                bool expected;
                bool actual;

                if (argc != 5) {
                    fputs("usage: fixture ACCEL ICOUNT DEVICE EXPECTED\n", stderr);
                    return 2;
                }
                fixture_accel_name = argv[1];
                fixture_icount_enabled = strcmp(argv[2], "1") == 0;
                if (strcmp(argv[3], "9p") == 0) {
                    virtio_device.device_id = VIRTIO_ID_9P;
                } else if (strcmp(argv[3], "rng") == 0) {
                    virtio_device.device_id = VIRTIO_ID_RNG;
                } else if (strcmp(argv[3], "block") == 0) {
                    virtio_device.device_id = VIRTIO_ID_BLOCK;
                } else {
                    fputs("unknown device\n", stderr);
                    return 2;
                }
                expected = strcmp(argv[4], "1") == 0;
                actual = virtio_pci_ioeventfd_enabled(&device);
                if (actual != expected) {
                    fputs("unexpected ioeventfd selection\n", stderr);
                    return 1;
                }
                printf("ioeventfd_enabled=%s\n", actual ? "true" : "false");
                return 0;
            }
            FIXTURE_SUFFIX

              cat "$fixture_source.prefix" "$function_source" \
                "$fixture_source.suffix" > "$fixture_source"
              cc -std=c11 -O2 -Wall -Wextra -Werror -Wno-unused-function \
                "$fixture_source" -o "$fixture_source.bin"
            }

            extract_ioeventfd_function hw/virtio/virtio-pci.c \
              "$TMPDIR/ioeventfd-prefix.function.c"
            write_fixture "$TMPDIR/ioeventfd-prefix.function.c" \
              "$TMPDIR/ioeventfd-prefix.c"

            patch --batch --fuzz=0 -p1 < "${patchDir}/${patchName}"
            grep -F -q 'vdev->device_id == VIRTIO_ID_9P' hw/virtio/virtio-pci.c
            grep -F -q 'vdev->device_id == VIRTIO_ID_RNG' hw/virtio/virtio-pci.c
            extract_ioeventfd_function hw/virtio/virtio-pci.c \
              "$TMPDIR/ioeventfd-patched.function.c"
            write_fixture "$TMPDIR/ioeventfd-patched.function.c" \
              "$TMPDIR/ioeventfd-patched.c"

            "$TMPDIR/ioeventfd-prefix.c.bin" sim 1 9p 1 > "$out/prefix-sim-9p.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 1 9p 0 > "$out/patched-sim-9p.txt"
            "$TMPDIR/ioeventfd-prefix.c.bin" sim 1 rng 0 > "$out/prefix-sim-rng.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 1 rng 0 > "$out/patched-sim-rng.txt"
            "$TMPDIR/ioeventfd-prefix.c.bin" sim 1 block 1 > "$out/prefix-sim-block.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 1 block 1 > "$out/patched-sim-block.txt"
            "$TMPDIR/ioeventfd-prefix.c.bin" tcg 1 9p 1 > "$out/prefix-tcg-9p.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" tcg 1 9p 1 > "$out/patched-tcg-9p.txt"
            "$TMPDIR/ioeventfd-prefix.c.bin" sim 0 9p 1 > "$out/prefix-sim-no-icount-9p.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 0 9p 1 > "$out/patched-sim-no-icount-9p.txt"

            cmp -s "$out/prefix-sim-9p.txt" "$out/patched-sim-9p.txt" \
              && fail "patched sim 9p selection did not differ from its prefix"
            diff -u "$out/prefix-sim-rng.txt" "$out/patched-sim-rng.txt"
            diff -u "$out/prefix-sim-block.txt" "$out/patched-sim-block.txt"
            diff -u "$out/prefix-tcg-9p.txt" "$out/patched-tcg-9p.txt"
            diff -u "$out/prefix-sim-no-icount-9p.txt" "$out/patched-sim-no-icount-9p.txt"
            grep -Fxq 'ioeventfd_enabled=true' "$out/prefix-sim-9p.txt"
            grep -Fxq 'ioeventfd_enabled=false' "$out/patched-sim-9p.txt"

            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:patch-microtests
            patch=0040-crucible-9p-sync-kick.patch
            prefix_negative_control=true
            patched_exact_source_fixture=true
            sim_icount_9p_kick_synchronous=true
            rng_selection_preserved=true
            block_selection_preserved=true
            plain_tcg_9p_upstream_equivalent=true
            sim_without_icount_9p_upstream_equivalent=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
