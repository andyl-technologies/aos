{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0032-crucible-det-virtio-ioeventfd.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
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
  qemuRuntimeResultLines =
    if qemuPackage == null
    then ''
      det_virtio_ioeventfd_runtime_exercised=false
    ''
    else ''
      det_virtio_ioeventfd_runtime_exercised=true
      det_virtio_ioeventfd_exact_source_fixture=passed
      det_virtio_ioeventfd_stock_vs_patched_discriminated=true
      det_virtio_ioeventfd_plain_icount_upstream_equivalent=true
      det_virtio_device_realization_boot_smoke=passed
    '';

  # Supplemental smoke probe: under the sim accelerator and -icount, boot a
  # stock guest with a virtio-rng-pci device and confirm the device realizes and
  # the VM reaches `running`. The exact-source fixture below separately compiles
  # the stock and patched virtio_pci_ioeventfd_enabled implementations and
  # exercises their actual virtio-rng selection result. The
  # crucible-det-virtio-ioeventfd patch makes virtio_pci_ioeventfd_enabled()
  # return false under sim-mode icount for virtio-rng and virtio-blk devices,
  # so a guest-issued virtqueue kick is serviced synchronously on the requesting
  # vCPU thread rather than via a host-scheduled main-loop dispatch. This patch
  # leaves 9p unchanged; the later 0040 patch synchronizes 9p and block kicks
  # after their forwarding gaps are characterized. This supplemental smoke proves only that the patched device
  # realizes and QEMU executes; the exact-source fixture and the real `/dev/hwrng`
  # request in the paired det-rng-delivery gate exercise the dispatch decision.
  # The effective ioeventfd
  # decision is a runtime override of the qdev flag and is not exposed as a QMP
  # property, so the icount gate itself is asserted structurally against the
  # patched virtio_pci_ioeventfd_enabled() below. This is the dispatch hop of the
  # two-hop synchronous entropy-completion seal; the backend hop is the
  # crucible-det-rng-delivery microtest. The end-to-end determinism property is
  # witnessed by checks.crucible.phase0.s6KaslrAslr and
  # checks.crucible.phase1.guestEntropyLaunch.
  qemuRuntimeScript =
    if qemuPackage == null
    then ''
      echo "qemuPackage=null; runtime virtio ioeventfd exercise skipped" > "$out/runtime-skipped.txt"
    ''
    else ''
      qemu="${qemuPackage}/bin/qemu-system-x86_64"
      qemu_pid=""

      fail() {
        echo "FAIL: $*" >&2
        exit 1
      }

      cleanup_qemu() {
        if [ -n "''${qemu_pid:-}" ]; then
          kill "$qemu_pid" 2>/dev/null || true
          wait "$qemu_pid" 2>/dev/null || true
          qemu_pid=""
        fi
      }

      trap cleanup_qemu EXIT

      qmp_cmd() {
        socket="$1"
        request="$2"
        response="$3"
        response_err="$response.err"
        attempts=0
        while [ "$attempts" -lt 100 ]; do
          {
            printf '{"execute":"qmp_capabilities"}\r\n'
            printf '%s\r\n' "$request"
          } | socat -T 2 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

          if [ -s "$response" ] \
            && ! jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null \
            && jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null
          then
            return 0
          fi
          sleep 0.1
          attempts=$((attempts + 1))
        done

        cat "$response_err" >&2 || true
        cat "$response" >&2 || true
        return 1
      }

      wait_for_socket() {
        socket="$1"
        waited=0
        while [ "$waited" -lt 300 ]; do
          if [ -S "$socket" ]; then
            return 0
          fi
          sleep 0.1
          waited=$((waited + 1))
        done
        return 1
      }

      socket="$TMPDIR/ioeventfd.qmp"
      stdout="$out/ioeventfd.stdout"
      stderr="$out/ioeventfd.stderr"
      rm -f "$socket" "$stdout" "$stderr"

      # A running (no -S) icount launch proves that the virtio-rng device realizes
      # and the VM reaches `running` without error. It does not claim that a guest
      # driver submitted a virtqueue request; the paired det-rng-delivery gate owns
      # that behavioral witness.
      timeout 60 "$qemu" \
        -nodefaults \
        -no-user-config \
        -display none \
        -monitor none \
        -machine q35 \
        -accel sim \
        -icount shift=0,sleep=off,align=off \
        -cpu qemu64,-rdrand,-rdseed \
        -m 128 \
        -smp 1 \
        -rtc base=2026-01-01T00:00:00,clock=vm \
        -seed 0x0010c032 \
        -object rng-builtin,id=det-rng0 \
        -device virtio-rng-pci,rng=det-rng0,id=det-vrng0 \
        -serial none \
        -qmp "unix:$socket,server=on,wait=off" \
        -no-reboot \
        > "$stdout" 2> "$stderr" &
      qemu_pid="$!"

      wait_for_socket "$socket" || {
        cat "$stderr" >&2 || true
        fail "virtio ioeventfd QMP socket did not appear under icount"
      }

      # The device must be present (realized) and the VM must be executing.
      qmp_cmd "$socket" '{"execute":"query-status"}' "$out/ioeventfd.status.json" \
        || fail "query-status failed under sim-mode icount"
      status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$out/ioeventfd.status.json")
      if [ "$status" != "running" ]; then
        cat "$out/ioeventfd.status.json" >&2 || true
        fail "VM status is '$status' under icount, expected 'running'"
      fi
      # Reaching `running` implies the virtio-rng-pci device realized: a failed
      # device realization aborts QEMU before the QMP monitor comes up.

      qmp_cmd "$socket" '{"execute":"quit"}' "$out/ioeventfd.quit.json" >/dev/null 2>&1 || true
      wait "$qemu_pid" || true
      qemu_pid=""
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

  qemuNixRequirements = [
    {
      label = "det virtio ioeventfd patch wiring";
      needle = "patch -p1 < \${./qemu-patches/0032-crucible-det-virtio-ioeventfd.patch}";
    }
  ];

  patchRequirements = [
    {
      label = "ioeventfd predicate function";
      needle = "static bool virtio_pci_ioeventfd_enabled(DeviceState *d)";
    }
    {
      label = "icount gate include";
      needle = "system/cpu-timers.h";
    }
    {
      label = "sim-icount-gated disable";
      needle = "if (icount_enabled() && strcmp(current_accel_name(), \"sim\") == 0) {";
    }
    {
      label = "sim-accelerator gate include";
      needle = "qemu/accel.h";
    }
    {
      label = "virtio-rng scoping lookup";
      needle = "VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);";
    }
    {
      label = "virtio-rng device-id gate";
      needle = "vdev->device_id == VIRTIO_ID_RNG";
    }
    {
      label = "virtio-blk device-id gate";
      needle = "vdev->device_id == VIRTIO_ID_BLOCK";
    }
    {
      label = "synchronous dispatch return";
      needle = "return false;";
    }
    {
      label = "upstream default preserved";
      needle = "(proxy->flags & VIRTIO_PCI_FLAG_USE_IOEVENTFD) != 0";
    }
    {
      label = "no record/replay rationale";
      needle = "RFC-0010 NG-6";
    }
    {
      label = "paired backend seal cross-reference";
      needle = "15-io-subnodes.md";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements;
in
  if failures != []
  then throw "crucible phase1 det-virtio-ioeventfd check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-det-virtio-ioeventfd";
      version = "0";
      src = null;

      inherit patchSource;
      passAsFile = ["patchSource"];

      buildDeps =
        [
          pkgs.coreutils
          pkgs.diffutils
          pkgs.gawk
          pkgs.grep
          pkgs.jq
          pkgs.patch
          pkgs.socat
          pkgs.tar
          pkgs.xz
        ]
        ++ lib.optionals (qemuPackage != null) [qemuPackage];

      phases = [
        {
          name = "run-det-virtio-ioeventfd-microtest";
          script = ''
            set -eu

            mkdir -p "$out"

            apply_dir="$TMPDIR/qemu-det-virtio-ioeventfd-apply"
            mkdir -p "$apply_dir"
            tar -xf ${pkgs.qemu-crucible.src} -C "$apply_dir"
            source_dir="$apply_dir/qemu-${pkgs.qemu-crucible.version}"

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

            write_ioeventfd_fixture() {
              implementation="$1"
              function_source="$2"
              fixture_source="$3"

              cat > "$fixture_source.prefix" <<'FIXTURE_PREFIX'
            #include <stdbool.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            enum {
                VIRTIO_ID_RNG = 4,
                VIRTIO_ID_BLOCK = 2,
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

                if (argc != 6) {
                    fputs("usage: fixture ACCEL ICOUNT DEVICE FLAG EXPECTED\n",
                          stderr);
                    return 2;
                }
                fixture_accel_name = argv[1];
                fixture_icount_enabled = strcmp(argv[2], "1") == 0;
                if (strcmp(argv[3], "rng") == 0) {
                    virtio_device.device_id = VIRTIO_ID_RNG;
                } else if (strcmp(argv[3], "block") == 0) {
                    virtio_device.device_id = VIRTIO_ID_BLOCK;
                } else if (strcmp(argv[3], "none") == 0) {
                    proxy.bus.device = NULL;
                } else {
                    fputs("unknown device\n", stderr);
                    return 2;
                }
                proxy.flags = strcmp(argv[4], "1") == 0
                    ? VIRTIO_PCI_FLAG_USE_IOEVENTFD : 0;
                expected = strcmp(argv[5], "1") == 0;

                actual = virtio_pci_ioeventfd_enabled(&device);
                if (actual != expected) {
                    fputs("unexpected ioeventfd selection\n", stderr);
                    return 1;
                }

                printf("accel=%s\n", fixture_accel_name);
                printf("icount=%s\n", fixture_icount_enabled ? "on" : "off");
                printf("device=%s\n", argv[3]);
                printf("configured_ioeventfd=%s\n",
                       proxy.flags != 0 ? "true" : "false");
                printf("ioeventfd_enabled=%s\n", actual ? "true" : "false");
                return 0;
            }
            FIXTURE_SUFFIX

              cat "$fixture_source.prefix" "$function_source" \
                "$fixture_source.suffix" > "$fixture_source"
              cc -std=c11 -O2 -Wall -Wextra -Werror \
                -Wno-unused-function -D"FIXTURE_IMPLEMENTATION=$implementation" \
                "$fixture_source" -o "$fixture_source.bin"
            }

            extract_ioeventfd_function "$source_dir/hw/virtio/virtio-pci.c" \
              "$TMPDIR/ioeventfd-stock.function.c"
            write_ioeventfd_fixture stock "$TMPDIR/ioeventfd-stock.function.c" \
              "$TMPDIR/ioeventfd-stock.c"

            if grep -R -q 'current_accel_name(), "sim"' "$source_dir"/hw/virtio/virtio-pci.c 2>/dev/null; then
              echo "stock virtio-pci already gates ioeventfd on the sim accelerator" >&2
              exit 1
            fi

            (
              cd "$source_dir"
              patch --batch --fuzz=0 -p1 < "$patchSourcePath"
              grep -F -q 'static bool virtio_pci_ioeventfd_enabled(DeviceState *d)' hw/virtio/virtio-pci.c
              grep -F -q 'if (icount_enabled() && strcmp(current_accel_name(), "sim") == 0) {' hw/virtio/virtio-pci.c
              grep -F -q '#include "qemu/accel.h"' hw/virtio/virtio-pci.c
              grep -F -q 'VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);' hw/virtio/virtio-pci.c
              grep -F -q 'vdev->device_id == VIRTIO_ID_RNG' hw/virtio/virtio-pci.c
              grep -F -q 'vdev->device_id == VIRTIO_ID_BLOCK' hw/virtio/virtio-pci.c
              grep -F -q '#include "system/cpu-timers.h"' hw/virtio/virtio-pci.c
              grep -F -q '(proxy->flags & VIRTIO_PCI_FLAG_USE_IOEVENTFD) != 0' hw/virtio/virtio-pci.c
            )

            extract_ioeventfd_function "$source_dir/hw/virtio/virtio-pci.c" \
              "$TMPDIR/ioeventfd-patched.function.c"
            write_ioeventfd_fixture patched "$TMPDIR/ioeventfd-patched.function.c" \
              "$TMPDIR/ioeventfd-patched.c"

            "$TMPDIR/ioeventfd-stock.c.bin" sim 1 rng 1 1 > "$out/stock-sim-rng.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 1 rng 1 0 > "$out/patched-sim-rng.txt"
            "$TMPDIR/ioeventfd-stock.c.bin" tcg 1 rng 1 1 > "$out/stock-plain-icount-rng.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" tcg 1 rng 1 1 > "$out/patched-plain-icount-rng.txt"
            "$TMPDIR/ioeventfd-stock.c.bin" sim 0 rng 1 1 > "$out/stock-sim-no-icount-rng.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 0 rng 1 1 > "$out/patched-sim-no-icount-rng.txt"
            "$TMPDIR/ioeventfd-stock.c.bin" sim 1 block 1 1 > "$out/stock-sim-block.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 1 block 1 0 > "$out/patched-sim-block.txt"
            "$TMPDIR/ioeventfd-stock.c.bin" sim 1 none 1 1 > "$out/stock-sim-no-device.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 1 none 1 1 > "$out/patched-sim-no-device.txt"
            "$TMPDIR/ioeventfd-stock.c.bin" sim 1 rng 0 0 > "$out/stock-sim-rng-disabled.txt"
            "$TMPDIR/ioeventfd-patched.c.bin" sim 1 rng 0 0 > "$out/patched-sim-rng-disabled.txt"

            if cmp -s "$out/stock-sim-rng.txt" "$out/patched-sim-rng.txt"; then
              echo "patched sim virtio-rng selection did not differ from stock" >&2
              exit 1
            fi
            if cmp -s "$out/stock-sim-block.txt" "$out/patched-sim-block.txt"; then
              echo "patched sim virtio-blk selection did not differ from stock" >&2
              exit 1
            fi
            diff -u "$out/stock-plain-icount-rng.txt" "$out/patched-plain-icount-rng.txt"
            diff -u "$out/stock-sim-no-icount-rng.txt" "$out/patched-sim-no-icount-rng.txt"
            diff -u "$out/stock-sim-no-device.txt" "$out/patched-sim-no-device.txt"
            diff -u "$out/stock-sim-rng-disabled.txt" "$out/patched-sim-rng-disabled.txt"
            grep -q '^ioeventfd_enabled=true$' "$out/stock-sim-rng.txt"
            grep -q '^ioeventfd_enabled=false$' "$out/patched-sim-rng.txt"
            grep -q '^ioeventfd_enabled=true$' "$out/stock-sim-block.txt"
            grep -q '^ioeventfd_enabled=false$' "$out/patched-sim-block.txt"

            ${qemuRuntimeScript}

            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.detVirtioIoeventfd
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-1
            patch=0032-crucible-det-virtio-ioeventfd.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            stock_vs_patched_sim_rng_discriminated=true
            plain_icount_rng_matches_upstream=true
            sim_without_icount_rng_matches_upstream=true
            sim_icount_block_ioeventfd_disabled=true
            unselected_sim_icount_matches_upstream=true
            configured_ioeventfd_off_matches_upstream=true
            exact_ioeventfd_predicate_exercised=true
            seal_hop=dispatch
            paired_backend_seal=0031-crucible-det-rng-delivery.patch
            e2e_witness=checks.crucible.phase0.s6KaslrAslr
            e2e_witness=checks.crucible.phase1.guestEntropyLaunch
            ${qemuPackageResultLines}
            ${qemuRuntimeResultLines}
            RESULT
          '';
        }
      ];
    }
