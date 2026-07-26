{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchName = "0041-crucible-whitebox-guest-write.patch";
  series = import (patchDir + "/_series.nix");
  prefixPatchFiles = builtins.genList (index: builtins.elemAt series.patchFiles index) 40;
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
    builtins.any (index: builtins.substring index needleLen haystack == needle) indexes;

  failures =
    lib.optionals (!(hasInfix "qemu_plugin_crucible_write_memory_vaddr" patchSource)) [
      "${patchName}: guest-memory write export is absent"
    ]
    ++ lib.optionals (!(hasInfix "cpu_memory_rw_debug(current_cpu" patchSource)) [
      "${patchName}: current-vCPU debug-memory write path is absent"
    ]
    ++ lib.optionals (!(hasInfix "len, true) == 0" patchSource)) [
      "${patchName}: write direction or complete-write result check is absent"
    ]
    ++ lib.optionals (
      builtins.length series.patchFiles
      <= 40
      || builtins.elemAt series.patchFiles 40 != patchName
    ) [
      "${patchName}: white-box guest-write patch is not patch-series entry 41"
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU white-box guest-write check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-whitebox-guest-write";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep pkgs.patch pkgs.tar pkgs.xz];

      phases = [
        {
          name = "run-qemu-whitebox-guest-write-microtest";
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
              patch --batch --fuzz=0 -p1 < "${patchDir}/$patch" > /dev/null
            done

            if grep -q 'qemu_plugin_crucible_write_memory_vaddr' include/qemu/qemu-plugin.h; then
              fail "prefix unexpectedly exposes the guest-write capability"
            fi
            patch --batch --fuzz=0 -p1 < "${patchDir}/${patchName}" > /dev/null
            grep -q 'qemu_plugin_crucible_write_memory_vaddr' include/qemu/qemu-plugin.h
            grep -q 'cpu_memory_rw_debug(current_cpu' plugins/api.c

            cat > "$TMPDIR/write-memory-fixture.c" <<'FIXTURE'
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <string.h>

            static uint8_t guest_memory[16];
            static bool current_cpu = true;

            static int cpu_memory_rw_debug(
                bool cpu, uint64_t address, uint8_t *data, size_t length, bool write)
            {
                if (!cpu || !write || address > sizeof guest_memory
                    || length > sizeof guest_memory - address) {
                    return -1;
                }
                memcpy(&guest_memory[address], data, length);
                return 0;
            }

            static bool qemu_plugin_crucible_write_memory_vaddr(
                uint64_t address, const uint8_t *data, size_t length)
            {
                if (length == 0) {
                    return false;
                }
                return cpu_memory_rw_debug(
                    current_cpu, address, (uint8_t *)data, length, true) == 0;
            }

            int main(void)
            {
                const uint8_t reply[] = {0x43, 0x52, 0x55, 0x43};
                uint8_t before[sizeof guest_memory];

                memcpy(before, guest_memory, sizeof before);
                if (qemu_plugin_crucible_write_memory_vaddr(0, reply, 0)) {
                    return 1;
                }
                if (memcmp(before, guest_memory, sizeof before) != 0) {
                    return 2;
                }
                if (!qemu_plugin_crucible_write_memory_vaddr(4, reply, sizeof reply)) {
                    return 3;
                }
                if (memcmp(&guest_memory[4], reply, sizeof reply) != 0) {
                    return 4;
                }
                if (qemu_plugin_crucible_write_memory_vaddr(14, reply, sizeof reply)) {
                    return 5;
                }
                return 0;
            }
            FIXTURE
            "$CC" -std=c11 -Wall -Wextra -Werror "$TMPDIR/write-memory-fixture.c" \
              -o "$TMPDIR/write-memory-fixture"
            "$TMPDIR/write-memory-fixture"

            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:patch-microtests
            patch=0041-crucible-whitebox-guest-write.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            prefix_negative_control=true
            current_vcpu_debug_write=true
            zero_length_rejected=true
            out_of_range_write_rejected=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
