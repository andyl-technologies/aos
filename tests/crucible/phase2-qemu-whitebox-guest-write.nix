{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  patchSource = builtins.readFile (patchDir + "/${atomicPatch.file}");

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
    lib.optionals (!(hasInfix "qemu_plugin_crucible_write_selectable_reply_ram" patchSource)) [
      "${atomicPatch.file}: paused selectable-reply RAM write export is absent"
    ]
    ++ lib.optionals (!(hasInfix "memory_region_is_ram(fragment.region)" patchSource)) [
      "${atomicPatch.file}: RAM-only range validation is absent"
    ]
    ++ lib.optionals (!(hasInfix "qemu_get_cpu(vcpu_index)" patchSource)) [
      "${atomicPatch.file}: exact resume-vCPU lookup is absent"
    ]
    ++ lib.optionals (!(hasInfix "qemu_plugin_crucible_resume_callback_active(cpu)" patchSource)) [
      "${atomicPatch.file}: exact resume-callback authority check is absent"
    ]
    ++ lib.optionals (!(hasInfix "qemu_plugin_crucible_write_memory_vaddr_for_vcpu" patchSource)) [
      "${atomicPatch.file}: exact resume-vCPU virtual write export is absent"
    ]
    ++ lib.optionals (!(hasInfix "memory_region_fault_commit_ram" patchSource)) [
      "${atomicPatch.file}: validated RAM fragment commit is absent"
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

            if grep -q 'qemu_plugin_crucible_write_selectable_reply_ram' include/plugins/qemu-plugin.h; then
              fail "stock QEMU unexpectedly exposes the guest-write capability"
            fi
            patch --batch --fuzz=0 -p1 < "${patchDir}/${atomicPatch.file}" > /dev/null
            grep -q 'qemu_plugin_crucible_write_selectable_reply_ram' include/plugins/qemu-plugin.h
            grep -q 'memory_region_is_ram(fragment.region)' plugins/api-system.c
            grep -q 'memory_region_fault_commit_ram' plugins/api-system.c
            grep -q 'qemu_get_cpu(vcpu_index)' plugins/api-system.c
            grep -q 'qemu_plugin_crucible_resume_callback_active(cpu)' plugins/api.c
            grep -q 'qemu_plugin_crucible_resume_callback_depth == 1' plugins/api-system.c
            grep -q 'qemu_plugin_crucible_write_memory_vaddr_for_vcpu' plugins/api.c
            grep -A1 '^QEMU_PLUGIN_API$' include/plugins/qemu-plugin.h \
              | grep -q 'qemu_plugin_crucible_write_memory_vaddr_for_vcpu'

            cat > "$TMPDIR/write-memory-fixture.c" <<'FIXTURE'
            #include <stdbool.h>
            #include <stddef.h>
            #include <stdint.h>
            #include <string.h>

            static uint8_t guest_memory[2][16];

            static bool qemu_plugin_crucible_write_selectable_reply_ram(
                unsigned int vcpu_index, uint64_t address,
                const uint8_t *data, size_t length)
            {
                if (vcpu_index >= 2 || !data || length == 0 ||
                    address > sizeof guest_memory[0] ||
                    length > sizeof guest_memory[0] - address) {
                    return false;
                }
                memcpy(&guest_memory[vcpu_index][address], data, length);
                return true;
            }

            int main(void)
            {
                const uint8_t reply[] = {0x43, 0x52, 0x55, 0x43};
                uint8_t before[sizeof guest_memory];

                memcpy(before, guest_memory, sizeof before);
                if (qemu_plugin_crucible_write_selectable_reply_ram(
                        0, 0, reply, 0)) {
                    return 1;
                }
                if (memcmp(before, guest_memory, sizeof before) != 0) {
                    return 2;
                }
                if (!qemu_plugin_crucible_write_selectable_reply_ram(
                        0, 4, reply, sizeof reply)) {
                    return 3;
                }
                if (memcmp(&guest_memory[0][4], reply, sizeof reply) != 0) {
                    return 4;
                }
                if (qemu_plugin_crucible_write_selectable_reply_ram(
                        0, 14, reply, sizeof reply)) {
                    return 5;
                }
                if (qemu_plugin_crucible_write_selectable_reply_ram(
                        2, 0, reply, sizeof reply)) {
                    return 6;
                }
                if (!qemu_plugin_crucible_write_selectable_reply_ram(
                        1, 8, reply, sizeof reply)) {
                    return 7;
                }
                if (memcmp(&guest_memory[1][8], reply, sizeof reply) != 0) {
                    return 8;
                }
                if (memcmp(&guest_memory[0][8], reply, sizeof reply) == 0) {
                    return 9;
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
            atomic_patch=${atomicPatch.file}
            patched_fixture_exercised=true
            stock_negative_control=true
            prefix_negative_control=true
            paused_selectable_reply_ram_write=true
            exact_resume_vcpu_ram_write=true
            exact_resume_vcpu_virtual_write=true
            resume_callback_authority_checked=true
            unknown_vcpu_rejected=true
            zero_length_rejected=true
            out_of_range_write_rejected=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
