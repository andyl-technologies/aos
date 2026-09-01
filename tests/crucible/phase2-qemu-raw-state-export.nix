{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
}: let
  patchSource = builtins.readFile ../../pkgs/emulation/qemu-patches/0036-crucible-raw-state-export.patch;
  incomingSetupSealBeforeMutation = builtins.concatStringsSep "\n" [
    "@@ -697,6 +701,12 @@ migration_incoming_state_setup(MigrationIncomingState *mis, Error **errp)"
    " {"
    "     MigrationStatus current = mis->state;"
    " "
    "+    if (migration_crucible_raw_state_export_sealed()) {"
    "+        error_setg(errp,"
    "+                   \"incoming migration rejected during terminal Crucible \""
    "+                   \"raw-state export\");"
    "+        return false;"
    "+    }"
    "     if (current == MIGRATION_STATUS_POSTCOPY_PAUSED) {"
  ];
  requiredPatchNeedles = [
    "qemu_plugin_crucible_guest_ram_regions("
    "qemu_plugin_crucible_guest_ram_region_copy("
    "qemu_plugin_crucible_vmstate_snapshot_begin("
    "flatview_for_each_section(view, crucible_collect_ram_region, &state);"
    "section->readonly"
    "crucible_terminal_vmstate_export_latched = true;"
    "VM resume rejected after terminal Crucible VMState export"
    "VM reset rejected after terminal Crucible VMState export"
    "vCPU execution rejected after terminal Crucible VMState export"
    "int qemu_loadvm_state_main(QEMUFile *f, MigrationIncomingState *mis)"
    "migration_crucible_raw_state_export_admit()"
    "crucible_active_loaders != 0 || migration_is_running()"
    "migration_crucible_load_begin()"
    incomingSetupSealBeforeMutation
  ];
  hasInfix = needle: haystack: let
    needleLength = builtins.stringLength needle;
    haystackLength = builtins.stringLength haystack;
    finalStart = haystackLength - needleLength;
    starts =
      if needleLength == 0
      then [0]
      else if finalStart < 0
      then []
      else builtins.genList (index: index) (finalStart + 1);
  in
    builtins.any (index: builtins.substring index needleLength haystack == needle) starts;
  missingPatchNeedles = lib.filter (needle: !(hasInfix needle patchSource)) requiredPatchNeedles;
in
  if missingPatchNeedles != []
  then throw "crucible raw-state export patch is incomplete: ${builtins.concatStringsSep ", " missingPatchNeedles}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-raw-state-export";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
        pkgs.glib
        pkgs.glib.dev
        pkgs.grep
        pkgs.jq
        pkgs.pkg-config
        pkgs.socat
        qemuPackage
        referenceQemu
      ];

      phases = [
        {
          name = "run-raw-state-export";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            cat > raw-state-probe.c <<'PROBE'
            #include <errno.h>
            #include <inttypes.h>
            #include <stdbool.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>

            #include <qemu-plugin.h>

            QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

            static const char *result_path;
            static bool completed;

            enum {
              COPY_CHUNK_BYTES = 1024 * 1024,
            };

            static const uint64_t fixture_writable_bytes =
                UINT64_C(64) * 1024 * 1024 - UINT64_C(64) * 1024;
            static const uint64_t readonly_alias_base = UINT64_C(0xf0000);
            static const uint64_t readonly_alias_length = UINT64_C(0x10000);

            static void
            fail_probe(const char *message, int status)
            {
              FILE *result = fopen(result_path, "w");

              if (result != NULL) {
                fprintf(result, "failure=%s\nstatus=%d\n", message, status);
                fclose(result);
              }
              qemu_plugin_outs("crucible raw-state probe failed\n");
              qemu_plugin_request_shutdown(1);
            }

            static uint64_t
            next_boundary(void *userdata)
            {
              (void)userdata;
              return 256;
            }

            static int
            hash_region(const struct qemu_plugin_crucible_ram_region *region,
                        uint64_t *hash)
            {
              uint8_t *buffer = malloc(COPY_CHUNK_BYTES);
              uint64_t offset = 0;

              if (buffer == NULL) {
                return -ENOMEM;
              }
              while (offset < region->length) {
                uint64_t remaining = region->length - offset;
                uint64_t chunk = remaining < COPY_CHUNK_BYTES
                                     ? remaining
                                     : COPY_CHUNK_BYTES;
                int status = qemu_plugin_crucible_guest_ram_region_copy(
                    region, offset, buffer, chunk);

                if (status != 0) {
                  free(buffer);
                  return status;
                }
                for (uint64_t index = 0; index < chunk; index++) {
                  *hash ^= buffer[index];
                  *hash *= UINT64_C(1099511628211);
                }
                offset += chunk;
              }
              free(buffer);
              return 0;
            }

            static void
            export_at_terminal_boundary(int terminal_status, void *userdata)
            {
              struct qemu_plugin_crucible_vmstate_snapshot *snapshot = NULL;
              struct qemu_plugin_crucible_vmstate_snapshot *duplicate = NULL;
              struct qemu_plugin_crucible_ram_region *regions = NULL;
              struct qemu_plugin_crucible_ram_region stale;
              struct qemu_plugin_crucible_ram_region undersized;
              uint8_t untouched = 0xa5;
              uint8_t *vmstate = NULL;
              uint64_t count = 0;
              uint64_t ram_hash = UINT64_C(14695981039346656037);
              uint64_t ram_total = 0;
              uint64_t vmstate_size = 0;
              char size_failure[128];
              char total_failure[160];
              int status;
              FILE *result;

              (void)userdata;
              if (terminal_status != 0) {
                fail_probe("terminal paused callback failed", terminal_status);
                return;
              }
              status = qemu_plugin_crucible_guest_ram_regions(NULL, 0, &count);
              if (status != -ENOSPC || count != 2 ||
                  count > SIZE_MAX / sizeof(*regions)) {
                fail_probe("RAM sizing query failed", status);
                return;
              }
              memset(&undersized, 0xa5, sizeof(undersized));
              {
                uint64_t required = count;

                status = qemu_plugin_crucible_guest_ram_regions(
                    &undersized, count - 1, &required);
                if (status != -ENOSPC || required != count ||
                    ((const uint8_t *)&undersized)[0] != 0xa5) {
                  fail_probe("undersized RAM descriptor query was not atomic",
                             status);
                  return;
                }
              }
              regions = calloc((size_t)count, sizeof(*regions));
              if (regions == NULL) {
                fail_probe("RAM descriptor allocation failed", -ENOMEM);
                return;
              }
              status = qemu_plugin_crucible_guest_ram_regions(regions, count, &count);
              if (status != 0) {
                fail_probe("RAM enumeration failed", status);
                free(regions);
                return;
              }
              if (count != 2 || regions[0].guest_physical_base != 0 ||
                  regions[0].length != readonly_alias_base ||
                  regions[1].guest_physical_base !=
                      readonly_alias_base + readonly_alias_length ||
                  regions[1].length !=
                      UINT64_C(64) * 1024 * 1024 -
                          (readonly_alias_base + readonly_alias_length)) {
                fail_probe("RAM descriptors do not exactly cover fixture GPAs",
                           -ENODATA);
                free(regions);
                return;
              }
              for (uint64_t index = 0; index < count; index++) {
                uint64_t end;

                if (regions[index].length == 0 ||
                    regions[index].memory_region_name[0] == '\0' ||
                    memchr(regions[index].memory_region_name, '\0',
                           sizeof(regions[index].memory_region_name)) == NULL ||
                    regions[index].length >
                        UINT64_MAX - regions[index].guest_physical_base) {
                  fail_probe("RAM descriptor is malformed", -EOVERFLOW);
                  free(regions);
                  return;
                }
                end = regions[index].guest_physical_base + regions[index].length;
                if (index != 0 &&
                    regions[index - 1].length >
                        UINT64_MAX - regions[index - 1].guest_physical_base) {
                  fail_probe("RAM predecessor end overflows", -EOVERFLOW);
                  free(regions);
                  return;
                }
                if (index != 0 &&
                    regions[index - 1].guest_physical_base +
                            regions[index - 1].length >
                        regions[index].guest_physical_base) {
                  fail_probe("RAM descriptors are not GPA sorted", -EINVAL);
                  free(regions);
                  return;
                }
                if (regions[index].guest_physical_base <
                        readonly_alias_base + readonly_alias_length &&
                    readonly_alias_base < end) {
                  fail_probe("read-only PAM alias was exported as writable", -EROFS);
                  free(regions);
                  return;
                }
                if (strcmp(regions[index].memory_region_name, "pc.ram") != 0) {
                  fail_probe("RAM descriptor did not retain leaf-region identity",
                             -ENODATA);
                  free(regions);
                  return;
                }
                if (regions[index].length > UINT64_MAX - ram_total) {
                  fail_probe("RAM total overflows", -EOVERFLOW);
                  free(regions);
                  return;
                }
                ram_total += regions[index].length;
                status = hash_region(&regions[index], &ram_hash);
                if (status != 0) {
                  fail_probe("full RAM descriptor copy failed", status);
                  free(regions);
                  return;
                }
              }
              if (ram_total != fixture_writable_bytes) {
                snprintf(total_failure, sizeof(total_failure),
                         "writable RAM total mismatch: actual=%" PRIu64
                         " expected=%" PRIu64 " descriptors=%" PRIu64,
                         ram_total, fixture_writable_bytes, count);
                fail_probe(total_failure, -ENODATA);
                free(regions);
                return;
              }
              status = qemu_plugin_crucible_guest_ram_region_copy(
                  &regions[0], regions[0].length, &untouched, 1);
              if (status != -ERANGE || untouched != 0xa5) {
                fail_probe("RAM bounds failure modified the destination", status);
                free(regions);
                return;
              }
              stale = regions[0];
              stale.length--;
              status = qemu_plugin_crucible_guest_ram_region_copy(
                  &stale, 0, NULL, 0);
              if (status != -ESTALE) {
                fail_probe("RAM identity drift was accepted", status);
                free(regions);
                return;
              }

              status = qemu_plugin_crucible_vmstate_snapshot_begin(&snapshot);
              if (status != 0 || snapshot == NULL) {
                fail_probe("terminal VMState snapshot failed", status);
                free(regions);
                return;
              }
              status = qemu_plugin_crucible_vmstate_snapshot_size(
                  snapshot, &vmstate_size);
              if (status != 0 || vmstate_size < 9 || vmstate_size > SIZE_MAX) {
                snprintf(size_failure, sizeof(size_failure),
                         "VMState snapshot size is invalid: %" PRIu64,
                         vmstate_size);
                fail_probe(size_failure, status);
                qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
                free(regions);
                return;
              }
              vmstate = malloc((size_t)vmstate_size);
              if (vmstate == NULL) {
                fail_probe("VMState allocation failed", -ENOMEM);
                qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
                free(regions);
                return;
              }
              status = qemu_plugin_crucible_vmstate_snapshot_copy(
                  snapshot, 0, vmstate, vmstate_size);
              if (status != 0 || vmstate[0] != 0x51 || vmstate[1] != 0x45 ||
                  vmstate[2] != 0x56 || vmstate[3] != 0x4d) {
                fail_probe("VMState exact bytes lack the QEMU stream header", status);
                free(vmstate);
                qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
                free(regions);
                return;
              }
              status = qemu_plugin_crucible_vmstate_snapshot_copy(
                  snapshot, vmstate_size, &untouched, 1);
              if (status != -ERANGE || untouched != 0xa5) {
                fail_probe("VMState bounds failure modified the destination", status);
                free(vmstate);
                qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
                free(regions);
                return;
              }
              status = qemu_plugin_crucible_vmstate_snapshot_begin(&duplicate);
              if (status != -EALREADY || duplicate != NULL) {
                fail_probe("VMState export was not one-shot", status);
                free(vmstate);
                qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
                free(regions);
                return;
              }
              status = qemu_plugin_crucible_guest_ram_regions(NULL, 0, &count);
              if (status != -ESHUTDOWN) {
                fail_probe("RAM export remained available after VMState pre_save", status);
                free(vmstate);
                qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
                free(regions);
                return;
              }

              result = fopen(result_path, "w");
              if (result == NULL) {
                free(vmstate);
                qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
                free(regions);
                return;
              }
              fprintf(result,
                      "raw_state_export_passed=true\n"
                      "ram_gpa_ordered=true\n"
                      "ram_full_copy_hashed=true\n"
                      "ram_readonly_alias_excluded=true\n"
                      "ram_rom_excluded=true\n"
                      "ram_exact_total=%" PRIu64 "\n"
                      "ram_fnv1a64=%016" PRIx64 "\n"
                      "ram_bounds_fail_closed=true\n"
                      "ram_identity_drift_rejected=true\n"
                      "vmstate_terminal_one_shot=true\n"
                      "vmstate_exact_bytes=%" PRIu64 "\n",
                      ram_total, ram_hash, vmstate_size);
              fclose(result);
              free(vmstate);
              qemu_plugin_crucible_vmstate_snapshot_free(snapshot);
              free(regions);
            }

            static void
            observe_boundary(uint64_t current_icount, void *userdata)
            {
              uint64_t count = 0;
              int status;

              (void)userdata;
              if (completed || current_icount < 256) {
                return;
              }
              completed = true;
              status = qemu_plugin_crucible_guest_ram_regions(NULL, 0, &count);
              if (status != -EBUSY) {
                fail_probe("running-state RAM enumeration did not fail busy", status);
                return;
              }
              status = qemu_plugin_crucible_request_terminal_pause(
                  export_at_terminal_boundary, NULL);
              if (status != 0) {
                fail_probe("terminal pause request failed", status);
              }
            }

            QEMU_PLUGIN_EXPORT int
            qemu_plugin_install(qemu_plugin_id_t id,
                                const qemu_info_t *info,
                                int argc,
                                char **argv)
            {
              (void)id;
              (void)info;

              if (argc != 1 || strncmp(argv[0], "out=", 4) != 0 || argv[0][4] == '\0') {
                return -1;
              }
              result_path = argv[0] + 4;
              qemu_plugin_register_sim_shmem_observer_cb(
                  observe_boundary, next_boundary, NULL);
              return 0;
            }
            PROBE

            cat > raw-state-bios.S <<'BIOS'
            .code16
            .section .text
            .global _start
            _start:
              cli
              movl $0x80000090, %eax
              movw $0x0cf8, %dx
              outl %eax, %dx
              movw $0x0cfc, %dx
              movb $0x10, %al
              outb %al, %dx
              movb $0x33, %al
              incw %dx
              outb %al, %dx
              incw %dx
              outb %al, %dx
              incw %dx
              outb %al, %dx
              movl $0x80000094, %eax
              movw $0x0cf8, %dx
              outl %eax, %dx
              movw $0x0cfc, %dx
              movb $0x33, %al
              outb %al, %dx
              incw %dx
              outb %al, %dx
              incw %dx
              outb %al, %dx
            1:
              nop
              jmp 1b

            .org 0xfff0
              jmp _start
            .org 0x10000
            BIOS

            glib_cflags=$(pkg-config --cflags glib-2.0)
            $CC -std=c11 -shared -fPIC -Wall -Wextra -Werror $glib_cflags \
              -I${qemuPackage}/include raw-state-probe.c -o raw-state-probe.so
            $CC -m32 -c raw-state-bios.S -o raw-state-bios.o
            objcopy -O binary -j .text raw-state-bios.o raw-state-bios.bin
            test "$(wc -c < raw-state-bios.bin)" -eq 65536 \
              || fail "raw-state fixture BIOS is not exactly 64 KiB"

            if grep -q 'qemu_plugin_crucible_guest_ram_regions' \
              ${referenceQemu}/include/qemu-plugin.h; then
              fail "stock QEMU unexpectedly declared the raw-state export API"
            fi

            socket="$TMPDIR/raw-state-qmp.sock"
            result="$TMPDIR/raw-state-result"
            stderr_log="$TMPDIR/raw-state-qemu.stderr"

            ${qemuPackage}/bin/qemu-system-x86_64 \
              -nodefaults -no-user-config -display none -monitor none -serial none \
              -machine q35 -accel sim,thread=single \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum=4096 \
              -cpu qemu64,-rdrand,-rdseed -smp 1 -m 64M \
              -bios "$PWD/raw-state-bios.bin" \
              -qmp "unix:$socket,server=on,wait=off" \
              -plugin "$PWD/raw-state-probe.so,out=$result" \
              -no-reboot -no-shutdown \
              > "$TMPDIR/raw-state-qemu.stdout" 2> "$stderr_log" &
            qemu_pid=$!
            trap 'kill "$qemu_pid" 2>/dev/null || true' EXIT

            attempts=0
            while [ ! -s "$result" ] && [ "$attempts" -lt 300 ]; do
              kill -0 "$qemu_pid" 2>/dev/null || {
                cat "$stderr_log" >&2
                fail "QEMU exited before the raw-state probe completed"
              }
              sleep 0.1
              attempts=$((attempts + 1))
            done
            test -s "$result" || fail "raw-state probe timed out"
            grep -q '^raw_state_export_passed=true$' "$result" || {
              cat "$result" >&2
              fail "raw-state probe reported failure"
            }
            grep -q '^ram_full_copy_hashed=true$' "$result" \
              || fail "raw-state probe did not hash every RAM byte"
            grep -q '^ram_readonly_alias_excluded=true$' "$result" \
              || fail "raw-state probe did not exclude the read-only alias"
            grep -q '^ram_rom_excluded=true$' "$result" \
              || fail "raw-state probe did not exclude firmware ROM"
            grep -q '^ram_exact_total=67043328$' "$result" \
              || fail "raw-state probe reported an unexpected writable total"

            qmp_response="$TMPDIR/raw-state-qmp-response.jsonl"
            {
              printf '{"execute":"qmp_capabilities"}\r\n'
              printf '{"execute":"system_reset"}\r\n'
              printf '{"execute":"query-status"}\r\n'
              printf '{"execute":"cont"}\r\n'
              printf '{"execute":"query-status"}\r\n'
              printf '{"execute":"migrate","arguments":{"uri":"tcp:127.0.0.1:1"}}\r\n'
              printf '{"execute":"quit"}\r\n'
            } | socat -T 3 - "UNIX-CONNECT:$socket" > "$qmp_response" \
              2> "$TMPDIR/raw-state-qmp-socat.stderr" || true

            wait "$qemu_pid"
            trap - EXIT
            jq -e -s 'any(.[]; .return.status? == "paused")' "$qmp_response" >/dev/null \
              || fail "QMP cont resumed after terminal VMState export"
            jq -e -s 'any(.[]; .error.desc? == "VM reset rejected after terminal Crucible VMState export")' \
              "$qmp_response" >/dev/null \
              || fail "QMP system_reset was not rejected after terminal export"
            jq -e -s 'any(.[]; .error.desc? == "outgoing migration rejected during terminal Crucible raw-state export")' \
              "$qmp_response" >/dev/null \
              || fail "QMP migrate was not rejected after raw-state admission"
            grep -q 'VM resume rejected after terminal Crucible VMState export' "$stderr_log" \
              || fail "resume rejection was not diagnosed"

            mkdir -p "$out"
            cp "$result" "$out/result"
            {
              echo PASS
              echo gate=gate:patch-microtests
              echo patch=0036-crucible-raw-state-export.patch
              echo patched_fixture_exercised=true
              echo stock_negative_control=true
              echo qemu_package=${qemuPackage}
              echo qemu_package_version=${qemuPackage.version}
              echo running_state_export_rejected=true
              echo reset_after_terminal_export_rejected=true
              echo resume_after_terminal_export_rejected=true
              echo migration_after_raw_export_rejected=true
            } >> "$out/result"
          '';
        }
      ];
    }
