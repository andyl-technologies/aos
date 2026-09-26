{
  pkgs,
  lib,
}: let
  workloadSource = builtins.readFile ./phase0-s5-workload.c;
  pluginSource = builtins.readFile ./phase0-s5-virtual-memory-plugin.c;
  linuxResetSource = builtins.readFile ./phase0-s5-linux-reset.S;
  linuxResetLinkerScript = builtins.readFile ./x86-direct-reset.ld;
  rrSwitchQuantum = 4096;
  kernelCommandLine = "console=ttyS0 reboot=k panic=1 rdinit=/init nokaslr norandmaps random.trust_cpu=off";

  # Keep the Linux MMU and mmap path while avoiding the deployment kernel's
  # unrelated driver initialization under sim's fixed 50 ps/instruction clock.
  s5Kernel = pkgs.mkDerivation {
    pname = "crucible-phase0-s5-linux";
    inherit (pkgs.linux) version src;

    buildDeps = [
      pkgs.bc
      pkgs.bison
      pkgs.flex
      pkgs.gawk
      pkgs.gnumake
      pkgs.llvm
      pkgs.openssl
      pkgs.patch
      pkgs.perl
      pkgs.python3
    ];
    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd linux-${pkgs.linux.version}
        '';
      }
      {
        name = "patch";
        script = ''
          patch -p1 < ${../../pkgs/kernel/linux-gawk-array-argument.patch}
        '';
      }
      {
        name = "configure";
        script = ''
          make ARCH=x86_64 LLVM=1 HOSTCC=cc HOSTCXX=c++ tinyconfig
          cat > .s5.config <<'KCONFIG'
          CONFIG_64BIT=y
          CONFIG_X86_64=y
          CONFIG_BINFMT_ELF=y
          CONFIG_BLK_DEV_INITRD=y
          CONFIG_RD_GZIP=y
          CONFIG_MMU=y
          CONFIG_TTY=y
          CONFIG_SERIAL_8250=y
          CONFIG_SERIAL_8250_CONSOLE=y
          CONFIG_SMP=n
          CONFIG_MODULES=n
          CONFIG_DEBUG_INFO_NONE=y
          CONFIG_DEBUG_INFO_BTF=n
          KCONFIG
          scripts/kconfig/merge_config.sh -m .config .s5.config
          make ARCH=x86_64 LLVM=1 HOSTCC=cc HOSTCXX=c++ olddefconfig

          grep -Fxq 'CONFIG_BINFMT_ELF=y' .config
          grep -Fxq 'CONFIG_BLK_DEV_INITRD=y' .config
          grep -Fxq 'CONFIG_SERIAL_8250_CONSOLE=y' .config
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" ARCH=x86_64 LLVM=1 HOSTCC=cc HOSTCXX=c++ bzImage
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/boot"
          cp arch/x86/boot/bzImage "$out/boot/vmlinuz"
          cp .config "$out/boot/config"
        '';
      }
    ];
  };

  workload = pkgs.mkDerivation {
    pname = "crucible-phase0-s5-workload";
    version = "0";
    src = null;

    workload = workloadSource;
    passAsFile = ["workload"];

    buildDeps = [
      pkgs.binutils
      pkgs.gawk
    ];

    phases = [
      {
        name = "build-workload";
        script = ''
          mkdir -p "$out/bin"
          cp "$workloadPath" phase0-s5-workload.c
          cc -std=c11 -O2 -Wall -Wextra -Werror -static -fno-PIE -no-pie \
            phase0-s5-workload.c \
            -o "$out/bin/s5-workload"

          activation_vaddr=$(
            nm -n "$out/bin/s5-workload" \
              | gawk '$3 == "marker_observation_enable" { print "0x" $1 }'
          )
          [ -n "$activation_vaddr" ] || {
            echo "FAIL: observation-enable marker symbol is missing" >&2
            exit 1
          }
          [ "$(printf '%s\n' "$activation_vaddr" | wc -l)" -eq 1 ] || {
            echo "FAIL: observation-enable marker symbol is not unique" >&2
            exit 1
          }
          mkdir -p "$out/share/crucible-phase0-s5"
          printf '%s\n' "$activation_vaddr" \
            > "$out/share/crucible-phase0-s5/activation-vaddr"
        '';
      }
    ];
  };

  linuxReset = pkgs.mkDerivation {
    pname = "crucible-phase0-s5-linux-reset";
    version = "0";
    src = null;

    reset = linuxResetSource;
    linker = linuxResetLinkerScript;
    passAsFile = ["reset" "linker"];
    buildDeps = [pkgs.binutils];

    phases = [
      {
        name = "build-linux-reset";
        script = ''
          cp "$resetPath" reset.S
          as --32 reset.S -o reset.o
          ld -m elf_i386 -T "$linkerPath" reset.o -o reset.elf
          objcopy -O binary --gap-fill 0 reset.elf reset.bin
          [ "$(wc -c < reset.bin)" -eq 65536 ]

          mkdir -p "$out"
          cp reset.bin "$out/"
        '';
      }
    ];
  };

  initramfs = pkgs.mkDerivation {
    pname = "crucible-phase0-s5-initramfs";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.cpio pkgs.findutils pkgs.gzip];

    phases = [
      {
        name = "build-initramfs";
        script = ''
          set -eu
          mkdir -p root/dev "$out"
          cp ${workload}/bin/s5-workload root/init
          (
            cd root
            find . -print0 \
              | LC_ALL=C sort -z \
              | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
              | gzip -9 -n > "$out/initrd.img"
          )
        '';
      }
    ];
  };

  linuxImage = pkgs.mkDerivation {
    pname = "crucible-phase0-s5-linux-image";
    version = "0";
    src = null;

    KERNEL = builtins.toString s5Kernel;
    INITRAMFS = "${initramfs}/initrd.img";
    KERNEL_CMDLINE = kernelCommandLine;

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
    ];

    phases = [
      {
        name = "prepare-linux-image";
        script = ''
          set -eu

          vmlinuz=$(find "$KERNEL"/boot -maxdepth 1 -type f -name 'vmlinuz*' | head -1)
          [ -n "$vmlinuz" ]
          setup_sectors=$(od -An -tu1 -j 497 -N 1 "$vmlinuz" | tr -d ' ')
          [ -n "$setup_sectors" ] && [ "$setup_sectors" -gt 0 ]
          setup_blocks=$((setup_sectors + 1))

          mkdir -p "$out"
          dd if="$vmlinuz" of="$out/setup.bin" bs=512 count="$setup_blocks" status=none
          dd if="$vmlinuz" of="$out/kernel.bin" bs=512 skip="$setup_blocks" status=none
          cp "$INITRAMFS" "$out/initrd.img"
          printf '%s\0' "$KERNEL_CMDLINE" > "$out/cmdline.bin"

          # Linux boot protocol fields for the fixed fixture addresses below.
          printf '\260' | dd of="$out/setup.bin" bs=1 seek=$((0x210)) conv=notrunc status=none
          printf '\201' | dd of="$out/setup.bin" bs=1 seek=$((0x211)) conv=notrunc status=none
          printf '\000\000\000\010' | dd of="$out/setup.bin" bs=1 seek=$((0x218)) conv=notrunc status=none
          initrd_size=$(wc -c < "$out/initrd.img")
          gawk -v size="$initrd_size" 'BEGIN {
            for (byte = 0; byte < 4; byte++) {
              printf "%c", int(size / (256 ^ byte)) % 256
            }
          }' > initrd-size.bin
          dd if=initrd-size.bin of="$out/setup.bin" bs=1 seek=$((0x21c)) conv=notrunc status=none
          printf '\000\376' | dd of="$out/setup.bin" bs=1 seek=$((0x224)) conv=notrunc status=none
          printf '\000\000\002\000' | dd of="$out/setup.bin" bs=1 seek=$((0x228)) conv=notrunc status=none

          [ "$(od -An -tx4 -j $((0x202)) -N 4 "$out/setup.bin" | tr -d ' ')" = 53726448 ]
          [ "$(wc -c < "$out/kernel.bin")" -gt 0 ]
          [ "$initrd_size" -gt 0 ]
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s5-virtual-memory";
    version = "0";
    src = null;

    plugin = pluginSource;
    passAsFile = ["plugin"];

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.gawk
      pkgs.glib
      pkgs.glib.dev
      pkgs.grep
      pkgs.jq
      pkgs.pkg-config
      pkgs.qemu-crucible
      pkgs.socat
    ];

    QEMU = "${pkgs.qemu-crucible}/bin/qemu-system-x86_64";
    RR_SWITCH_QUANTUM = builtins.toString rrSwitchQuantum;

    phases = [
      {
        name = "build-s5-plugin";
        script = ''
          cp "$pluginPath" phase0-s5-virtual-memory-plugin.c
          cc -fPIC -shared -O2 -Wall -Wextra -Werror \
            $(pkg-config --cflags glib-2.0) \
            -I${pkgs.qemu-crucible}/include \
            phase0-s5-virtual-memory-plugin.c \
            -o phase0-s5-virtual-memory-plugin.so
        '';
      }
      {
        name = "run-s5-virtual-memory";
        script = ''
          set -eu

          unset LD_LIBRARY_PATH || true

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          qmp_cmd() {
            socket="$1"
            request="$2"
            response="$3"
            response_err="$response.err"

            {
              printf '{"execute":"qmp_capabilities"}\r\n'
              printf '%s\r\n' "$request"
            } | socat -T 2 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

            if [ ! -s "$response" ]; then
              cat "$response_err" >&2
              return 1
            fi

            if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
              cat "$response" >&2
              return 1
            fi
            jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null
          }

          wait_for_socket() {
            socket="$1"
            waited=0
            while [ "$waited" -lt 600 ]; do
              if [ -S "$socket" ]; then
                return 0
              fi
              sleep 0.1
              waited=$((waited + 1))
            done
            return 1
          }

          wait_for_pause() {
            label="$1"
            socket="$2"
            current_status="$TMPDIR/qmp-status-current-$label.json"
            last_status="$TMPDIR/qmp-status-$label.json"
            waited=0
            while [ "$waited" -lt 1200 ]; do
              if qmp_cmd "$socket" '{"execute":"query-status"}' "$current_status"; then
                cp "$current_status" "$last_status"
                status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$last_status")
                case "$status" in
                  paused)
                    return 0
                    ;;
                  shutdown | internal-error | guest-panicked)
                    cat "$last_status" >&2
                    return 1
                    ;;
                esac
              fi
              sleep 0.25
              waited=$((waited + 1))
            done
            return 1
          }

          cleanup_qemu() {
            if [ -n "''${qemu_pid:-}" ]; then
              kill "$qemu_pid" 2>/dev/null || true
              wait "$qemu_pid" 2>/dev/null || true
              qemu_pid=""
            fi
          }

          trap cleanup_qemu EXIT

          report_trace_mismatch() {
            label="$1"
            jq -c '
              select(.event == "doorbell")
              | ([
                  {kind: 1, name: "resident", len: 64},
                  {kind: 2, name: "page_spanning", len: 96},
                  {kind: 3, name: "paged_mmap", len: 128}
                ][.marker_index - 1]) as $expected
              | {
                  marker_index,
                  marker_icount,
                  actual: {
                    vcpu,
                    kind,
                    name,
                    addr,
                    len,
                    register_read_ok,
                    read_enabled,
                    read_attempted,
                    read_success,
                    bytes_match,
                    payload_hash,
                    expected_hash
                  },
                  expected: $expected
                }
            ' "$TMPDIR/trace-$label.jsonl" >&2
            jq -c '
              select(.final == true and .pause_sample == true)
              | {
                  markers,
                  activation_marker_callbacks,
                  reset_completion_callbacks,
                  activation_errors,
                  measured_callbacks_active,
                  dormant_tb_translations,
                  read_enabled,
                  read_attempts,
                  read_successes,
                  read_failures,
                  bytes_mismatches,
                  sample_register_failures,
                  sample_capture_failures,
                  register_read_failures,
                  capture_status,
                  digest_status,
                  ram_bytes,
                  ram_material_length,
                  device_bytes,
                  device_material_length,
                  register_counts
                }
            ' "$TMPDIR/trace-$label.jsonl" >&2
          }

          report_pause_timeout() {
            label="$1"
            socket="$2"

            echo "--- S5 $label QMP status ---" >&2
            cat "$TMPDIR/qmp-status-$label.json" >&2 || true
            qmp_cmd "$socket" \
              '{"execute":"query-cpus-fast"}' \
              "$TMPDIR/qmp-cpus-$label.json" || true
            cat "$TMPDIR/qmp-cpus-$label.json" >&2 || true
            qmp_cmd "$socket" \
              '{"execute":"human-monitor-command","arguments":{"command-line":"info registers -a"}}' \
              "$TMPDIR/qmp-registers-$label.json" || true
            cat "$TMPDIR/qmp-registers-$label.json" >&2 || true
            qmp_cmd "$socket" \
              '{"execute":"human-monitor-command","arguments":{"command-line":"info pic"}}' \
              "$TMPDIR/qmp-pic-$label.json" || true
            cat "$TMPDIR/qmp-pic-$label.json" >&2 || true

            echo "--- S5 $label serial tail ---" >&2
            tail -n 80 "$TMPDIR/serial-$label.log" >&2 || true
            echo "--- S5 $label trace tail ---" >&2
            tail -n 32 "$TMPDIR/trace-$label.jsonl" >&2 || true
          }

          plugin="$PWD/phase0-s5-virtual-memory-plugin.so"
          activation_vaddr=$(cat ${workload}/share/crucible-phase0-s5/activation-vaddr)
          seed="$TMPDIR/seed.bin"
          printf 'crucible-phase0-s5-seed-v1\n' > "$seed"
          run_qemu() {
            label="$1"
            read_mode="$2"
            qmp_socket="$TMPDIR/qmp-$label.sock"
            serial="$TMPDIR/serial-$label.log"
            trace="$TMPDIR/trace-$label.jsonl"
            rm -f "$qmp_socket"

            timeout 900 "$QEMU" \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine q35 \
              -accel sim,thread=single \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum="$RR_SWITCH_QUANTUM" \
              -cpu qemu64 \
              -m 256 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c001 \
              -fw_cfg name=opt/crucible/seed,file="$seed" \
              -bios ${linuxReset}/reset.bin \
              -device loader,file=${linuxImage}/setup.bin,addr=0x10000,force-raw=on \
              -device loader,file=${linuxImage}/kernel.bin,addr=0x100000,force-raw=on \
              -device loader,file=${linuxImage}/cmdline.bin,addr=0x20000,force-raw=on \
              -device loader,file=${linuxImage}/initrd.img,addr=0x8000000,force-raw=on \
              -chardev file,id=serial0,path="$serial" \
              -serial chardev:serial0 \
              -qmp "unix:$qmp_socket,server=on,wait=off" \
              -plugin "$plugin",out="$trace",read="$read_mode",expected_markers=3,vcpus=1,activate-vaddr="$activation_vaddr" \
              -no-shutdown \
              -no-reboot &
            qemu_pid="$!"

            wait_for_socket "$qmp_socket" || fail "$label QMP socket did not appear"
            wait_for_pause "$label" "$qmp_socket" || {
              report_pause_timeout "$label" "$qmp_socket"
              fail "$label did not pause after S5 markers"
            }
            qmp_cmd "$qmp_socket" '{"execute":"quit"}' "$TMPDIR/qmp-quit-$label.json" || true
            wait "$qemu_pid" || fail "$label QEMU exited unsuccessfully"
            qemu_pid=""
          }

          assert_read_trace() {
            label="$1"
            jq -e -s '
              [ .[] | select(.event == "doorbell") ] as $events
              | [ .[] | select(.final == true and .pause_sample == true) ] as $finals
              | ($events | length) == 3
              and ($finals | length) == 1
              and all($events[]; (
                .register_read_ok == true
                and .read_enabled == true
                and .read_attempted == true
                and .read_success == true
                and .bytes_match == true
                and .payload_hash == .expected_hash
                and .len > 0
              ))
              and (($events | map(.kind) | sort) == [1,2,3])
              and ($events[] | select(.kind == 1 and .name == "resident" and .len == 64))
              and ($events[] | select(.kind == 2 and .name == "page_spanning" and .len == 96))
              and ($events[] | select(.kind == 3 and .name == "paged_mmap" and .len == 128))
              and all($finals[]; (
              .markers == 3
              and .activation_marker_callbacks == 1
              and .reset_completion_callbacks == 1
              and .activation_errors == 0
              and .measured_callbacks_active == true
              and .dormant_tb_translations > 0
              and .read_enabled == true
                and .read_attempts == 3
                and .read_successes == 3
                and .read_failures == 0
                and .bytes_mismatches == 0
                and .sample_register_failures == 0
                and .sample_capture_failures == 0
                and .register_read_failures == 0
                and .capture_status == 0
                and .digest_status == 0
                and .ram_bytes > 0
                and .ram_material_length > .ram_bytes
                and .device_bytes > 0
                and .device_material_length > .device_bytes
                and (.register_counts | type == "array")
                and (.register_counts | length) == 1
                and .register_counts[0] > 0
              ))
            ' "$TMPDIR/trace-$label.jsonl" >/dev/null || {
              report_trace_mismatch "$label"
              fail "invalid S5 read trace for $label"
            }
          }

          assert_control_trace() {
            label="$1"
            jq -e -s '
              [ .[] | select(.event == "doorbell") ] as $events
              | [ .[] | select(.final == true and .pause_sample == true) ] as $finals
              | ($events | length) == 3
              and ($finals | length) == 1
              and all($events[]; (
                .register_read_ok == true
                and .read_enabled == false
                and .read_attempted == false
                and .read_success == false
              ))
              and all($finals[]; (
              .markers == 3
              and .activation_marker_callbacks == 1
              and .reset_completion_callbacks == 1
              and .activation_errors == 0
              and .measured_callbacks_active == true
              and .dormant_tb_translations > 0
              and .read_enabled == false
                and .read_attempts == 0
                and .read_successes == 0
                and .read_failures == 0
                and .bytes_mismatches == 0
                and .sample_register_failures == 0
                and .sample_capture_failures == 0
                and .register_read_failures == 0
                and .capture_status == 0
                and .digest_status == 0
                and .ram_bytes > 0
                and .ram_material_length > .ram_bytes
                and .device_bytes > 0
                and .device_material_length > .device_bytes
              ))
            ' "$TMPDIR/trace-$label.jsonl" >/dev/null || {
              report_trace_mismatch "$label"
              fail "invalid S5 control trace for $label"
            }
          }

          normalize_events() {
            label="$1"
            jq -S -c '
              select(.event == "doorbell")
              | {
                  marker_index,
                  marker_icount,
                  kind,
                  name,
                  addr,
                  len,
                  payload_hash,
                  expected_hash,
                  bytes_match
                }
            ' "$TMPDIR/trace-$label.jsonl" > "$TMPDIR/events-$label.jsonl"
          }

          normalize_final() {
            label="$1"
            jq -S -c '
              select(.final == true and .pause_sample == true)
              | {
                  retired,
                  markers,
                  stream_hash,
                  register_hash,
                  ram_hash,
                  ram_bytes,
                  state_hash,
                  register_counts
                }
            ' "$TMPDIR/trace-$label.jsonl" > "$TMPDIR/final-$label.json"
          }

          run_qemu read-a on
          run_qemu read-b on
          run_qemu control off

          assert_read_trace read-a
          assert_read_trace read-b
          assert_control_trace control

          normalize_events read-a
          normalize_events read-b
          normalize_final read-a
          normalize_final read-b
          normalize_final control

          if ! diff -u "$TMPDIR/events-read-a.jsonl" "$TMPDIR/events-read-b.jsonl" > "$TMPDIR/events.diff"; then
            cat "$TMPDIR/events.diff" >&2
            fail "S5 virtual-read marker sequence is not reproducible"
          fi
          if ! diff -u "$TMPDIR/final-read-a.json" "$TMPDIR/final-read-b.json" > "$TMPDIR/final-read.diff"; then
            cat "$TMPDIR/final-read.diff" >&2
            fail "S5 read-enabled final fingerprint is not reproducible"
          fi
          if ! diff -u "$TMPDIR/final-read-a.json" "$TMPDIR/final-control.json" > "$TMPDIR/final-control.diff"; then
            cat "$TMPDIR/final-control.diff" >&2
            fail "S5 virtual-read servicing perturbed the final fingerprint"
          fi

          resident_hash=$(jq -r 'select(.event == "doorbell" and .kind == 1) | .payload_hash' "$TMPDIR/trace-read-a.jsonl")
          span_hash=$(jq -r 'select(.event == "doorbell" and .kind == 2) | .payload_hash' "$TMPDIR/trace-read-a.jsonl")
          paged_hash=$(jq -r 'select(.event == "doorbell" and .kind == 3) | .payload_hash' "$TMPDIR/trace-read-a.jsonl")
          final_hash=$(jq -r 'select(.final == true and .pause_sample == true) | .state_hash' "$TMPDIR/trace-read-a.jsonl")
          ram_hash=$(jq -r 'select(.final == true and .pause_sample == true) | .ram_hash' "$TMPDIR/trace-read-a.jsonl")
          register_hash=$(jq -r 'select(.final == true and .pause_sample == true) | .register_hash' "$TMPDIR/trace-read-a.jsonl")
          marker_icounts=$(jq -r 'select(.event == "doorbell") | .marker_icount' "$TMPDIR/trace-read-a.jsonl" | paste -sd, -)

          mkdir -p "$out"
          cp "$TMPDIR/trace-read-a.jsonl" "$out/trace-read-a.jsonl"
          cp "$TMPDIR/trace-read-b.jsonl" "$out/trace-read-b.jsonl"
          cp "$TMPDIR/trace-control.jsonl" "$out/trace-control.jsonl"
          cp "$TMPDIR/events-read-a.jsonl" "$out/events-read-a.jsonl"
          cp "$TMPDIR/final-read-a.json" "$out/final-read-a.json"
          cp phase0-s5-virtual-memory-plugin.c "$out/virtual-memory-plugin.c"
          {
            echo PASS
            echo spike=guest-virtual-memory-read
            echo check=checks.crucible.phase0.s5VirtualMemory
            echo qemu_plugin_read_memory_vaddr_available=true
            echo doorbell_surface=phase0_instruction_marker_double
            echo payload_source=register_triplet_kind_ptr_len
            echo virtual_address_read_result=pass
            echo placements=3
            echo resident_read=pass
            echo page_spanning_read=pass
            echo paged_mmap_read=pass
            echo resident_hash="$resident_hash"
            echo page_spanning_hash="$span_hash"
            echo paged_mmap_hash="$paged_hash"
            echo marker_icounts="$marker_icounts"
            echo rr_switch_quantum="$RR_SWITCH_QUANTUM"
            echo marker_icounts_reproducible=true
            echo observation_activation=guest_marker_then_plugin_reset
            echo boot_instruction_callbacks=disabled
            echo read_bytes_match_expected=true
            echo read_hashes_reproducible=true
            echo side_effect_free_fingerprint_match=true
            echo final_state_hash="$final_hash"
            echo final_ram_hash="$ram_hash"
            echo final_register_hash="$register_hash"
            echo production_whitebox_channel_implemented=false
            echo physical_pinned_fallback_adopted=false
            echo s5_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S5 guest virtual memory read spike";
    };
  }
