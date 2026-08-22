{
  pkgs,
  lib,
}: let
  boundedSchedulerPreemptionCheck = import ./phase0-bounded-scheduler-preemption.nix {inherit pkgs lib;};
  linuxSource = import ../../pkgs/kernel/_source.nix {fetchurl = pkgs.fetchurl;};

  kernel = pkgs.mkDerivation {
    pname = "crucible-aarch64-s1-s6-linux";
    inherit (linuxSource) version src;

    buildDeps = [
      pkgs."llvm-21"
      pkgs.bc
      pkgs.bison
      pkgs.coreutils
      pkgs.elfutils
      pkgs.flex
      pkgs.gawk
      pkgs.gnumake
      pkgs.openssl
      pkgs.perl
      pkgs.python3
      pkgs.rsync
      pkgs.zstd
    ];

    hardeningDisable = ["all"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd linux-${linuxSource.version}
          for file in $(find . -type f -name '*.py'); do
            case "$(head -n 1 "$file")" in
              '#!'*python*) sed -i "1s|.*|#!${pkgs.python3}/bin/python3|" "$file" ;;
            esac
          done
        '';
      }
      {
        name = "configure";
        script = ''
          make ARCH=arm64 LLVM=1 HOSTCC=cc HOSTCXX=c++ tinyconfig
          cat > .crucible-aarch64.config <<'KCONFIG'
          CONFIG_EXPERT=y
          CONFIG_EMBEDDED=y
          CONFIG_PRINTK=y
          CONFIG_BUG=y
          CONFIG_BINFMT_ELF=y
          CONFIG_RANDOMIZE_BASE=y
          CONFIG_RANDOMIZE_MODULE_REGION_FULL=y
          CONFIG_BLK_DEV_INITRD=y
          CONFIG_RD_GZIP=y
          CONFIG_TTY=y
          CONFIG_SERIAL_EARLYCON=y
          CONFIG_SERIAL_AMBA_PL011=y
          CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
          CONFIG_TMPFS=y
          CONFIG_SMP=n
          CONFIG_COMPAT=n
          CONFIG_MODULES=n
          CONFIG_DEBUG_INFO_NONE=y
          CONFIG_DEBUG_INFO_BTF=n
          CONFIG_PRINTK_TIME=n
          CONFIG_SERIAL_AMBA_PL011=y
          CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
          KCONFIG
          scripts/kconfig/merge_config.sh -m .config .crucible-aarch64.config
          make ARCH=arm64 LLVM=1 HOSTCC=cc HOSTCXX=c++ olddefconfig
          grep -Fxq 'CONFIG_RANDOMIZE_BASE=y' .config
          grep -Fxq 'CONFIG_BLK_DEV_INITRD=y' .config
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" ARCH=arm64 LLVM=1 HOSTCC=cc HOSTCXX=c++ Image
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/boot"
          cp arch/arm64/boot/Image "$out/boot/Image"
          cp .config "$out/boot/config"
        '';
      }
    ];
  };

  initramfs = pkgs.mkDerivation {
    pname = "crucible-aarch64-s1-s6-initramfs";
    version = "0";
    src = null;

    buildDeps = [
      pkgs."llvm-21"
      pkgs.coreutils
      pkgs.cpio
      pkgs.pigz
    ];

    phases = [
      {
        name = "build-initramfs";
        script = ''
          set -eu
          cat > init.S <<'ASSEMBLY'
          .section .text
          .global _start
          .type _start, %function
          _start:
            mov x20, sp
            adr x21, _start

            mov x0, #0
            mov x8, #214
            svc #0
            mov x22, x0

            mov x0, #0
            mov x1, #4096
            mov x2, #3
            mov x3, #0x22
            mov x4, #-1
            mov x5, #0
            mov x8, #222
            svc #0
            mov x23, x0

            mov x24, #0
            ldr x0, [x20]
            add x9, x20, #8
            add x9, x9, x0, lsl #3
            add x9, x9, #8
          1:
            ldr x10, [x9], #8
            cbnz x10, 1b
          2:
            ldp x10, x11, [x9], #16
            cbz x10, 3f
            cmp x10, #33
            b.ne 2b
            mov x24, x11
          3:
            mov x0, x21
            adr x1, pc_digits
            bl write_hex
            mov x0, x20
            adr x1, sp_digits
            bl write_hex
            mov x0, x22
            adr x1, brk_digits
            bl write_hex
            mov x0, x23
            adr x1, mmap_digits
            bl write_hex
            mov x0, x24
            adr x1, vdso_digits
            bl write_hex

            mov x0, #1
            adr x1, line
            mov x2, #(line_end - line)
            mov x8, #64
            svc #0
            movz x25, #0x5eed
            movk x25, #0x0010, lsl #16
            adr x26, sink
          4:
            add x25, x25, #0x9e3
            eor x25, x25, x25, ror #17
            str x25, [x26]
            b 4b

          write_hex:
            mov x2, #16
          5:
            lsr x3, x0, #60
            cmp x3, #9
            add x4, x3, #'0'
            add x5, x3, #('a' - 10)
            csel x3, x4, x5, ls
            strb w3, [x1], #1
            lsl x0, x0, #4
            subs x2, x2, #1
            b.ne 5b
            ret

          .section .data
          line:
            .ascii "CRUCIBLE_AARCH64_BASES pc=0x"
          pc_digits:
            .space 16
            .ascii " sp=0x"
          sp_digits:
            .space 16
            .ascii " brk=0x"
          brk_digits:
            .space 16
            .ascii " mmap=0x"
          mmap_digits:
            .space 16
            .ascii " vdso=0x"
          vdso_digits:
            .space 16
            .ascii "\n"
          line_end:
          sink:
            .quad 0
          ASSEMBLY

          clang --no-default-config \
            --target=aarch64-none-elf \
            -c init.S \
            -o init.o
          ld.lld -pie -static -e _start --build-id=none init.o -o init
          llvm-readelf -h init | grep -Eq 'Type:.*DYN'

          mkdir -p root "$out"
          cp init root/init
          chmod 0755 root/init
          (
            cd root
            find . -print0 \
              | LC_ALL=C sort -z \
              | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
              | pigz -9 -n > "$out/initrd.img"
          )
          test -s "$out/initrd.img"
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-aarch64-s1-s6";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.diffutils
      pkgs.dtc
      pkgs.gawk
      pkgs.grep
      pkgs.jq
      pkgs.qemu-crucible
      pkgs.crucible-qemu-trace-plugin
    ];

    KERNEL = "${kernel}/boot/Image";
    INITRAMFS = "${initramfs}/initrd.img";
    PLUGIN = "${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so";
    BOUNDED_PREEMPTION_HARNESS = ./_bounded-scheduler-preemption.sh;
    BOUNDED_PREEMPTION_TARGET_WRAPPER = ./_bounded-scheduler-preemption-target.sh;
    BOUNDED_PREEMPTION_CHECK = boundedSchedulerPreemptionCheck;

    phases = [
      {
        name = "run-aarch64-s1-s6";
        script = ''
          set -eu
          unset LD_LIBRARY_PATH || true
          grep -Fxq PASS "$BOUNDED_PREEMPTION_CHECK/result"

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          seed_dtb="$TMPDIR/virt-seeded.dtb"
          qemu-system-aarch64 \
            -nodefaults \
            -no-user-config \
            -display none \
            -machine "virt,gic-version=2,dumpdtb=$seed_dtb" \
            -cpu cortex-a57 \
            >/dev/null 2>"$TMPDIR/dumpdtb.log"
          test -s "$seed_dtb"
          if ! fdtget -l "$seed_dtb" / | grep -Fxq chosen; then
            fdtput -c "$seed_dtb" /chosen
          fi
          fdtput -t x "$seed_dtb" /chosen kaslr-seed 0x0010c006 0x5eed0010
          fdtput -t bx "$seed_dtb" /chosen rng-seed \
            00 10 c0 06 5e ed 00 10 00 10 c0 06 5e ed 00 11 \
            00 10 c0 06 5e ed 00 12 00 10 c0 06 5e ed 00 13

          . "$BOUNDED_PREEMPTION_HARNESS"
          trap 'bounded_preemption_cleanup' EXIT
          trap 'bounded_preemption_cleanup; exit 143' TERM
          trap 'bounded_preemption_cleanup; exit 130' INT

          run_one() {
            mode="$1"
            suffix="$2"
            label="$mode-$suffix"
            serial="$TMPDIR/serial-$label.log"
            trace="$TMPDIR/trace-$label.jsonl"
            append="console=ttyAMA0 rdinit=/init ignore_loglevel loglevel=8 random.trust_cpu=off"
            if [ "$mode" = control ]; then
              append="$append nokaslr norandmaps"
            fi

            set -- qemu-system-aarch64 \
              -nodefaults \
              -no-user-config \
              -display none \
              -monitor none \
              -machine virt,gic-version=2 \
              -cpu cortex-a57 \
              -accel sim,thread=single \
              -icount shift=0,sleep=off,align=off,rr_switch_quantum=4096 \
              -m 256 \
              -smp 1 \
              -rtc base=2026-01-01T00:00:00,clock=vm \
              -seed 0x0010c006 \
              -dtb "$seed_dtb" \
              -kernel "$KERNEL" \
              -initrd "$INITRAMFS" \
              -append "$append" \
              -serial "file:$serial" \
              -plugin "$PLUGIN,out=$trace,cadence=25000000,stop_at=25000000,extended=on,mem_events=off,rr_switch_events=on,vcpus=1" \
              -no-reboot \
              -no-shutdown
            qemu_binary=$(command -v "$1")
            bounded_preemption_launch_qemu \
              1200 "$TMPDIR/qemu-target-$label.pid" - "$qemu_binary" "$@" \
              >"$TMPDIR/stdout-$label.log" 2>"$TMPDIR/stderr-$label.log" \
              || fail "$label QEMU launch failed"
            qemu_pid="$BOUNDED_QEMU_PID"
            if [ "$label" = randomized-b ]; then
              # This comparison proves the seeded ASLR/KASLR result is
              # independent of host scheduling. Direct finite preemption is a
              # causal perturbation of the actual QEMU execution schedule.
              bounded_preemption_start "$TMPDIR/preemption-$label.log" \
                || fail "$label scheduler adversary did not start"
            fi

            waited=0
            while [ "$waited" -lt 1800 ]; do
              if grep -q '"observed_icount":25000000' "$trace" 2>/dev/null; then
                break
              fi
              kill -0 "$qemu_pid" 2>/dev/null \
                || fail "$label QEMU exited before the exact fingerprint horizon"
              sleep 0.5
              waited=$((waited + 1))
            done
            [ "$waited" -lt 1800 ] || fail "$label did not reach exact fingerprint horizon"
            sed -i 's/\r$//' "$serial"
            if ! grep -Eq '^CRUCIBLE_AARCH64_BASES pc=0x[0-9a-f]{16} sp=0x[0-9a-f]{16} brk=0x[0-9a-f]{16} mmap=0x[0-9a-f]{16} vdso=0x[0-9a-f]{16}$' "$serial"; then
              cat "$serial" >&2
              cat "$TMPDIR/stderr-$label.log" >&2
              fail "$label omitted the aarch64 PIE/ASLR layout"
            fi
            if [ "$mode" = control ]; then
              grep -q '^KASLR disabled on command line$' "$serial" \
                || fail "$label did not disable KASLR"
            else
              grep -q '^KASLR enabled$' "$serial" \
                || fail "$label did not enable KASLR"
            fi
            grep -Eq '^Root IRQ handler: 0xffff[0-9a-f]{12}$' "$serial" \
              || fail "$label omitted the relocated kernel text anchor"
            grep -q '"observed_icount":25000000' "$trace" \
              || fail "$label terminal fingerprint missed the exact horizon"

            if [ "$label" = randomized-b ]; then
              bounded_preemption_finish "$TMPDIR/preemption-$label.log" \
                || fail "$label scheduler adversary was incomplete"
            fi

            kill -9 "$qemu_pid" || fail "$label QEMU could not be terminated"
            bounded_preemption_wait_qemu 2>/dev/null || true
            qemu_pid=""
            jq -c '
              select(.observed_icount == 25000000)
              | del(.process_argv_digest)
              | select(
                  .sample_register_failures == 0
                  and .register_read_failures == 0
                  and .device_state_failures == 0
                  and .trajectory_digest_failures == 0
                  and (.register_file_bytes | all(. > 0))
                  and .device_state_complete == true
                  and .ram_status == 0
                )
            ' "$trace" | tail -1 >"$TMPDIR/horizon-$label.json"
            test -s "$TMPDIR/horizon-$label.json" \
              || fail "$label omitted a complete exact-horizon fingerprint"

            grep '^CRUCIBLE_AARCH64_BASES ' "$serial" | tail -1 >"$TMPDIR/bases-$label"
            grep '^Root IRQ handler: ' "$serial" | tail -1 \
              >"$TMPDIR/kernel-offset-$label"
          }

          run_one control a
          run_one randomized a
          run_one randomized b

          cmp "$TMPDIR/bases-randomized-a" "$TMPDIR/bases-randomized-b" \
            || fail "aarch64 ASLR bases differed under bounded scheduler preemption"
          cmp "$TMPDIR/kernel-offset-randomized-a" "$TMPDIR/kernel-offset-randomized-b" \
            || fail "aarch64 KASLR offset differed under bounded scheduler preemption"
          cmp "$TMPDIR/horizon-randomized-a.json" "$TMPDIR/horizon-randomized-b.json" \
            || fail "aarch64 S1 extended fingerprints differed under bounded scheduler preemption"
          if cmp -s "$TMPDIR/bases-control-a" "$TMPDIR/bases-randomized-a"; then
            fail "randomized aarch64 PIE/ASLR bases equal the no-randomization control"
          fi
          if cmp -s "$TMPDIR/kernel-offset-control-a" "$TMPDIR/kernel-offset-randomized-a"; then
            fail "randomized aarch64 KASLR offset equals the no-KASLR control"
          fi

          final_hash=$(sha256sum "$TMPDIR/horizon-randomized-a.json" | cut -d ' ' -f 1)
          echo "$final_hash" | grep -Eq '^[0-9a-f]{64}$'

          mkdir -p "$out"
          cp "$TMPDIR/preemption-randomized-b.log" "$out/preemption-randomized-b.log"
          cp "$TMPDIR"/bases-* "$out/"
          cp "$TMPDIR"/kernel-offset-* "$out/"
          cp "$TMPDIR"/trace-randomized-*.jsonl "$out/"
          cp "$TMPDIR"/serial-*.log "$out/"
          {
            echo PASS
            echo check=checks.crucible.phase0.aarch64S1S6
            echo architecture=aarch64
            echo backend=qemu-system-aarch64
            echo accelerator=sim,thread=single
            echo entropy_source=fixed-device-tree-kaslr-seed-and-rng-seed
            echo randomized_kernel_cmdline_has_nokaslr_norandmaps=false
            echo randomized_kernel_offset_reproducible=true
            echo randomized_pie_aslr_layout_reproducible=true
            echo randomized_layout_differs_from_control=true
            echo host_adversary=bounded-scheduler-preemption
            echo host_adversary_perturbations=6
            echo host_adversary_configured_pause_milliseconds=15
            echo host_adversary_configured_total_stopped_milliseconds=90
            echo host_adversary_nominal_worker_wall_milliseconds=240
            echo host_adversary_worker_wall_timeout_seconds=2
            echo host_adversary_busy_workers=0
            echo extended_fingerprint_match=true
            echo exact_horizon_icount=25000000
            echo final_extended_hash="$final_hash"
            echo aarch64_s1_complete=true
            echo aarch64_s6_complete=true
            echo fallback_adopted=none
          } >"$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible AArch64 S1 fingerprint and S6 KASLR/ASLR gate";
    };
  }
