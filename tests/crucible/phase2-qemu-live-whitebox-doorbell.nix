{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveWhiteboxDoorbell",
  taskIds ? ["T-DET-31" "T-PLUG-14" "T-PLUG-27" "T-GHC-4" "T-GHC-6" "T-GHC-9" "T-GHC-12" "T-GHC-16"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  guest = pkgs.mkDerivation {
    pname = "crucible-live-whitebox-doorbell-guest";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils];

    phases = [
      {
        name = "build-whitebox-gate-guests";
        script = ''
          set -eu
          # A gate-only ROM enters the white-box instruction without waiting
          # for PC firmware timers. At 50 ps per instruction, the generic BIOS
          # boot delay otherwise dominates the exact callback horizon.
          cat > whitebox-bios.S <<'WHITEBOX_BIOS_ASM'
          .section .text,"ax"
          .code16
          .global _start
          _start:
            cli
            movl $(0x000f0000 + whitebox_frame), %eax
            movl $22, %ecx
            outb %al, $0xe7
            xorl %eax, %eax
          workload_loop:
            addl $0x9e3779b9, %eax
            roll $7, %eax
            xorl $0xa5a5a5a5, %eax
            outb %al, $0x80
            jmp workload_loop

          .align 16
          whitebox_frame:
            .byte 0x43, 0x52, 0x42, 0x4c
            .byte 0x03, 0x00
            .byte 0x04, 0x00
            .byte 0x0a, 0x00, 0x00, 0x00
            .byte 0x08, 0x00
            .ascii "hot-path"

          .section .reset,"ax"
          .code16
            ljmp $0xf000, $0x0000
          WHITEBOX_BIOS_ASM

          cat > app-random-bios.S <<'APP_RANDOM_BIOS_ASM'
          .section .text,"ax"
          .code16
          .global _start
          _start:
            cli
            pushw %cs
            popw %ds
            xorw %ax, %ax
            movw %ax, %es
            movw $random_request_rom, %si
            movw $0x5000, %di
            movw $27, %cx
            rep movsb
            movw %ax, %ds
            movl $0x5000, %eax
            movl $27, %ecx
            outb %al, $0xe7
            cmpl $0x4c425243, 0x5000
            je workload_loop
            pushw %cs
            popw %ds
            xorw %ax, %ax
            movw %ax, %es
            movw $reply_marker_rom, %si
            movw $0x5100, %di
            movw $26, %cx
            rep movsb
            movw %ax, %ds
            movl $0x5100, %eax
            movl $26, %ecx
            outb %al, $0xe7
          workload_loop:
            addl $0x9e3779b9, %eax
            roll $7, %eax
            xorl $0xa5a5a5a5, %eax
            outb %al, $0x80
            jmp workload_loop

          .align 16
          reply_marker_rom:
            .byte 0x43, 0x52, 0x42, 0x4c
            .byte 0x03, 0x00
            .byte 0x04, 0x00
            .byte 0x0e, 0x00, 0x00, 0x00
            .byte 0x0c, 0x00
            .ascii "random-reply"

          .align 16
          random_request_rom:
            .byte 0x43, 0x52, 0x42, 0x4c
            .byte 0x03, 0x00
            .byte 0x05, 0x00
            .byte 0x0f, 0x00, 0x00, 0x00
            .byte 0x04, 0x03, 0x02, 0x01
            .byte 0x03
            .byte 0x08, 0x00
            .ascii "live-rng"

          .section .reset,"ax"
          .code16
            ljmp $0xf000, $0x0000
          APP_RANDOM_BIOS_ASM

          cat > gate-bios.ld <<'GATE_BIOS_LD'
          OUTPUT_FORMAT(elf32-i386)
          ENTRY(_start)
          SECTIONS {
            . = 0;
            .text : { *(.text*) }
            . = 0xfff0;
            .reset : { *(.reset*) }
            . = 0xffff;
            .last : { BYTE(0) }
            /DISCARD/ : { *(.note*) *(.comment*) }
          }
          GATE_BIOS_LD

          mkdir -p "$out"
          as --32 whitebox-bios.S -o whitebox-bios.o
          ld -m elf_i386 -nostdlib -T gate-bios.ld \
            -o whitebox-bios.elf whitebox-bios.o
          objcopy -O binary whitebox-bios.elf "$out/whitebox-bios.bin"
          test "$(wc -c < "$out/whitebox-bios.bin")" -eq 65536
          as --32 app-random-bios.S -o app-random-bios.o
          ld -m elf_i386 -nostdlib -T gate-bios.ld \
            -o app-random-bios.elf app-random-bios.o
          objcopy -O binary app-random-bios.elf "$out/app-random-bios.bin"
          test "$(wc -c < "$out/app-random-bios.bin")" -eq 65536

          # QEMU's aarch64 virt direct-kernel loader enters a raw image at
          # 0x40080000. The image loads x0/x1 with the frame pointer/length,
          # executes the frozen inert hint #0x4c doorbell twice, proving the
          # first observation does not prevent later guest execution, then
          # remains live in a deterministic arithmetic loop.
          dd if=/dev/zero of="$out/whitebox-guest-aarch64.img" \
            bs=65536 count=1 status=none
          printf '%b' \
            '\000\001\000\130\301\002\200\322\237\051\003\325' \
            '\237\051\003\325\102\004\000\221\143\000\002\312' \
            '\376\377\377\027\037\040\003\325' \
            '\050\000\010\100\000\000\000\000' \
            '\103\122\102\114\003\000\004\000\012\000\000\000' \
            '\010\000hot-path' \
            | dd of="$out/whitebox-guest-aarch64.img" \
              conv=notrunc status=none
        '';
      }
    ];
  };

  rootImage = pkgs.mkDerivation {
    pname = "crucible-live-whitebox-doorbell-root-image";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.qemu-crucible];
    phases = [
      {
        name = "build-empty-qcow2";
        script = ''
          mkdir -p "$out"
          qemu-img create -q -f qcow2 "$out/root.qcow2" 64M
        '';
      }
    ];
  };

  flight = pkgs.mkDerivation {
    pname = "crucible-live-whitebox-doorbell-flight";
    version = "0";
    src = crucibleSrc;

    buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" \
            "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          cargo build --frozen --offline --release \
            --target-dir "$TMPDIR/live-whitebox-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-install \
            --example crucible-qemu-whitebox-map-validate
          mkdir -p "$out/bin"
          cp \
            "$TMPDIR/live-whitebox-target/release/examples/crucible-qemu-live-plugin-install" \
            "$TMPDIR/live-whitebox-target/release/examples/crucible-qemu-whitebox-map-validate" \
            "$out/bin/"
        '';
      }
    ];
  };
  testing = import ../../lib/testing {inherit pkgs lib;};
  vmTest = testing.mkVMTest {
    name = "crucible-phase2-qemu-live-whitebox-doorbell";
    memory = 3072;
    rootfsDeps = [
      flight
      guest
      rootImage
      pkgs.qemu-crucible
      pkgs.crucible-qemu-plugin
      pkgs.linux
      pkgs.e2fsprogs
      pkgs.coreutils
      pkgs.util-linux
      pkgs.grep
      pkgs.sed
    ];
    testScript = ''
            set -eu
            export TMPDIR=/tmp
            for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
              grep -Fxq "CONFIG_$option=y" ${pkgs.linux}/boot/config-*
            done
            mkdir -p /sys/fs/cgroup
            ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
            echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
            mkdir /sys/fs/cgroup/crucible
            echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control

            truncate -s 3G /tmp/attempts.img
            ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
              -E quotatype=prjquota /tmp/attempts.img
            mkdir /tmp/attempts
            ${pkgs.util-linux}/bin/mount -o loop,prjquota \
              /tmp/attempts.img /tmp/attempts
            mkdir -m 700 /tmp/attempts/run
            evidence_dir=/tmp/live-whitebox-evidence
            mkdir "$evidence_dir"
            installer_launches=0

      run_mode() {
        label="$1"
        mode="$2"
        report="$TMPDIR/live-whitebox-$label.result"
        qemu_log="$TMPDIR/live-whitebox-$label.qemu.log"
        if ! CRUCIBLE_LIVE_PLUGIN_WHITEBOX="$mode" \
          CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=on \
          CRUCIBLE_LIVE_PLUGIN_FIRMWARE_BOOT=on \
          ${pkgs.coreutils}/bin/timeout -k 15 180 \
          ${flight}/bin/crucible-qemu-live-plugin-install \
          ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
          ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
          ${guest}/whitebox-bios.bin \
          ${rootImage}/root.qcow2 \
          /sys/fs/cgroup/crucible \
          /tmp/attempts/run 65534 65534 \
          > "$report" 2> "$qemu_log"; then
          cat "$report" >&2
          cat "$qemu_log" >&2
          exit 1
        fi
        installer_launches=$((installer_launches + 1))
        cat "$report"
        grep -Fxq PASS "$report"
        grep -Fxq "whitebox=$mode" "$report"
        if [ "$mode" = on ]; then
          grep -Fxq 'whitebox_setup_region=io' "$report"
          grep -Fxq 'whitebox_marker_count=1' "$report"
          grep -Fxq 'whitebox_marker_point=hot-path' "$report"
        else
          grep -Fxq 'whitebox_setup_region=not-required' "$report"
          grep -Fxq 'whitebox_marker_count=0' "$report"
          grep -Fxq 'whitebox_marker_icount=not-observed' "$report"
          grep -Fxq 'whitebox_marker_point=not-observed' "$report"
        fi
        grep -Fxq 'fingerprint=on' "$report"
        grep -Fxq 'plugin_loaded=rust-control-cdylib' "$report"
        grep -Fxq 'setup_ack_ready=true' "$report"
        grep -Fxq 'boot_barrier_ceiling_enforced=true' "$report"
        grep -Fxq 'orderly_child_exit=true' "$report"
      }

      run_mode off off
      run_mode on on
      run_mode off-repeat off
      run_mode on-repeat on

      aarch64_report="$TMPDIR/live-whitebox-aarch64.result"
      aarch64_log="$TMPDIR/live-whitebox-aarch64.qemu.log"
      if ! CRUCIBLE_LIVE_PLUGIN_GUEST_ARCH=aarch64 \
        CRUCIBLE_LIVE_PLUGIN_WHITEBOX=on \
        CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=off \
        ${pkgs.coreutils}/bin/timeout -k 15 180 \
        ${flight}/bin/crucible-qemu-live-plugin-install \
        ${pkgs.qemu-crucible}/bin/qemu-system-aarch64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${guest}/whitebox-guest-aarch64.img \
        ${rootImage}/root.qcow2 \
        /sys/fs/cgroup/crucible \
          /tmp/attempts/run 65534 65534 \
        > "$aarch64_report" 2> "$aarch64_log"; then
        cat "$aarch64_report" >&2
        cat "$aarch64_log" >&2
        exit 1
      fi
      installer_launches=$((installer_launches + 1))
      cat "$aarch64_report"
      grep -Fxq PASS "$aarch64_report"
      grep -Fxq 'whitebox=on' "$aarch64_report"
      grep -Fxq 'whitebox_setup_region=aarch64-hint-4c-inert' "$aarch64_report"
      grep -Fxq 'whitebox_marker_count=2' "$aarch64_report"
      grep -Fxq 'whitebox_marker_point=hot-path' "$aarch64_report"
      grep -Fxq 'fingerprint=off' "$aarch64_report"
      grep -Fxq 'execution_fingerprint=not-observed' "$aarch64_report"
      grep -Fxq 'boot_barrier_ceiling_enforced=true' "$aarch64_report"
      grep -Fxq 'orderly_child_exit=true' "$aarch64_report"
      aarch64_first_icount=$(sed -n \
        's/^whitebox_marker_icount=\([0-9][0-9]*\)$/\1/p' "$aarch64_report")
      aarch64_last_icount=$(sed -n \
        's/^whitebox_last_marker_icount=\([0-9][0-9]*\)$/\1/p' "$aarch64_report")
      test -n "$aarch64_first_icount"
      test "$aarch64_last_icount" -eq "$((aarch64_first_icount + 1))"

      aarch64_repeat_report="$TMPDIR/live-whitebox-aarch64-repeat.result"
      aarch64_repeat_log="$TMPDIR/live-whitebox-aarch64-repeat.qemu.log"
      if ! CRUCIBLE_LIVE_PLUGIN_GUEST_ARCH=aarch64 \
        CRUCIBLE_LIVE_PLUGIN_WHITEBOX=on \
        CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=off \
        ${pkgs.coreutils}/bin/timeout -k 15 180 \
        ${flight}/bin/crucible-qemu-live-plugin-install \
        ${pkgs.qemu-crucible}/bin/qemu-system-aarch64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${guest}/whitebox-guest-aarch64.img \
        ${rootImage}/root.qcow2 \
        /sys/fs/cgroup/crucible \
          /tmp/attempts/run 65534 65534 \
        > "$aarch64_repeat_report" 2> "$aarch64_repeat_log"; then
        cat "$aarch64_repeat_report" >&2
        cat "$aarch64_repeat_log" >&2
        exit 1
      fi
      installer_launches=$((installer_launches + 1))
      cat "$aarch64_repeat_report"
      grep -Fxq PASS "$aarch64_repeat_report"
      grep -Fxq 'whitebox_marker_count=2' "$aarch64_repeat_report"
      grep -Fxq 'execution_fingerprint=not-observed' "$aarch64_repeat_report"
      repeat_first_icount=$(sed -n \
        's/^whitebox_marker_icount=\([0-9][0-9]*\)$/\1/p' "$aarch64_repeat_report")
      repeat_last_icount=$(sed -n \
        's/^whitebox_last_marker_icount=\([0-9][0-9]*\)$/\1/p' "$aarch64_repeat_report")
      test "$repeat_first_icount" = "$aarch64_first_icount"
      test "$repeat_last_icount" = "$aarch64_last_icount"

      aarch64_off_report="$TMPDIR/live-whitebox-aarch64-off.result"
      aarch64_off_log="$TMPDIR/live-whitebox-aarch64-off.qemu.log"
      if ! CRUCIBLE_LIVE_PLUGIN_GUEST_ARCH=aarch64 \
        CRUCIBLE_LIVE_PLUGIN_WHITEBOX=off \
        CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=off \
        ${pkgs.coreutils}/bin/timeout -k 15 180 \
        ${flight}/bin/crucible-qemu-live-plugin-install \
        ${pkgs.qemu-crucible}/bin/qemu-system-aarch64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${guest}/whitebox-guest-aarch64.img \
        ${rootImage}/root.qcow2 \
        /sys/fs/cgroup/crucible \
          /tmp/attempts/run 65534 65534 \
        > "$aarch64_off_report" 2> "$aarch64_off_log"; then
        cat "$aarch64_off_report" >&2
        cat "$aarch64_off_log" >&2
        exit 1
      fi
      installer_launches=$((installer_launches + 1))
      cat "$aarch64_off_report"
      grep -Fxq PASS "$aarch64_off_report"
      grep -Fxq 'whitebox=off' "$aarch64_off_report"
      grep -Fxq 'whitebox_setup_region=not-required' "$aarch64_off_report"
      grep -Fxq 'whitebox_marker_count=0' "$aarch64_off_report"
      grep -Fxq 'execution_fingerprint=not-observed' "$aarch64_off_report"
      grep -Fxq 'whitebox_marker_icount=not-observed' "$aarch64_off_report"
      grep -Fxq 'whitebox_last_marker_icount=not-observed' "$aarch64_off_report"
      grep -Fxq 'boot_barrier_ceiling_enforced=true' "$aarch64_off_report"
      grep -Fxq 'orderly_child_exit=true' "$aarch64_off_report"
      if grep -q '^CRUCIBLE_WHITEBOX_' "$aarch64_off_log"; then
        echo "FAIL: disabled AArch64 HINT triggered white-box callback I/O" >&2
        exit 1
      fi

      app_random_report="$TMPDIR/live-whitebox-app-random.result"
      app_random_log="$TMPDIR/live-whitebox-app-random.qemu.log"
      if ! CRUCIBLE_LIVE_PLUGIN_WHITEBOX=on \
        CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=on \
        CRUCIBLE_LIVE_PLUGIN_FIRMWARE_BOOT=on \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_SEED=1048598 \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_CAP=1 \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_NODE=plugin-install-gate-vm \
        ${pkgs.coreutils}/bin/timeout -k 15 180 \
        ${flight}/bin/crucible-qemu-live-plugin-install \
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${guest}/app-random-bios.bin \
        ${rootImage}/root.qcow2 \
        /sys/fs/cgroup/crucible \
          /tmp/attempts/run 65534 65534 \
        > "$app_random_report" 2> "$app_random_log"; then
        cat "$app_random_report" >&2
        cat "$app_random_log" >&2
        exit 1
      fi
      installer_launches=$((installer_launches + 1))
      cat "$app_random_report"
      grep -Fxq PASS "$app_random_report"
      grep -Fxq 'app_random_decision_count=1' "$app_random_report"
      grep -Fxq 'app_random_request_id=16909060' "$app_random_report"
      grep -Eq '^app_random_values=[0-9]+$' "$app_random_report"
      grep -Fxq 'app_random_width_bits=24' "$app_random_report"
      grep -Fxq 'whitebox_marker_count=1' "$app_random_report"
      grep -Fxq 'whitebox_marker_point=random-reply' "$app_random_report"

      app_random_branch_report="$TMPDIR/live-whitebox-app-random-branch.result"
      app_random_branch_log="$TMPDIR/live-whitebox-app-random-branch.qemu.log"
      if ! CRUCIBLE_LIVE_PLUGIN_WHITEBOX=on \
        CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=on \
        CRUCIBLE_LIVE_PLUGIN_FIRMWARE_BOOT=on \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_SEED=11 \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_CAP=1 \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_NODE=plugin-install-gate-vm \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_BRANCH_SEEDS=1048598 \
        CRUCIBLE_LIVE_PLUGIN_APP_RANDOM_BRANCH_AFTERS=0 \
        ${pkgs.coreutils}/bin/timeout -k 15 180 \
        ${flight}/bin/crucible-qemu-live-plugin-install \
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
        ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
        ${guest}/app-random-bios.bin \
        ${rootImage}/root.qcow2 \
        /sys/fs/cgroup/crucible \
          /tmp/attempts/run 65534 65534 \
        > "$app_random_branch_report" 2> "$app_random_branch_log"; then
        cat "$app_random_branch_report" >&2
        cat "$app_random_branch_log" >&2
        exit 1
      fi
      installer_launches=$((installer_launches + 1))
      cat "$app_random_branch_report"
      grep -Fxq PASS "$app_random_branch_report"
      grep -Fxq 'app_random_decision_count=1' "$app_random_branch_report"
      original_app_random_values=$(sed -n 's/^app_random_values=//p' "$app_random_report")
      branch_app_random_values=$(sed -n 's/^app_random_values=//p' "$app_random_branch_report")
      test -n "$original_app_random_values"
      test "$branch_app_random_values" = "$original_app_random_values"

      collision_map="$TMPDIR/live-whitebox-collision.mtree"
      collision_result="$TMPDIR/live-whitebox-collision.result"
      collision_error="$TMPDIR/live-whitebox-collision.error"
      printf 'info mtree -f\nquit\n' |
        ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
          -machine pc-q35-9.2 \
          -accel sim,thread=single \
          -icount shift=0,sleep=off,align=off,rr_switch_quantum=4096 \
          -S \
          -display none \
          -monitor stdio \
          -nodefaults \
          -chardev null,id=collision \
          -device isa-debugcon,iobase=0xe7,chardev=collision \
          > "$collision_map" 2> "$TMPDIR/live-whitebox-collision.qemu.log"
      grep -Eq '00e7-00000000000000e7 .*: isa-debugcon' "$collision_map"
      if ${flight}/bin/crucible-qemu-whitebox-map-validate \
        "$collision_map" > "$collision_result" 2> "$collision_error"; then
        echo "FAIL: mapped white-box doorbell port passed setup validation" >&2
        exit 1
      fi
      grep -Fxq \
        'FAIL: reserved white-box port 0x00e7 collides with QEMU region `isa-debugcon`' \
        "$collision_error"

      if grep -q '^CRUCIBLE_WHITEBOX_' "$TMPDIR/live-whitebox-off.qemu.log" \
        || grep -q '^CRUCIBLE_WHITEBOX_' "$TMPDIR/live-whitebox-on.qemu.log"; then
        echo "FAIL: white-box callback performed diagnostic I/O" >&2
        exit 1
      fi

      marker_icount=$(sed -n 's/^whitebox_marker_icount=\([0-9][0-9]*\)$/\1/p' \
        "$TMPDIR/live-whitebox-on.result")
      test -n "$marker_icount"
      off_fingerprint=$(sed -n 's/^execution_fingerprint=//p' "$TMPDIR/live-whitebox-off.result")
      off_repeat_fingerprint=$(sed -n 's/^execution_fingerprint=//p' \
        "$TMPDIR/live-whitebox-off-repeat.result")
      on_fingerprint=$(sed -n 's/^execution_fingerprint=//p' "$TMPDIR/live-whitebox-on.result")
      on_repeat_fingerprint=$(sed -n 's/^execution_fingerprint=//p' \
        "$TMPDIR/live-whitebox-on-repeat.result")
      test -n "$off_fingerprint"
      test "$off_repeat_fingerprint" = "$off_fingerprint"
      test "$on_repeat_fingerprint" = "$on_fingerprint"
      test "$off_fingerprint" = "$on_fingerprint"

      mkdir -p "$evidence_dir"
      cp "$TMPDIR/live-whitebox-off.result" "$evidence_dir/install-off-result"
      cp "$TMPDIR/live-whitebox-off-repeat.result" "$evidence_dir/install-off-repeat-result"
      cp "$TMPDIR/live-whitebox-on.result" "$evidence_dir/install-on-result"
      cp "$TMPDIR/live-whitebox-on-repeat.result" "$evidence_dir/install-on-repeat-result"
      cp "$TMPDIR/live-whitebox-off.qemu.log" "$evidence_dir/qemu-off.log"
      cp "$TMPDIR/live-whitebox-off-repeat.qemu.log" "$evidence_dir/qemu-off-repeat.log"
      cp "$TMPDIR/live-whitebox-on.qemu.log" "$evidence_dir/qemu-on.log"
      cp "$TMPDIR/live-whitebox-on-repeat.qemu.log" "$evidence_dir/qemu-on-repeat.log"
      cp "$aarch64_report" "$evidence_dir/install-aarch64-result"
      cp "$aarch64_log" "$evidence_dir/qemu-aarch64.log"
      cp "$aarch64_repeat_report" "$evidence_dir/install-aarch64-repeat-result"
      cp "$aarch64_repeat_log" "$evidence_dir/qemu-aarch64-repeat.log"
      cp "$aarch64_off_report" "$evidence_dir/install-aarch64-off-result"
      cp "$aarch64_off_log" "$evidence_dir/qemu-aarch64-off.log"
      cp "$app_random_report" "$evidence_dir/app-random-result"
      cp "$app_random_log" "$evidence_dir/qemu-app-random.log"
      cp "$app_random_branch_report" "$evidence_dir/app-random-branch-result"
      cp "$app_random_branch_log" "$evidence_dir/qemu-app-random-branch.log"
      cp "$collision_map" "$evidence_dir/collision.mtree"
      cp "$collision_error" "$evidence_dir/collision.error"
      cp "$TMPDIR/live-whitebox-collision.qemu.log" "$evidence_dir/qemu-collision.log"
      {
        printf 'PASS\n'
        printf 'attr_path=%s\n' "${attrPath}"
        printf 'task_ids=%s\n' "${builtins.concatStringsSep "," taskIds}"
        printf 'open_task_ids=%s\n' "${builtins.concatStringsSep "," openTaskIds}"
        printf 'status=complete\n'
        printf 'plugin_loaded=rust-control-cdylib\n'
        test "$installer_launches" -eq 9
        printf 'installer_launches=%s\n' "$installer_launches"
        printf 'whitebox_modes=off,on\n'
        printf 'off_mode_callback_records=0\n'
        printf 'setup_port_map_probe=stopped-plugin-free-exact-machine\n'
        printf 'setup_reserved_port_region=io\n'
        printf 'setup_attestation=x86-port-00e7-unclaimed-v1\n'
        printf 'collision_negative_device=isa-debugcon\n'
        printf 'collision_negative_rejected_before_plugin_launch=true\n'
        printf 'doorbell_architecture=x86_64\n'
        printf 'doorbell_instruction=out-imm8-al\n'
        printf 'doorbell_port=0x00e7\n'
        printf 'payload_registers=rax,rcx\n'
        printf 'guest_memory_api=qemu_plugin_read_memory_vaddr\n'
        printf 'marker_kind=coverage\n'
        printf 'marker_transport=plugin-to-host-shmem-spsc\n'
        printf 'marker_host_consumer=quantum-boundary\n'
        printf 'marker_event_log_admission=true\n'
        printf 'marker_icount=%s\n' "$marker_icount"
        printf 'marker_payload_len=10\n'
        printf 'exact_icount_callback=true\n'
        printf 'fingerprint_sampling=production-plugin\n'
        printf 'off_fingerprint=%s\n' "$off_fingerprint"
        printf 'on_fingerprint=%s\n' "$on_fingerprint"
        printf 'off_on_fingerprint_equal=true\n'
        printf 'production_whitebox_channel_implemented=x86_64,aarch64\n'
        printf 'aarch64_setup_attestation=aarch64-hint-4c-inert-v1\n'
        printf 'aarch64_doorbell_instruction=hint-0x4c\n'
        printf 'aarch64_repeated_doorbells=2\n'
        printf 'aarch64_adjacent_marker_icounts=true\n'
        printf 'aarch64_marker_icounts_reproducible=true\n'
        printf 'aarch64_whitebox_off_inert=true\n'
        printf 'aarch64_payload_registers=x0,x1\n'
        printf 'aarch64_live_marker_observed=true\n'
        printf 'aarch64_boot_barrier_ceiling_enforced=true\n'
        printf 'app_random_live_decisions=1\n'
        printf 'app_random_guest_reply_observed=true\n'
        printf 'app_random_host_seed_reconstruction=true\n'
        printf 'app_random_branch_sequence_live_qemu=true\n'
        printf 'app_random_branch_sequence_values=%s\n' "$branch_app_random_values"
        printf 'app_random_reply_api=qemu_plugin_crucible_write_memory_vaddr\n'
      } > "$evidence_dir/result"

            emit_evidence() {
              name="$1"
              path="$2"
              printf 'CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_BEGIN:%s\n' "$name"
              cat "$path"
              printf 'CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_END:%s\n' "$name"
            }
            for name in \
              result \
              install-off-result \
              install-off-repeat-result \
              install-on-result \
              install-on-repeat-result \
              install-aarch64-result \
              install-aarch64-repeat-result \
              install-aarch64-off-result \
              app-random-result \
              app-random-branch-result \
              qemu-off.log \
              qemu-off-repeat.log \
              qemu-on.log \
              qemu-on-repeat.log \
              qemu-aarch64.log \
              qemu-aarch64-repeat.log \
              qemu-aarch64-off.log \
              qemu-app-random.log \
              qemu-app-random-branch.log \
              qemu-collision.log \
              collision.mtree \
              collision.error; do
              emit_evidence "$name" "$evidence_dir/$name"
            done
            ${pkgs.util-linux}/bin/umount /tmp/attempts
    '';
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-whitebox-doorbell";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed vmTest];
    passthru = {inherit flight guest rootImage;};
    phases = [
      {
        name = "retain-vm-evidence";
        script = ''
          set -eu
          normalized_serial="$TMPDIR/vm-serial.normalized.log"
          ${pkgs.sed}/bin/sed 's/\r$//' \
            "${vmTest}/serial.log" > "$normalized_serial"

          extract_evidence() {
            name="$1"
            begin="CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_BEGIN:$name"
            end="CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_END:$name"
            test "$(grep -Fxc "$begin" "$normalized_serial")" -eq 1
            test "$(grep -Fxc "$end" "$normalized_serial")" -eq 1
            ${pkgs.sed}/bin/sed -n \
              "/^CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_BEGIN:$name\$/,/^CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_END:$name\$/ {
                /^CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_BEGIN:/d
                /^CRUCIBLE_LIVE_WHITEBOX_EVIDENCE_END:/d
                p
              }" "$normalized_serial" > "$out/$name"
          }

          mkdir -p "$out"
          for name in \
            result \
            install-off-result \
            install-off-repeat-result \
            install-on-result \
            install-on-repeat-result \
            install-aarch64-result \
            install-aarch64-repeat-result \
            install-aarch64-off-result \
            app-random-result \
            app-random-branch-result \
            qemu-off.log \
            qemu-off-repeat.log \
            qemu-on.log \
            qemu-on-repeat.log \
            qemu-aarch64.log \
            qemu-aarch64-repeat.log \
            qemu-aarch64-off.log \
            qemu-app-random.log \
            qemu-app-random-branch.log \
            qemu-collision.log \
            collision.mtree \
            collision.error; do
            extract_evidence "$name"
          done
          cp "${vmTest}/serial.log" "$out/vm-serial.log"
          cp "${vmTest}/fc.log" "$out/vm-monitor.log"
          grep -Fxq PASS "$out/result"
          grep -Fxq 'status=complete' "$out/result"
          grep -Fxq 'installer_launches=9' "$out/result"
        '';
      }
    ];
  }
