{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLiveWhiteboxDoorbell",
  taskIds ? ["T-GHC-6"],
  openTaskIds ? ["T-PLUG-14" "T-GHC-4"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  guest = pkgs.mkDerivation {
    pname = "crucible-live-whitebox-doorbell-guest";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils];

    phases = [
      {
        name = "build-whitebox-multiboot-guest";
        script = ''
          set -eu
          cat > guest.S <<'GUEST_ASM'
          .section .multiboot,"a"
          .align 4
          .long 0x1badb002
          .long 0x00000003
          .long -(0x1badb002 + 0x00000003)

          .section .text,"ax"
          .code32
          .global _start
          _start:
            cli
            movl $stack_top, %esp
            movl $whitebox_frame, %eax
            movl $22, %ecx
            movl $0x00e7, %edx
            outl %eax, %dx
            xorl %eax, %eax
          workload_loop:
            addl $0x9e3779b9, %eax
            roll $7, %eax
            xorl $0xa5a5a5a5, %eax
            movl %eax, scratch
            movl scratch, %edx
            movb %al, 0x000b8000
            outb %al, $0x80
            jmp workload_loop

          .section .rodata
          .align 16
          whitebox_frame:
            .byte 0x43, 0x52, 0x42, 0x4c
            .byte 0x02, 0x00
            .byte 0x04, 0x00
            .byte 0x0a, 0x00, 0x00, 0x00
            .byte 0x08, 0x00
            .ascii "hot-path"

          .section .bss
          .align 16
          scratch:
            .skip 4
          stack_bottom:
            .skip 16384
          stack_top:
          GUEST_ASM

          cat > guest.ld <<'GUEST_LD'
          ENTRY(_start)
          PHDRS {
            text PT_LOAD FLAGS(5);
            data PT_LOAD FLAGS(6);
          }
          SECTIONS {
            . = 0x00100000;
            .multiboot : { KEEP(*(.multiboot)) } :text
            .text : { *(.text*) } :text
            .rodata : { *(.rodata*) } :text
            . = ALIGN(0x1000);
            .data : { *(.data*) } :data
            .bss : { *(.bss*) *(COMMON) } :data
          }
          GUEST_LD

          mkdir -p "$out"
          as --32 guest.S -o guest.o
          ld -m elf_i386 -nostdlib -T guest.ld -o "$out/whitebox-guest.elf" guest.o
          strip --strip-all "$out/whitebox-guest.elf"
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
          qemu-img create -q -f qcow2 "$out/overlay.qcow2" 64M
        '';
      }
    ];
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-whitebox-doorbell";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible-qemu-plugin
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
    ];

    TASK_IDS = builtins.concatStringsSep "," taskIds;
    OPEN_TASK_IDS = builtins.concatStringsSep "," openTaskIds;
    ATTR_PATH = attrPath;

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
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-live-whitebox-doorbell";
        script = ''
          set -eu
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi

          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/live-whitebox-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-qemu \
            --example crucible-qemu-live-plugin-install \
            --example crucible-qemu-whitebox-map-validate

          run_mode() {
            label="$1"
            mode="$2"
            run_dir="$TMPDIR/live-whitebox-$label"
            report="$TMPDIR/live-whitebox-$label.result"
            qemu_log="$TMPDIR/live-whitebox-$label.qemu.log"
            mkdir -p "$run_dir"
            cp ${rootImage}/overlay.qcow2 "$run_dir/crucible-root-overlay.qcow2"
            chmod u+w "$run_dir/crucible-root-overlay.qcow2"
            if ! CRUCIBLE_LIVE_PLUGIN_WHITEBOX="$mode" \
              CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=on \
              timeout -k 15 180 \
              "$TMPDIR/live-whitebox-target/debug/examples/crucible-qemu-live-plugin-install" \
              ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
              ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
              ${guest}/whitebox-guest.elf \
              ${rootImage}/root.qcow2 \
              "$run_dir" \
              > "$report" 2> "$qemu_log"; then
              cat "$report" >&2
              cat "$qemu_log" >&2
              exit 1
            fi
            grep -Fxq PASS "$report"
            grep -Fxq "whitebox=$mode" "$report"
            if [ "$mode" = on ]; then
              grep -Fxq 'whitebox_setup_region=io' "$report"
            else
              grep -Fxq 'whitebox_setup_region=not-required' "$report"
            fi
            grep -Fxq 'fingerprint=on' "$report"
            grep -Fxq 'plugin_loaded=rust-control-cdylib' "$report"
            grep -Fxq 'setup_ack_ready=true' "$report"
            grep -Fxq 'boot_barrier_ceiling_enforced=true' "$report"
            grep -Fxq 'orderly_child_exit=true' "$report"
          }

          run_mode off off
          run_mode on on

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
          if "$TMPDIR/live-whitebox-target/debug/examples/crucible-qemu-whitebox-map-validate" \
            "$collision_map" > "$collision_result" 2> "$collision_error"; then
            echo "FAIL: mapped white-box doorbell port passed setup validation" >&2
            exit 1
          fi
          grep -Fxq \
            'FAIL: reserved white-box port 0x00e7 collides with QEMU region `isa-debugcon`' \
            "$collision_error"

          if grep -q '^CRUCIBLE_WHITEBOX_' "$TMPDIR/live-whitebox-off.qemu.log"; then
            echo "FAIL: white-box off mode emitted a callback record" >&2
            exit 1
          fi
          grep -Eq '^CRUCIBLE_WHITEBOX_MARKER icount=[1-9][0-9]* vcpu=0 kind=4 payload_len=10$' \
            "$TMPDIR/live-whitebox-on.qemu.log"

          marker_icount=$(sed -n 's/^CRUCIBLE_WHITEBOX_MARKER icount=\([0-9][0-9]*\) .*/\1/p' \
            "$TMPDIR/live-whitebox-on.qemu.log")
          test -n "$marker_icount"
          off_fingerprint=$(sed -n 's/^execution_fingerprint=//p' "$TMPDIR/live-whitebox-off.result")
          on_fingerprint=$(sed -n 's/^execution_fingerprint=//p' "$TMPDIR/live-whitebox-on.result")
          test -n "$off_fingerprint"
          test "$off_fingerprint" = "$on_fingerprint"

          mkdir -p "$out"
          cp "$TMPDIR/live-whitebox-off.result" "$out/install-off-result"
          cp "$TMPDIR/live-whitebox-on.result" "$out/install-on-result"
          cp "$TMPDIR/live-whitebox-off.qemu.log" "$out/qemu-off.log"
          cp "$TMPDIR/live-whitebox-on.qemu.log" "$out/qemu-on.log"
          cp "$collision_map" "$out/collision.mtree"
          cp "$collision_error" "$out/collision.error"
          {
            printf 'PASS\n'
            printf 'attr_path=%s\n' "$ATTR_PATH"
            printf 'task_ids=%s\n' "$TASK_IDS"
            printf 'open_task_ids=%s\n' "$OPEN_TASK_IDS"
            printf 'status=partial\n'
            printf 'plugin_loaded=rust-control-cdylib\n'
            printf 'whitebox_modes=off,on\n'
            printf 'off_mode_callback_records=0\n'
            printf 'setup_port_map_probe=stopped-plugin-free-exact-machine\n'
            printf 'setup_reserved_port_region=io\n'
            printf 'setup_attestation=x86-port-00e7-unclaimed-v1\n'
            printf 'collision_negative_device=isa-debugcon\n'
            printf 'collision_negative_rejected_before_plugin_launch=true\n'
            printf 'doorbell_architecture=x86_64\n'
            printf 'doorbell_instruction=out-dx-eax\n'
            printf 'doorbell_port=0x00e7\n'
            printf 'payload_registers=rax,rcx\n'
            printf 'port_register=rdx\n'
            printf 'guest_memory_api=qemu_plugin_read_memory_vaddr\n'
            printf 'marker_kind=coverage\n'
            printf 'marker_icount=%s\n' "$marker_icount"
            printf 'marker_payload_len=10\n'
            printf 'exact_icount_callback=true\n'
            printf 'fingerprint_sampling=production-plugin\n'
            printf 'off_fingerprint=%s\n' "$off_fingerprint"
            printf 'on_fingerprint=%s\n' "$on_fingerprint"
            printf 'off_on_fingerprint_equal=true\n'
            printf 'production_whitebox_channel_implemented=x86_64-live-slice\n'
          } > "$out/result"
        '';
      }
    ];
  }
