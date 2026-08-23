{
  pkgs,
  guestVcpus ? 4,
  guestIdle ? true,
  startAps ? true,
}: let
  apStartup =
    if guestVcpus == 1 || !startAps
    then "bsp-only"
    else "directed-init-sipi-sipi";
  startApplicationProcessors =
    if guestVcpus == 1 || !startAps
    then ""
    else ''
        /*
         * The live gate observes COM1 as an output-only stream. The rendezvous
         * below emits A^(N-1) B P^(N-1) R. After every AP is actively
         * contending on a held lock, the BSP releases it, executes PAUSE, and
         * immediately attempts to reacquire it. Success emits F and parks the
         * BSP forever. A passing stream therefore proves a waiter ran in the
         * zero-instruction interval between PAUSE and the BSP's next guest
         * instruction; an ordinary 4096-instruction quantum handoff is too late.
         */
        movw $0, 0x7000
        movw $1, 0x7002
        movw $0, 0x7004
        movw $0, 0x7006
        movw $0, 0x7008
        movw $0x3f9, %dx
        movb $0, %al
        outb %al, %dx
        movw $0x3fb, %dx
        movb $0x80, %al
        outb %al, %dx
        movw $0x3f8, %dx
        movb $1, %al
        outb %al, %dx
        movw $0x3f9, %dx
        movb $0, %al
        outb %al, %dx
        movw $0x3fb, %dx
        movb $0x03, %al
        outb %al, %dx

        /*
         * Keep every ELF PT_LOAD segment above the option-ROM window. QEMU's
         * multiboot loader exposes the complete elf_low..elf_high span through
         * one fw_cfg DMA transfer, including sparse zero-filled gaps. A low
         * PT_LOAD at the SIPI vector would therefore overwrite the executing
         * multiboot option ROM at 0xc0000. Copy this position-independent
         * trampoline into low RAM from the compact high load segment instead.
         */
        movl $ap_trampoline_start, %esi
        movl $0x00008000, %edi
        movl $(ap_trampoline_end - ap_trampoline_start), %ecx
        rep movsb

        /* Start APIC IDs 1..${toString (guestVcpus - 1)} at the real-mode trampoline on vector 8. */
        movl $1, %ecx
      start_next_ap:
        movl %ecx, %eax
        shll $24, %eax
        movl %eax, 0xfee00310
        movl $0x0000c500, 0xfee00300
        call wait_for_icr
        movl $0x00008500, 0xfee00300
        call wait_for_icr
        movl $0x00000608, 0xfee00300
        call wait_for_icr
        movl $0x00000608, 0xfee00300
        call wait_for_icr
        incl %ecx
      cmpl ${"$"}${toString guestVcpus}, %ecx
        jne start_next_ap

      wait_for_all_aps_online:
        cmpw ${"$"}${toString (guestVcpus - 1)}, 0x7000
        je all_aps_online
        pause
        jmp wait_for_all_aps_online
      all_aps_online:
        movb $'B', %al
        call serial_byte
        xorw %ax, %ax
        movw $1, %cx
        movw $0, 0x7002
        pause

        /* The very next guest instruction must observe a waiter's lock. */
        lock cmpxchgw %cx, 0x7002
        jne pause_handoff_proven
        movb $'F', %al
        call serial_byte
      pause_handoff_failed:
        cli
        hlt
        jmp pause_handoff_failed

      pause_handoff_proven:
        movw $1, 0x7006

      wait_for_all_aps_past_pause:
        cmpw ${"$"}${toString (guestVcpus - 1)}, 0x7008
        je all_aps_past_pause
        pause
        jmp wait_for_all_aps_past_pause
      all_aps_past_pause:
        cmpw ${"$"}${toString (guestVcpus - 1)}, 0x7004
        jne pause_handoff_failed
        movb $'R', %al
        call serial_byte
    '';
  bspRunLoop =
    if guestIdle
    then ''
        /* Install an interrupt gate for the remapped PIT IRQ. */
        movl $irq0, %eax
        movw %ax, idt + (0x20 * 8)
        movw %cs, %ax
        movw %ax, idt + (0x20 * 8) + 2
        movb $0, idt + (0x20 * 8) + 4
        movb $0x8e, idt + (0x20 * 8) + 5
        movl $irq0, %eax
        shrl $16, %eax
        movw %ax, idt + (0x20 * 8) + 6
        lidt idtr

        /* Remap the 8259 PIC and unmask only IRQ0. */
        movb $0x11, %al
        outb %al, $0x20
        outb %al, $0xa0
        movb $0x20, %al
        outb %al, $0x21
        movb $0x28, %al
        outb %al, $0xa1
        movb $0x04, %al
        outb %al, $0x21
        movb $0x02, %al
        outb %al, $0xa1
        movb $0x01, %al
        outb %al, $0x21
        outb %al, $0xa1
        movb $0xfe, %al
        outb %al, $0x21
        movb $0xff, %al
        outb %al, $0xa1

        /* PIT channel 0, mode 2, roughly 100 Hz. */
        movb $0x34, %al
        outb %al, $0x43
        movw $11932, %ax
        outb %al, $0x40
        movb %ah, %al
        outb %al, $0x40

      bsp_idle:
        sti
        hlt
        jmp bsp_idle
    ''
    else ''
        movl $0x51f15eed, %eax
      bsp_busy:
        roll $13, %eax
        xorl $0x9e3779b9, %eax
        addl $0x6d2b79f5, %eax
        jmp bsp_busy
    '';
  apRunLoop =
    if guestIdle
    then ''
      ap_idle:
        hlt
        jmp ap_idle
    ''
    else ''
        movw $0x51f1, %ax
      ap_busy:
        rolw $5, %ax
        xorw $0x79b9, %ax
        addw $0x5eed, %ax
        jmp ap_busy
    '';
  guestActivity =
    if guestIdle
    then "all-vcpus-hlt"
    else if startAps
    then "all-vcpus-busy"
    else "bsp-busy-aps-halted";
  guestDeadline =
    if guestIdle
    then "periodic-pit-channel-0"
    else "none";
in
  assert guestVcpus >= 1 && guestVcpus <= 4;
  # A diskless multiboot guest that optionally starts application processors.
  # Idle mode parks every configured vCPU with HLT and gives the BSP a periodic
  # PIT deadline; busy mode keeps the BSP, and optionally every started AP,
  # executing a fixed register-only loop. These modes keep scheduler proofs
  # independent of Linux boot policy.
    pkgs.mkDerivation {
      pname = "crucible-live-plugin-quantum-${toString guestVcpus}vcpu-${
        if guestIdle
        then "idle"
        else "busy"
      }-${
        if startAps
        then "smp"
        else "bsp-only"
      }-guest";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "build-smp-idle-multiboot-guest";
          script = ''
            set -eu
            cat > guest.S <<'GUEST_ASM'
            .section .text,"ax"
            .code32
            .global _start
            _start:
              cli
              movl $stack_top, %esp

              ${startApplicationProcessors}

            ${bspRunLoop}

            wait_for_icr:
              movl 0xfee00300, %eax
              testl $0x1000, %eax
              jnz wait_for_icr
              ret

            serial_byte:
              pushl %eax
            serial_wait:
              movw $0x3fd, %dx
              inb %dx, %al
              testb $0x20, %al
              jz serial_wait
              popl %eax
              movw $0x3f8, %dx
              outb %al, %dx
              ret

            irq0:
              pushal
              movb $0x20, %al
              outb %al, $0x20
              popal
              iret

            .section .rodata
            .align 4
            idtr:
              .word (33 * 8) - 1
              .long idt

            .section .bss
            .align 16
            idt:
              .skip 33 * 8
            stack_bottom:
              .skip 16384
            stack_top:

            /*
             * SIPI enters real mode at vector << 12. APs deliberately keep
             * interrupts masked after reaching HLT; only the BSP owns the PIT.
             */
            .section .ap_trampoline_source,"ax"
            .code16
            ap_trampoline_start:
              jmp ap_start

            /*
             * Keep the multiboot header at the beginning of the compact high
             * load segment so its file offset remains below the 8 KiB scan
             * boundary without creating a sparse low-address PT_LOAD.
             */
            .section .multiboot,"a"
            .align 4
            .long 0x1badb002
            .long 0x00000003
            .long -(0x1badb002 + 0x00000003)

            .section .ap_trampoline_source,"ax"
            .code16
            ap_start:
              cli
              /* Publish online only after the byte reached the UART. */
              movb $'A', %bl
            ap_online_serial_wait:
              movw $0x3fd, %dx
              inb %dx, %al
              testb $0x20, %al
              jz ap_online_serial_wait
              movb %bl, %al
              movw $0x3f8, %dx
              outb %al, %dx
              lock incw 0x7000

            ap_acquire_handoff_lock:
              xorw %ax, %ax
              movw $1, %cx
              lock cmpxchgw %cx, 0x7002
              je ap_acquired_handoff_lock
              pause
              jmp ap_acquire_handoff_lock
            ap_acquired_handoff_lock:
              movb $'P', %bl
            ap_handoff_serial_wait:
              movw $0x3fd, %dx
              inb %dx, %al
              testb $0x20, %al
              jz ap_handoff_serial_wait
              movb %bl, %al
              movw $0x3f8, %dx
              outb %al, %dx
              lock incw 0x7004
            ap_wait_for_lock_release_authorization:
              cmpw $1, 0x7006
              je ap_release_handoff_lock
              pause
              jmp ap_wait_for_lock_release_authorization
            ap_release_handoff_lock:
              movw $0, 0x7002
              lock incw 0x7008
            ${apRunLoop}
            ap_trampoline_end:
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
              .ap_trampoline_source : {
                *(.ap_trampoline_source)
              } :text
              . = ALIGN(0x1000);
              .data : { *(.data*) } :data
              .bss : { *(.bss*) *(COMMON) } :data
            }
            GUEST_LD

            mkdir -p "$out"
            as --32 guest.S -o guest.o
            ld -m elf_i386 -nostdlib -T guest.ld -o "$out/smp-idle-guest.elf" guest.o
            strip --strip-all "$out/smp-idle-guest.elf"
            test -s "$out/smp-idle-guest.elf"

            # QEMU's multiboot fw_cfg loader copies the full span between the
            # lowest and highest PT_LOAD addresses. Keep that span compact and
            # above 1 MiB so it cannot overwrite the executing option ROM.
            readelf -lW "$out/smp-idle-guest.elf" > program-headers
            test "$(grep -c '^[[:space:]]*LOAD[[:space:]]' program-headers)" -eq 2
            grep -Eq 'LOAD[[:space:]]+0x[[:xdigit:]]+[[:space:]]+0x00100000[[:space:]]+0x00100000' program-headers
            grep -Eq 'LOAD[[:space:]]+0x[[:xdigit:]]+[[:space:]]+0x00101000[[:space:]]+0x00101000' program-headers

            cat > "$out/evidence.env" <<'EVIDENCE'
            guest_format=multiboot-elf32
            guest_vcpus=${toString guestVcpus}
            guest_ap_startup=${apStartup}
            ${
              if guestIdle
              then "guest_idle=all-vcpus-hlt"
              else "guest_idle=false"
            }
            guest_activity=${guestActivity}
            guest_deadline=${guestDeadline}
            guest_ap_trampoline=high-load-copy-to-sipi-vector
            guest_load_segments=compact-high-only
            guest_smp_rendezvous=release-pause-immediate-reacquire-fails-before-ap-lock-chain
            EVIDENCE
          '';
        }
      ];
    }
