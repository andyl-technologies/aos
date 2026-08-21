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
            .section .ap_vector,"ax"
            .code16
              jmp ap_start

            /*
             * Keep the multiboot header in the first, low-address load segment so
             * its file offset remains strictly below the 8 KiB scan boundary.
             */
            .section .multiboot,"a"
            .align 4
            .long 0x1badb002
            .long 0x00000003
            .long -(0x1badb002 + 0x00000003)

            .section .ap_trampoline,"ax"
            .code16
            ap_start:
              cli
            ${apRunLoop}
            GUEST_ASM

            cat > guest.ld <<'GUEST_LD'
            ENTRY(_start)
            PHDRS {
              text PT_LOAD FLAGS(5);
              data PT_LOAD FLAGS(6);
              trampoline PT_LOAD FLAGS(5);
            }
            SECTIONS {
              .ap_trampoline 0x00008000 : {
                *(.ap_vector)
                KEEP(*(.multiboot))
                *(.ap_trampoline)
              } :trampoline
              . = 0x00100000;
              .text : { *(.text*) } :text
              .rodata : { *(.rodata*) } :text
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
            EVIDENCE
          '';
        }
      ];
    }
