{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-loaded-qemu-coverage-guest";
  version = "0";
  src = null;

  buildDeps = [pkgs.coreutils];

  phases = [
    {
      name = "build-uninstrumented-multiboot-guest";
      script = ''
        set -eu
        cat > guest.S <<'GUEST_ASM'
        .section .multiboot,"a"
        .align 4
        .long 0x1badb002
        .long 0x00000003
        .long -(0x1badb002 + 0x00000003)

        .section .text
        .code32
        .global _start
        _start:
          cli
          movl $stack_top, %esp
          xorl %eax, %eax
        workload_loop:
          addl $0x9e3779b9, %eax
          roll $7, %eax
          xorl $0xa5a5a5a5, %eax
          movl %eax, scratch
          movl scratch, %edx
          xorl %edx, %eax
          jmp workload_loop

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
        ld -m elf_i386 -nostdlib -T guest.ld -o "$out/coverage-guest.elf" guest.o
        test -s "$out/coverage-guest.elf"

        cat > "$out/evidence.env" <<'EVIDENCE'
        guest_format=multiboot-elf32
        guest_interface=none
        guest_instrumentation=none
        guest_symbols=removed-by-fixup
        EVIDENCE
      '';
    }
  ];
}
