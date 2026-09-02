{pkgs}:
# A finite, uninstrumented multiboot workload for the production CLI fuzz gate.
# The guest executes distinct basic blocks and then halts with interrupts
# disabled. The campaign's explicit quantum bound owns iteration completion, so
# this fixture need not borrow a timer-active Linux userspace workload.
pkgs.mkDerivation {
  pname = "crucible-cli-fuzz-guest";
  version = "0";
  src = null;

  buildDeps = [pkgs.coreutils];

  phases = [
    {
      name = "build-cli-fuzz-guest";
      script = ''
        set -eu
        cat > guest.S <<'GUEST_ASM'
        .section .multiboot,"a"
        .align 4
        .long 0x1badb002
        .long 0x00000003
        .long -(0x1badb002 + 0x00000003)

        .section .text.entry,"ax"
        .code32
        .global _start
        _start:
          cli
          movl $stack_top, %esp
          movl $0x9e3779b9, %eax
          movl $256, %ecx
        workload_loop:
          testl $1, %ecx
          jnz odd_iteration
        even_iteration:
          roll $7, %eax
          xorl $0xa5a5a5a5, %eax
          jmp joined_iteration
        odd_iteration:
          rorl $3, %eax
          addl $0x7f4a7c15, %eax
        joined_iteration:
          testl $7, %ecx
          jnz skip_io
          movb %al, 0x000b8000
          outb %al, $0x80
        skip_io:
          decl %ecx
          jnz workload_loop
          movl %eax, result
        halted:
          hlt
          jmp halted

        .section .bss
        .align 16
        result:
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
        ld -m elf_i386 -nostdlib -T guest.ld -o "$out/fuzz-guest.elf" guest.o
        strip --strip-all "$out/fuzz-guest.elf"
        test -s "$out/fuzz-guest.elf"
      '';
    }
  ];
}
