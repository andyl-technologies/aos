{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-phase2-qemu-nvcpu-bios";
  version = "0";
  src = null;

  phases = [
    {
      name = "build-nvcpu-bios";
      script = ''
        mkdir -p "$out"

        cat > ap.S <<'AP_ASM'
        .section .text,"ax"
        .code16
        .global ap_start
        ap_start:
          cli
          xorw %ax, %ax
          movw %ax, %ds
          lgdt ap_gdtr
          movl %cr0, %eax
          orl $1, %eax
          movl %eax, %cr0
          ljmpl $0x08, $ap_protected

        .code32
        ap_protected:
          movw $0x10, %ax
          movw %ax, %ds
          movw %ax, %es
          movw %ax, %ss
          movl 0xfee00020, %eax
          shrl $24, %eax
          cmpl $2, %eax
          je ap2_busy_seed
          cmpl $3, %eax
          je ap3_busy_seed

          movl $0x51f15eed, %eax
        ap1_busy:
          roll $13, %eax
          xorl $0x9e3779b9, %eax
          addl $0x6d2b79f5, %eax
          jmp ap1_busy

        ap2_busy_seed:
          movl $0x7f4a7c15, %eax
        ap2_busy:
          roll $11, %eax
          xorl $0xbf58476d, %eax
          addl $0x1ce4e5b9, %eax
          jmp ap2_busy

        ap3_busy_seed:
          movl $0x94d049bb, %eax
        ap3_busy:
          roll $17, %eax
          xorl $0x133111eb, %eax
          addl $0x8538ec2d, %eax
          jmp ap3_busy

        .align 8
        ap_gdt:
          .quad 0
          .quad 0x00cf9a000000ffff
          .quad 0x00cf92000000ffff
        ap_gdt_end:
        ap_gdtr:
          .word ap_gdt_end - ap_gdt - 1
          .long ap_gdt
        AP_ASM

        cat > ap.ld <<'AP_LINK'
        OUTPUT_FORMAT("elf32-i386")
        ENTRY(ap_start)
        SECTIONS {
          . = 0x8000;
          .text : { *(.text) }
        }
        AP_LINK

        as --32 ap.S -o ap.o
        ld -m elf_i386 -nostdlib -T ap.ld -o ap.elf ap.o
        objcopy -O binary ap.elf ap.bin

        cat > bios.S <<'BIOS_ASM'
        .section .text,"ax"
        .code16
        .global bios_start
        bios_start:
          cli

          /* Copy the complete real-mode AP trampoline to SIPI vector 8. */
          movw $0xf000, %ax
          movw %ax, %ds
          xorw %ax, %ax
          movw %ax, %es
          movw $(ap_blob - bios_start), %si
          movw $0x8000, %di
          movw $(ap_blob_end - ap_blob), %cx
          cld
          rep movsb

          lgdt %cs:(bsp_gdtr - bios_start)
          movl %cr0, %eax
          orl $1, %eax
          movl %eax, %cr0
          ljmpl $0x08, $bsp_protected

        .code32
        bsp_protected:
          movw $0x10, %ax
          movw %ax, %ds
          movw %ax, %es
          movw %ax, %ss
          movl $0x70000, %esp

          /* Enable the BSP local APIC before issuing broadcast INIT/SIPI. */
          movl $0x1b, %ecx
          rdmsr
          orl $0x800, %eax
          wrmsr

          /* Broadcast INIT/SIPI with the architected all excluding self shorthand. */
          movl $0x000cc500, 0xfee00300
          call wait_for_icr
          movl $0x000c8500, 0xfee00300
          call wait_for_icr
          movl $0x000c0608, 0xfee00300
          call wait_for_icr
          movl $0x000c0608, 0xfee00300
          call wait_for_icr

          movl $0x0010c016, %eax
        bsp_busy:
          roll $7, %eax
          xorl $0xbf58476d, %eax
          addl $0x94d049bb, %eax
          jmp bsp_busy

        wait_for_icr:
          movl 0xfee00300, %eax
          testl $0x1000, %eax
          jnz wait_for_icr
          ret

        .align 8
        bsp_gdt:
          .quad 0
          .quad 0x00cf9a000000ffff
          .quad 0x00cf92000000ffff
        bsp_gdt_end:
        bsp_gdtr:
          .word bsp_gdt_end - bsp_gdt - 1
          .long bsp_gdt

        ap_blob:
          .incbin "ap.bin"
        ap_blob_end:

        .section .reset,"ax"
        .code16
          ljmp $0xf000, $0x0000
        BIOS_ASM

        cat > bios.ld <<'BIOS_LINK'
        OUTPUT_FORMAT("elf32-i386")
        ENTRY(bios_start)
        SECTIONS {
          . = 0x000f0000;
          .text : { *(.text) }
          . = 0x000ffff0;
          .reset : { *(.reset) }
          . = 0x000fffff;
          .end : { BYTE(0) }
          /DISCARD/ : { *(.note*) }
        }
        BIOS_LINK

        as --32 bios.S -o bios.o
        ld -m elf_i386 -nostdlib -T bios.ld -o bios.elf bios.o
        objcopy -O binary bios.elf "$out/nvcpu-bios.bin"

        bios_bytes=$(wc -c < "$out/nvcpu-bios.bin")
        if [ "$bios_bytes" -ne 65536 ]; then
          echo "N-vCPU BIOS is $bios_bytes bytes, expected 65536" >&2
          exit 1
        fi
      '';
    }
  ];
}
