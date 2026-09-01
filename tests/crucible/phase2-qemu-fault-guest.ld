/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)

SECTIONS
{
  . = 0x00100000;
  .multiboot : { *(.multiboot) }
  .text : { *(.text) }
  . = 0x00102000;
  .data : { *(.data) }
  . = 0x00102fff;
  .cross : { *(.cross) }
  . = 0x00104000;
  .mutation_code : { *(.mutation_code) }
  . = 0x00105000;
  .readonly_data : { *(.readonly_data) }
  . = 0x00106000;
  .bss : { *(.bss) }
  . = 0x0010b000;
  .page_tables : { *(.page_tables) }
}
