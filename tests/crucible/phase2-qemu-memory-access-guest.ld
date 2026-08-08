/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)

SECTIONS
{
  . = 0x00100000;
  .multiboot : { *(.multiboot) }
  .text : { *(.text) }
  . = 0x00102000;
  .fault_data : { *(.fault_data) }
  . = 0x00104000;
  .bss : { *(.bss) }
  . = 0x00109000;
  .fault_text : { *(.fault_text) }
  . = 0x0010a000;
  .page_tables : { *(.page_tables) }
  . = 0x0010d000;
  .gdt : { *(.gdt) }
}
