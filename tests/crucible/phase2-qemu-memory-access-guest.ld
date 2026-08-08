/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)

SECTIONS
{
  . = 0x00100000;
  .multiboot : { *(.multiboot) }
  .text : { *(.text) }
  . = 0x00102000;
  .fault_data : { *(.fault_data) }
  . = 0x00103000;
  .bss : { *(.bss) }
  . = 0x00108000;
  .page_tables : { *(.page_tables) }
}
