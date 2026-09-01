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
  . = 0x00108000;
  .scenario_data : { *(.scenario_data) }
  . = 0x00109000;
  .fault_text : { *(.fault_text) }
  . = 0x0010a000;
  .page_tables : { *(.page_tables) }
  . = 0x0010e000;
  .gdt : { *(.gdt) }
  /* The IDT is 4 KiB plus its 10-byte descriptor. Keep both below the
     fixed nested-virtualization region at 0x00110000. */
  . = 0x0010e100;
  .idt : { *(.idt) }
  ASSERT(. <= 0x00110000, "IDT overlaps nested-virtualization state")
  . = 0x00110000;
  .nested_vm : { *(.nested_vm) }
}
