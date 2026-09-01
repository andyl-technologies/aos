/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)

SECTIONS
{
  . = 0x40200000;
  .text : { *(.text) }
  . = 0x40201000;
  .mutation_code : { *(.mutation_code) }
  . = 0x40300000;
  .data : { *(.data) }
  . = 0x40300fff;
  .cross : { *(.cross) }
  . = 0x40302000;
  .readonly_data : { *(.readonly_data) }
  . = 0x40400000;
  .page_tables : { *(.page_tables) }
}
