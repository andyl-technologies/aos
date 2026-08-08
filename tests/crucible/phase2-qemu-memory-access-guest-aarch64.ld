/* SPDX-License-Identifier: Apache-2.0 */

ENTRY(_start)

SECTIONS
{
  . = 0x40200000;
  .text : { *(.text) }
  . = 0x40210000;
  .fault_text : { *(.fault_text) }
  . = 0x40300000;
  .fault_data : { *(.fault_data) }
  . = 0x40400000;
  .page_tables : { *(.page_tables) }
}
