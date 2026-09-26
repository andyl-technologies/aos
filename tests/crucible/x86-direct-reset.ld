/* SPDX-License-Identifier: Apache-2.0 */

OUTPUT_FORMAT("elf32-i386")
ENTRY(boot)

SECTIONS
{
  . = 0;
  .text : { *(.text.boot) }
  . = 0x0000fff0;
  .reset : { *(.reset) }
  /DISCARD/ : { *(.note*) *(.comment*) }
}
