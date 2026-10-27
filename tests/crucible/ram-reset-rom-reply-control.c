// SPDX-License-Identifier: Apache-2.0
/* Execute the actual ROM's cdecl decoder without a guest or privileged I/O. */
typedef unsigned char byte;

extern unsigned validate_reply(const byte reply[128], unsigned sequence);

static void put_word(byte *bytes, unsigned value) {
  for (unsigned index = 0; index < 4; ++index) {
    bytes[index] = value >> (8 * index);
  }
}

static void prepare_reply(byte reply[128], unsigned sequence) {
  for (unsigned index = 0; index < 128; ++index) {
    reply[index] = 0;
  }
  put_word(reply, 0x00030001);
  put_word(reply + 4, 96);
  put_word(reply + 8, 97);
  put_word(reply + 12, sequence);
  put_word(reply + 88, 96);
  put_word(reply + 92, 1);
  reply[96] = 1;
}

static unsigned controls(void) {
  byte reply[128];
  prepare_reply(reply, 2);
  if (validate_reply(reply, 2) != 1 || validate_reply(reply, 3) != 0) {
    return 1;
  }
  prepare_reply(reply, 3);
  if (validate_reply(reply, 3) != 1 || validate_reply(reply, 2) != 0) {
    return 2;
  }

  /* One changed field at a time: wire version/kind/header/reserved/length,
   * sequence, selected status, value range/Unit, and trailing reply padding. */
  const unsigned rejected[] = {0, 2, 4, 6, 8, 12, 16, 20, 22, 88, 92, 96, 127};
  for (unsigned index = 0; index < sizeof(rejected) / sizeof(rejected[0]); ++index) {
    prepare_reply(reply, 2);
    reply[rejected[index]] ^= 1;
    if (validate_reply(reply, 2) != 0) {
      return 3 + index;
    }
  }

  /* An unchanged request cannot authorize the following writer stores. */
  for (unsigned index = 0; index < 128; ++index) {
    reply[index] = 0;
  }
  put_word(reply, 0x00020001);
  put_word(reply + 4, 48);
  put_word(reply + 8, 128);
  put_word(reply + 12, 2);
  return validate_reply(reply, 2) == 0 ? 0 : 16;
}

void _start(void) {
  unsigned status = controls();
  /* This freestanding ELF32 uses the real Linux exit ABI; no libc or emulator
   * substitutes the ROM decoder. The boot/port-I/O functions are never called. */
  __asm__ volatile("int $0x80" : : "a"(1), "b"(status) : "memory");
  __builtin_unreachable();
}
