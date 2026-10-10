// SPDX-License-Identifier: Apache-2.0
/* Real x86 stores with capture boundaries and an independent byte oracle. */
#define _GNU_SOURCE

#include <cpuid.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error This fixture requires the x86-64 instruction set.
#endif

enum { PAGE_BYTES = 4096, ARENA_BYTES = 2 * PAGE_BYTES };

enum instruction_feature { BASELINE, CX16, AVX, AVX512 };

struct writer {
  const char *name;
  unsigned offset;
  unsigned length;
  void (*store)(unsigned char *address);
  enum instruction_feature feature;
};

static int failed_cas_observed;
static int force_cas_write;

/* Keep instruction families explicit: a memcpy substitution defeats this test. */
static void scalar8(unsigned char *address) {
  __asm__ volatile("movb $0x10, (%0)" : : "r"(address) : "memory");
}

static void scalar32(unsigned char *address) {
  __asm__ volatile("movl $0x76543210, (%0)" : : "r"(address) : "memory");
}

static void atomic8(unsigned char *address) {
  unsigned char value = 0x10;
  __asm__ volatile("xchgb %0, (%1)"
                   : "+q"(value) : "r"(address) : "memory");
}

static void atomic16(unsigned char *address) {
  uint16_t value = 0x3210;
  __asm__ volatile("xchgw %0, (%1)"
                   : "+r"(value) : "r"(address) : "memory");
}

static void atomic32(unsigned char *address) {
  uint32_t value = 0x76543210;
  __asm__ volatile("xchgl %0, (%1)"
                   : "+r"(value) : "r"(address) : "memory");
}

static void scalar64(unsigned char *address) {
  uint64_t value = UINT64_C(0xfedcba9876543210);
  __asm__ volatile("movq %1, (%0)" : : "r"(address), "r"(value) : "memory");
}

static void vector128(unsigned char *address) {
  const uint64_t value[2] = {
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
  };
  __asm__ volatile("movdqu %1, %%xmm0\n\tmovdqu %%xmm0, (%0)"
                   : : "r"(address), "m"(value) : "xmm0", "memory");
}

static void vector256(unsigned char *address) {
  const uint64_t value[4] = {
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
  };
  __asm__ volatile("vmovdqu %1, %%ymm0\n\tvmovdqu %%ymm0, (%0)\n\tvzeroupper"
                   : : "r"(address), "m"(value) : "ymm0", "memory");
}

static void vector512(unsigned char *address) {
  const uint64_t value[8] = {
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
    UINT64_C(0xfedcba9876543210), UINT64_C(0x0123456789abcdef),
  };
  __asm__ volatile("vmovdqu64 %1, %%zmm0\n\tvmovdqu64 %%zmm0, (%0)\n\tvzeroupper"
                   : : "r"(address), "m"(value) : "zmm0", "memory");
}

static void failed_cas64(unsigned char *address) {
  uint64_t expected = force_cas_write ? UINT64_C(0x3535353535353535) : 0;
  uint64_t replacement = UINT64_C(0xfedcba9876543210);
  unsigned char exchanged;
  __asm__ volatile("lock cmpxchgq %3, (%2)\n\tsetz %1"
                   : "+a"(expected), "=qm"(exchanged)
                   : "r"(address), "r"(replacement) : "cc", "memory");
  /* A failed CAS must execute and report the original value. Unchanged bytes
   * alone would also accept an omitted instruction. This says nothing about
   * the CPU's write cycle or native dirty notification for a failed CAS. */
  failed_cas_observed = !exchanged && expected == UINT64_C(0x3535353535353535);
}

static void atomic64(unsigned char *address) {
  uint64_t value = UINT64_C(0x123456789abcdef0);
  __asm__ volatile("lock xaddq %0, (%1)"
                   : "+r"(value) : "r"(address) : "cc", "memory");
}

static void atomic128(unsigned char *address) {
  uint64_t low = UINT64_C(0x3535353535353535);
  uint64_t high = low;
  uint64_t replacement_low = UINT64_C(0xfedcba9876543210);
  uint64_t replacement_high = UINT64_C(0x0123456789abcdef);
  __asm__ volatile("lock cmpxchg16b (%2)"
                   : "+a"(low), "+d"(high)
                   : "r"(address), "b"(replacement_low), "c"(replacement_high)
                   : "cc", "memory");
}

static void streaming64(unsigned char *address) {
  uint64_t value = UINT64_C(0xfedcba9876543210);
  __asm__ volatile("movnti %1, (%0)\n\tsfence"
                   : : "r"(address), "r"(value) : "memory");
}

static void repeated_bytes(unsigned char *address) {
  size_t count = 32;
  __asm__ volatile("cld\n\trep stosb"
                   : "+D"(address), "+c"(count) : "a"(0xa7) : "cc", "memory");
}

static const struct writer writers[] = {
  {"byte-store", 48, 1, scalar8, 0},
  {"scalar32", 64, 4, scalar32, 0},
  {"unaligned64", 67, 8, scalar64, 0},
  {"cross-page64", PAGE_BYTES - 3, 8, scalar64, 0},
  {"vector128", 128, 16, vector128, 0},
  {"unaligned-vector128", 131, 16, vector128, 0},
  {"cross-page-vector128", PAGE_BYTES - 7, 16, vector128, 0},
  {"atomic8", 176, 1, atomic8, 0},
  {"atomic16", 178, 2, atomic16, 0},
  {"atomic32", 180, 4, atomic32, 0},
  {"atomic64", 192, 8, atomic64, 0},
  {"atomic128", 208, 16, atomic128, 1},
  {"streaming64", 240, 8, streaming64, 0},
  {"cross-page-rep-stos", PAGE_BYTES - 13, 32, repeated_bytes, 0},
  {"failed-cas64", 256, 8, failed_cas64, BASELINE},
  {"vector256", 288, 32, vector256, AVX},
  {"unaligned-vector256", 291, 32, vector256, AVX},
  {"cross-page-vector256", PAGE_BYTES - 15, 32, vector256, AVX},
  {"vector512", 384, 64, vector512, AVX512},
  {"unaligned-vector512", 389, 64, vector512, AVX512},
  {"cross-page-vector512", PAGE_BYTES - 31, 64, vector512, AVX512},
};

static int supports_feature(enum instruction_feature feature) {
  unsigned eax, ebx, ecx, edx;
  if (feature == BASELINE) {
    return 1;
  }
  if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return 0;
  }
  if (feature == CX16) {
    return (ecx & bit_CMPXCHG16B) != 0;
  }
  if ((ecx & (bit_AVX | bit_OSXSAVE)) != (bit_AVX | bit_OSXSAVE)) {
    return 0;
  }

  /* CPUID alone cannot authorize AVX: the OS must preserve its register state.
   * XGETBV itself is legal only after the OSXSAVE check above. */
  __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
  if ((eax & 6) != 6) {
    return 0;
  }
  if (feature == AVX) {
    return 1;
  }
  if ((eax & 0xe6) != 0xe6 || !__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
    return 0;
  }
  return (ebx & bit_AVX512F) != 0;
}

/* This reference uses byte arithmetic, never the instruction under test. */
static void expected_store(const struct writer *writer, unsigned char *bytes) {
  if (writer->store == failed_cas64) {
    return;
  }
  uint64_t low = UINT64_C(0xfedcba9876543210);
  uint64_t high = UINT64_C(0x0123456789abcdef);
  if (writer->store == atomic64) {
    low = UINT64_C(0x3535353535353535) + UINT64_C(0x123456789abcdef0);
  }
  for (unsigned index = 0; index < writer->length; ++index) {
    bytes[writer->offset + index] = writer->store == repeated_bytes
      ? 0xa7 : (unsigned char)(((index / 8) % 2 == 0 ? low : high) >> (8 * (index % 8)));
  }
}

static int wait_for(unsigned char command) {
  unsigned char actual;
  ssize_t count = read(STDIN_FILENO, &actual, 1);
  return count == 1 && actual == command ? 0 : -1;
}

static const struct writer *find_writer(const char *name) {
  for (unsigned index = 0; index < sizeof(writers) / sizeof(writers[0]); ++index) {
    if (strcmp(writers[index].name, name) == 0) {
      return &writers[index];
    }
  }
  return NULL;
}

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s CASE [--omit-store|--corrupt-byte|--force-cas-write]\n", argv[0]);
    return 2;
  }
  const struct writer *writer = find_writer(argv[1]);
  if (!writer || (argc == 3 && strcmp(argv[2], "--omit-store") != 0
                            && strcmp(argv[2], "--corrupt-byte") != 0
                            && strcmp(argv[2], "--force-cas-write") != 0)) {
    return 2;
  }
  if (argc == 3 && strcmp(argv[2], "--force-cas-write") == 0) {
    if (writer->store != failed_cas64) {
      return 2;
    }
    force_cas_write = 1;
  }
  if (sysconf(_SC_PAGESIZE) != PAGE_BYTES) {
    fputs("UNSUPPORTED: host page size is not 4096\n", stderr);
    return 77;
  }
  if (!supports_feature(writer->feature)) {
    fprintf(stderr, "UNSUPPORTED: instruction feature %d\n", writer->feature);
    return 77;
  }

  unsigned char *arena = mmap(NULL, ARENA_BYTES, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (arena == MAP_FAILED) {
    return 3;
  }
  unsigned char expected[ARENA_BYTES];
  memset(arena, 0x35, ARENA_BYTES);
  memset(expected, 0x35, ARENA_BYTES);
  expected_store(writer, expected);

  /* Both pages are materialized before the caller takes its baseline capture. */
  printf("WRITER_READY_V1 %s %u %u\n", writer->name, writer->offset, writer->length);
  fflush(stdout);
  int status = 0;
  if (wait_for('W') != 0) {
    status = 5;
    goto close_arena;
  }
  if (argc != 3 || strcmp(argv[2], "--omit-store") != 0) {
    writer->store(arena + writer->offset);
  }
  if (argc == 3 && strcmp(argv[2], "--corrupt-byte") == 0) {
    arena[writer->offset] ^= 1;
  }
  if (memcmp(arena, expected, ARENA_BYTES) != 0 ||
      (writer->store == failed_cas64 && !failed_cas_observed)) {
    fputs("WRITER_MISMATCH_V1\n", stderr);
    status = 4;
    goto close_arena;
  }
  printf("WRITER_STORED_V1 %s\n", writer->name);
  fflush(stdout);

  /* A second boundary lets an external capture acknowledge and rearm first. */
  if (wait_for('Z') != 0) {
    status = 5;
    goto close_arena;
  }
  memset(arena + writer->offset, 0, writer->length);
  memset(expected + writer->offset, 0, writer->length);
  if (memcmp(arena, expected, ARENA_BYTES) != 0) {
    status = 4;
    goto close_arena;
  }
  printf("WRITER_ZEROED_V1 %s\n", writer->name);
  fflush(stdout);
  if (wait_for('Q') != 0) {
    status = 5;
  }

close_arena:
  if (munmap(arena, ARENA_BYTES) != 0 && status == 0) {
    status = 6;
  }
  return status;
}
