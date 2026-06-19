#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum {
  KIND_RESIDENT = 1,
  KIND_PAGE_SPAN = 2,
  KIND_PAGED_MMAP = 3,
  RESIDENT_LEN = 64,
  PAGE_SPAN_LEN = 96,
  PAGED_MMAP_LEN = 128,
};

static unsigned char resident_payload[RESIDENT_LEN] __attribute__((aligned(64)));

static unsigned char
expected_byte(uint64_t kind, uint64_t offset)
{
  return (unsigned char)((kind * 37U + offset * 17U + (offset >> 3U)) & 0xffU);
}

static void
fill_payload(unsigned char *payload, uint64_t kind, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    payload[i] = expected_byte(kind, i);
  }
}

static void
poison_payload(unsigned char *payload, uint64_t kind, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    payload[i] = (unsigned char)(expected_byte(kind, i) ^ 0xa5U);
  }
}

static uint64_t
payload_hash(const unsigned char *payload, size_t len)
{
  uint64_t hash = 1469598103934665603ULL;

  for (size_t i = 0; i < len; i++) {
    hash ^= payload[i];
    hash *= 1099511628211ULL;
  }
  return hash;
}

static void
ring_s5_doorbell(uint64_t kind, const void *payload, uint64_t len)
{
  __asm__ volatile(
      "movq %0, %%rdi\n\t"
      "movq %1, %%rsi\n\t"
      "movq %2, %%rdx\n\t"
      ".byte 0x0f, 0x1f, 0x84, 0x00\n\t"
      ".long 0xc0100505\n\t"
      :
      : "r"(kind), "r"((uintptr_t)payload), "r"(len)
      : "rdi", "rsi", "rdx", "memory");
}

static void *
checked_mmap(size_t len)
{
  void *mapping =
      mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) {
    perror("mmap");
    exit(1);
  }
  return mapping;
}

int
main(void)
{
  const long page_size = sysconf(_SC_PAGESIZE);
  if (page_size < 4096) {
    puts("CRUCIBLE_S5_BAD_PAGE_SIZE");
    return 1;
  }

  fill_payload(resident_payload, KIND_RESIDENT, sizeof(resident_payload));
  ring_s5_doorbell(KIND_RESIDENT, resident_payload, sizeof(resident_payload));
  poison_payload(resident_payload, KIND_RESIDENT, sizeof(resident_payload));

  unsigned char *span_mapping = checked_mmap((size_t)page_size * 2U);
  unsigned char *span_payload = span_mapping + (size_t)page_size - 31U;
  fill_payload(span_payload, KIND_PAGE_SPAN, PAGE_SPAN_LEN);
  ring_s5_doorbell(KIND_PAGE_SPAN, span_payload, PAGE_SPAN_LEN);
  poison_payload(span_payload, KIND_PAGE_SPAN, PAGE_SPAN_LEN);

  unsigned char *paged_mapping = checked_mmap((size_t)page_size * 4U);
  unsigned char *paged_payload = paged_mapping + (size_t)page_size + 123U;
  if (madvise(paged_mapping, (size_t)page_size * 4U, MADV_RANDOM) != 0) {
    perror("madvise");
    return 1;
  }
  fill_payload(paged_payload, KIND_PAGED_MMAP, PAGED_MMAP_LEN);
  ring_s5_doorbell(KIND_PAGED_MMAP, paged_payload, PAGED_MMAP_LEN);
  poison_payload(paged_payload, KIND_PAGED_MMAP, PAGED_MMAP_LEN);

  printf(
      "CRUCIBLE_S5_DONE resident=%016llx span=%016llx paged=%016llx\n",
      (unsigned long long)payload_hash(resident_payload, sizeof(resident_payload)),
      (unsigned long long)payload_hash(span_payload, PAGE_SPAN_LEN),
      (unsigned long long)payload_hash(paged_payload, PAGED_MMAP_LEN));
  return 0;
}
