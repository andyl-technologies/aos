#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <unistd.h>

static uint64_t
fnv1a_u64(uint64_t hash, uint64_t value)
{
  for (unsigned int i = 0; i < 8; i++) {
    hash ^= (value >> (i * 8)) & 0xffU;
    hash *= 1099511628211ULL;
  }
  return hash;
}

static int
mount_proc_if_needed(void)
{
  if (mount("proc", "/proc", "proc", 0, "") == 0 || errno == EBUSY) {
    return 0;
  }

  perror("mount proc");
  return 1;
}

static int
read_randomize_va_space(void)
{
  FILE *file = fopen("/proc/sys/kernel/randomize_va_space", "r");
  if (file == NULL) {
    return -1;
  }

  int value = -1;
  if (fscanf(file, "%d", &value) != 1) {
    value = -1;
  }
  fclose(file);
  return value;
}

static const char *
read_mode_from_cmdline(char *buffer, size_t len)
{
  FILE *file = fopen("/proc/cmdline", "r");
  if (file == NULL) {
    return "unknown";
  }

  if (fgets(buffer, len, file) == NULL) {
    fclose(file);
    return "unknown";
  }
  fclose(file);

  for (char *tok = strtok(buffer, " \n"); tok != NULL; tok = strtok(NULL, " \n")) {
    const char prefix[] = "crucible_s6_mode=";
    const size_t prefix_len = sizeof(prefix) - 1U;
    if (strncmp(tok, prefix, prefix_len) == 0) {
      return tok + prefix_len;
    }
  }

  return "unknown";
}

static uint64_t
read_kernel_symbol(const char *const *names, size_t name_count)
{
  FILE *file = fopen("/proc/kallsyms", "r");
  if (file == NULL) {
    return 0;
  }

  char line[512];
  while (fgets(line, sizeof(line), file) != NULL) {
    unsigned long long addr = 0;
    char type = 0;
    char symbol[256];

    if (sscanf(line, "%llx %c %255s", &addr, &type, symbol) != 3) {
      continue;
    }
    (void)type;

    for (size_t i = 0; i < name_count; i++) {
      if (strcmp(symbol, names[i]) == 0) {
        fclose(file);
        return (uint64_t)addr;
      }
    }
  }

  fclose(file);
  return 0;
}

static uint64_t
read_vdso_base(void)
{
  FILE *file = fopen("/proc/self/maps", "r");
  if (file == NULL) {
    return 0;
  }

  char line[512];
  while (fgets(line, sizeof(line), file) != NULL) {
    if (strstr(line, "[vdso]") == NULL) {
      continue;
    }

    unsigned long long start = 0;
    unsigned long long end = 0;
    if (sscanf(line, "%llx-%llx", &start, &end) == 2 && start < end) {
      fclose(file);
      return (uint64_t)start;
    }
  }

  fclose(file);
  return 0;
}

static void
touch_bytes(unsigned char *bytes, size_t len, uint64_t salt)
{
  for (size_t i = 0; i < len; i++) {
    bytes[i] = (unsigned char)((salt + i * 17U + (i >> 3U)) & 0xffU);
  }
}

int
main(int argc, char **argv)
{
  if (mount_proc_if_needed() != 0) {
    puts("CRUCIBLE_S6_PROC_MOUNT_FAIL");
    return 1;
  }

  char mode_buffer[4096];
  const char *mode =
      argc > 1 ? argv[1] : read_mode_from_cmdline(mode_buffer, sizeof(mode_buffer));

  volatile uintptr_t stack_anchor = 0x0010c006ULL;
  void *heap = malloc(4096);
  void *mapping =
      mmap(NULL, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (heap == NULL || mapping == MAP_FAILED) {
    perror(heap == NULL ? "malloc" : "mmap");
    return 1;
  }

  touch_bytes(heap, 4096, 0x6e8b1d5ULL);
  touch_bytes(mapping, 16384, 0xa511d00dULL);

  const char *const kernel_text_names[] = {
      "_text",
      "_stext",
      "startup_64",
      "__startup_64",
  };
  const char *const kernel_stext_names[] = {
      "_stext",
      "_text",
      "startup_64",
      "__startup_64",
  };

  const int randomize_va_space = read_randomize_va_space();
  const uint64_t kernel_text =
      read_kernel_symbol(kernel_text_names, sizeof(kernel_text_names) / sizeof(kernel_text_names[0]));
  const uint64_t kernel_stext =
      read_kernel_symbol(kernel_stext_names, sizeof(kernel_stext_names) / sizeof(kernel_stext_names[0]));
  const uint64_t stack = (uint64_t)(uintptr_t)&stack_anchor;
  const uint64_t heap_addr = (uint64_t)(uintptr_t)heap;
  const uint64_t brk_addr = (uint64_t)(uintptr_t)sbrk(0);
  const uint64_t mmap_addr = (uint64_t)(uintptr_t)mapping;
  const uint64_t vdso_addr = read_vdso_base();

  uint64_t checksum = 1469598103934665603ULL;
  checksum = fnv1a_u64(checksum, (uint64_t)(uint32_t)randomize_va_space);
  checksum = fnv1a_u64(checksum, kernel_text);
  checksum = fnv1a_u64(checksum, kernel_stext);
  checksum = fnv1a_u64(checksum, stack);
  checksum = fnv1a_u64(checksum, heap_addr);
  checksum = fnv1a_u64(checksum, brk_addr);
  checksum = fnv1a_u64(checksum, mmap_addr);
  checksum = fnv1a_u64(checksum, vdso_addr);
  checksum = fnv1a_u64(checksum, stack_anchor);

  printf(
      "CRUCIBLE_S6_BASES mode=%s randomize_va_space=%d "
      "kernel_text=%016llx kernel_stext=%016llx stack=%016llx "
      "heap=%016llx brk=%016llx mmap=%016llx vdso=%016llx checksum=%016llx\n",
      mode,
      randomize_va_space,
      (unsigned long long)kernel_text,
      (unsigned long long)kernel_stext,
      (unsigned long long)stack,
      (unsigned long long)heap_addr,
      (unsigned long long)brk_addr,
      (unsigned long long)mmap_addr,
      (unsigned long long)vdso_addr,
      (unsigned long long)checksum);
  puts("CRUCIBLE_S6_DONE");

  if (munmap(mapping, 16384) != 0) {
    perror("munmap");
    free(heap);
    return 1;
  }
  free(heap);
  return 0;
}
