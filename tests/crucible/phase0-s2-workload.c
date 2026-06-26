#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

enum {
  S2_OPERATIONS = 32,
  S2_BLOCK_WARMUP = 8,
  S2_9P_WARMUP = 8,
  S2_READ_SIZE = 4096,
  S2_BLOCK_STRIDE = 131072
};

static inline void
marker_block_begin(void)
{
  __asm__ __volatile__(
      ".byte 0x0f, 0x1f, 0x84, 0x00\n\t"
      ".long 0xc0100201\n\t"
      :
      :
      : "memory");
}

static inline void
marker_block_end(void)
{
  __asm__ __volatile__(
      ".byte 0x0f, 0x1f, 0x84, 0x00\n\t"
      ".long 0xc0100202\n\t"
      :
      :
      : "memory");
}

static inline void
marker_9p_begin(void)
{
  __asm__ __volatile__(
      ".byte 0x0f, 0x1f, 0x84, 0x00\n\t"
      ".long 0xc0100901\n\t"
      :
      :
      : "memory");
}

static inline void
marker_9p_end(void)
{
  __asm__ __volatile__(
      ".byte 0x0f, 0x1f, 0x84, 0x00\n\t"
      ".long 0xc0100902\n\t"
      :
      :
      : "memory");
}

static int
read_exact_at(int fd, void *buffer, size_t len, off_t offset)
{
  unsigned char *cursor = buffer;
  size_t remaining = len;

  while (remaining > 0) {
    ssize_t n = pread(fd, cursor, remaining, offset);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      errno = EIO;
      return -1;
    }

    cursor += (size_t)n;
    remaining -= (size_t)n;
    offset += n;
  }

  return 0;
}

static int
read_exact(int fd, void *buffer, size_t len)
{
  unsigned char *cursor = buffer;
  size_t remaining = len;

  while (remaining > 0) {
    ssize_t n = read(fd, cursor, remaining);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (n == 0) {
      errno = EIO;
      return -1;
    }

    cursor += (size_t)n;
    remaining -= (size_t)n;
  }

  return 0;
}

static uint64_t
fold_bytes(uint64_t checksum, const unsigned char *buffer, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    checksum ^= buffer[i];
    checksum *= 1099511628211ULL;
  }
  return checksum;
}

static int
path_for_file(char *path, size_t path_len, const char *root, const char *prefix, int index)
{
  int n = snprintf(path, path_len, "%s/%s-%02d.bin", root, prefix, index);
  if (n < 0 || (size_t)n >= path_len) {
    fputs("9p path too long\n", stderr);
    return 1;
  }

  return 0;
}

static int
open_9p_file(const char *path)
{
  int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (fd < 0) {
    perror("open 9p");
  }
  return fd;
}

static int
make_fd_blocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
    perror("fcntl 9p blocking");
    return 1;
  }

  return 0;
}

static int
run_block_reads(const char *device)
{
  void *buffer = NULL;
  uint64_t checksum = 1469598103934665603ULL;
  int fd = -1;

  if (posix_memalign(&buffer, S2_READ_SIZE, S2_READ_SIZE) != 0) {
    perror("posix_memalign");
    return 1;
  }

  fd = open(device, O_RDONLY | O_DIRECT | O_SYNC | O_CLOEXEC);
  if (fd < 0) {
    perror("open block direct");
    free(buffer);
    return 1;
  }

  for (int i = 0; i < S2_BLOCK_WARMUP; i++) {
    const off_t offset = (off_t)i * S2_BLOCK_STRIDE;
    memset(buffer, 0x3c, S2_READ_SIZE);
    if (read_exact_at(fd, buffer, S2_READ_SIZE, offset) != 0) {
      perror("pread block warmup");
      close(fd);
      free(buffer);
      return 1;
    }
  }

  puts("CRUCIBLE_S2_BLOCK_DIRECT=1");
  for (int i = 0; i < S2_OPERATIONS; i++) {
    const off_t offset = (off_t)i * S2_BLOCK_STRIDE;
    memset(buffer, 0xa5, S2_READ_SIZE);

    marker_block_begin();
    const int rc = read_exact_at(fd, buffer, S2_READ_SIZE, offset);
    marker_block_end();

    if (rc != 0) {
      perror("pread block");
      close(fd);
      free(buffer);
      return 1;
    }
    checksum = fold_bytes(checksum, buffer, S2_READ_SIZE);
  }

  printf(
      "CRUCIBLE_S2_BLOCK_DONE ops=%d bytes=%d checksum=%016" PRIx64 "\n",
      S2_OPERATIONS,
      S2_OPERATIONS * S2_READ_SIZE,
      checksum);
  close(fd);
  free(buffer);
  return 0;
}

static int
run_9p_reads(const char *root)
{
  unsigned char buffer[S2_READ_SIZE];
  uint64_t checksum = 1469598103934665603ULL;
  char path[256];

  for (int i = 0; i < S2_9P_WARMUP; i++) {
    if (path_for_file(path, sizeof(path), root, "warmup", i) != 0) {
      return 1;
    }

    int fd = open_9p_file(path);
    if (fd < 0) {
      return 1;
    }

    memset(buffer, 0x4b, sizeof(buffer));
    if (make_fd_blocking(fd) != 0) {
      close(fd);
      return 1;
    }
    if (read_exact(fd, buffer, sizeof(buffer)) != 0) {
      perror("read 9p warmup");
      close(fd);
      return 1;
    }
    close(fd);
  }

  for (int i = 0; i < S2_OPERATIONS; i++) {
    if (path_for_file(path, sizeof(path), root, "file", i) != 0) {
      return 1;
    }

    int fd = open_9p_file(path);
    if (fd < 0) {
      return 1;
    }

    memset(buffer, 0x5a, sizeof(buffer));
    marker_9p_begin();
    if (make_fd_blocking(fd) != 0) {
      marker_9p_end();
      close(fd);
      return 1;
    }
    const int rc = read_exact(fd, buffer, sizeof(buffer));
    marker_9p_end();

    if (rc != 0) {
      perror("read 9p");
      close(fd);
      return 1;
    }

    checksum = fold_bytes(checksum, buffer, sizeof(buffer));
    close(fd);
  }

  printf(
      "CRUCIBLE_S2_9P_DONE ops=%d bytes=%d checksum=%016" PRIx64 "\n",
      S2_OPERATIONS,
      S2_OPERATIONS * S2_READ_SIZE,
      checksum);
  return 0;
}

int
main(int argc, char **argv)
{
  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: %s BLOCK_DEVICE [NINEP_ROOT]\n", argv[0]);
    return 1;
  }

  if (run_block_reads(argv[1]) != 0) {
    return 1;
  }
  if (argc == 2) {
    puts("CRUCIBLE_S2_BLOCK_ONLY_DONE");
    return 0;
  }
  if (run_9p_reads(argv[2]) != 0) {
    return 1;
  }

  puts("CRUCIBLE_S2_DONE");
  return 0;
}
