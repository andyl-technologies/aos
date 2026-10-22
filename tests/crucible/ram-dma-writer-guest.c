// SPDX-License-Identifier: Apache-2.0
/* Direct vectored payload I/O; actual virtio queue/bounce attribution is external. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <unistd.h>

enum { PAGE_BYTES = 4096, VECTOR_COUNT = 2, PAYLOAD_BYTES = 8192 };

static void io_error(const char *phase, ssize_t transferred, int saved_errno) {
  fprintf(stderr, "DMA_WRITER_IO_ERROR_V1 phase=%s transferred=%zd errno=%d\n",
          phase, transferred, saved_errno);
}

static int virtio_block_driver(dev_t device) {
  char expected_device[64];
  int expected_length = snprintf(expected_device, sizeof(expected_device), "%u:%u\n",
                                 major(device), minor(device));
  if (expected_length <= 0 || (size_t)expected_length >= sizeof(expected_device)) {
    return 0;
  }
  int identity = open("/sys/block/vda/dev", O_RDONLY | O_CLOEXEC);
  if (identity < 0) {
    io_error("device-identity-open", -1, errno);
    return 0;
  }
  char actual_device[64];
  ssize_t actual_length = read(identity, actual_device, sizeof(actual_device));
  int read_errno = actual_length < 0 ? errno : 0;
  int close_status = close(identity);
  int close_errno = close_status < 0 ? errno : 0;
  if (actual_length < 0) {
    io_error("device-identity-read", actual_length, read_errno);
  }
  if (close_status < 0) {
    io_error("device-identity-close", -1, close_errno);
  }
  if (actual_length != expected_length || close_status != 0
      || memcmp(actual_device, expected_device, (size_t)expected_length) != 0) {
    return 0;
  }

  /* Resolve the driver through the opened descriptor's actual device identity. */
  char driver_path[128];
  int path_length = snprintf(driver_path, sizeof(driver_path),
                             "/sys/dev/block/%u:%u/device/driver",
                             major(device), minor(device));
  if (path_length <= 0 || (size_t)path_length >= sizeof(driver_path)) {
    return 0;
  }
  char driver[256];
  ssize_t length = readlink(driver_path, driver, sizeof(driver) - 1);
  if (length < 0) {
    io_error("device-driver-readlink", length, errno);
  }
  if (length <= 0 || (size_t)length == sizeof(driver) - 1) {
    return 0;
  }
  driver[length] = 0;
  const char *name = strrchr(driver, '/');
  return name && strcmp(name + 1, "virtio_blk") == 0;
}

static unsigned char pattern(unsigned index) {
  return (unsigned char)((index * 29u) ^ (index >> 7) ^ 0x6bu);
}

static int wait_for(unsigned char command) {
  unsigned char actual;
  return read(STDIN_FILENO, &actual, 1) == 1 && actual == command ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[1], "--virtio-block") != 0
                && strcmp(argv[1], "--local-file-control") != 0)) {
    fputs("usage: dma-writer --virtio-block /dev/vda\n"
          "       dma-writer --local-file-control PRIVATE_FILE\n", stderr);
    return 2;
  }
  int local_control = strcmp(argv[1], "--local-file-control") == 0;
  if (!local_control && strcmp(argv[2], "/dev/vda") != 0) {
    return 2;
  }
  int descriptor = open(argv[2], O_RDWR | O_DIRECT | O_CLOEXEC);
  if (descriptor < 0) {
    io_error("open", -1, errno);
    return 3;
  }
  struct stat information;
  uint64_t device_bytes = 0;
  int status = 0;
  if (fstat(descriptor, &information) != 0) {
    io_error("fstat", -1, errno);
    status = 3;
    goto close_descriptor;
  }
  if ((local_control && (!S_ISREG(information.st_mode) || information.st_size != 65536))
      || (!local_control && !S_ISBLK(information.st_mode))) {
    fputs("DMA_WRITER_UNSUPPORTED_V1 storage-kind-or-size\n", stderr);
    status = 3;
    goto close_descriptor;
  }
  if (!local_control && ioctl(descriptor, BLKGETSIZE64, &device_bytes) != 0) {
    io_error("block-size", -1, errno);
    status = 3;
    goto close_descriptor;
  }
  if (!local_control && (device_bytes < 65536 || !virtio_block_driver(information.st_rdev))) {
    fputs("DMA_WRITER_UNSUPPORTED_V1 virtio-block-driver-or-size\n", stderr);
    status = 3;
    goto close_descriptor;
  }

  unsigned char *payload = NULL;
  if (posix_memalign((void **)&payload, PAGE_BYTES, PAYLOAD_BYTES) != 0) {
    status = 4;
    goto close_descriptor;
  }
  struct iovec vectors[VECTOR_COUNT];
  for (unsigned index = 0; index < PAYLOAD_BYTES; ++index) {
    payload[index] = pattern(index);
  }
  for (unsigned index = 0; index < VECTOR_COUNT; ++index) {
    vectors[index].iov_base = payload + index * PAGE_BYTES;
    vectors[index].iov_len = PAGE_BYTES;
  }
  printf("DMA_WRITER_READY_V1 %s %u\n", local_control ? "local-file" : "virtio-block",
         PAYLOAD_BYTES);
  fflush(stdout);
  if (wait_for('W') != 0) {
    status = 5;
    goto free_payload;
  }
  ssize_t transferred = pwritev(descriptor, vectors, VECTOR_COUNT, PAGE_BYTES);
  if (transferred != PAYLOAD_BYTES) {
    io_error("pwritev", transferred, transferred < 0 ? errno : 0);
    status = 6;
    goto free_payload;
  }
  if (fsync(descriptor) != 0) {
    io_error("fsync", -1, errno);
    status = 6;
    goto free_payload;
  }

  /* Nonzero poison makes a missing or partial device-to-guest payload observable. */
  memset(payload, 0xa5, PAYLOAD_BYTES);
  puts("DMA_WRITER_READ_READY_V1");
  fflush(stdout);
  if (wait_for('R') != 0) {
    status = 5;
    goto free_payload;
  }
  transferred = preadv(descriptor, vectors, VECTOR_COUNT, PAGE_BYTES);
  if (transferred != PAYLOAD_BYTES) {
    io_error("preadv", transferred, transferred < 0 ? errno : 0);
    status = 7;
    goto free_payload;
  }
  for (unsigned index = 0; index < PAYLOAD_BYTES; ++index) {
    if (payload[index] != pattern(index)) {
      status = 8;
      goto free_payload;
    }
  }
  puts("DMA_WRITER_READ_DONE_V1");
  fflush(stdout);
  if (wait_for('Q') != 0) {
    status = 5;
  }

free_payload:
  free(payload);
close_descriptor:
  if (close(descriptor) != 0) {
    io_error("close", -1, errno);
    if (status == 0) {
      status = 9;
    }
  }
  return status;
}
