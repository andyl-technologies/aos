// SPDX-License-Identifier: Apache-2.0
/* PID 1 drives the real writer programs without accepting host console input. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum { LINE_BYTES = 256, COMMAND_BYTES = 4096 };

static int read_line(int descriptor, char line[LINE_BYTES]) {
  for (unsigned index = 0; index < LINE_BYTES - 1; ++index) {
    ssize_t count;
    do {
      count = read(descriptor, line + index, 1);
    } while (count < 0 && errno == EINTR);
    if (count != 1) {
      errno = count == 0 ? EPIPE : errno;
      return -1;
    }
    if (line[index] == 0) {
      errno = EPROTO;
      return -1;
    }
    if (line[index] == '\n') {
      line[index + 1] = 0;
      return 0;
    }
  }
  errno = EMSGSIZE;
  return -1;
}

static int milestone_matches(const char *line, const char *prefix, const char *name, int range) {
  size_t length = strlen(prefix);
  if (strncmp(line, prefix, length) != 0) {
    return 0;
  }
  if (name == NULL) {
    return strcmp(line + length, "\n") == 0;
  }
  line += length;
  length = strlen(name);
  if (strncmp(line, name, length) != 0) {
    return 0;
  }
  if (!range) {
    return strcmp(line + length, "\n") == 0;
  }
  unsigned offset, bytes;
  char excess;
  return line[length] == ' '
    && sscanf(line + length, "%u %u %c", &offset, &bytes, &excess) == 2
    && bytes > 0 && bytes <= 64 && offset <= 8192 - bytes;
}

/* A native selectable handoff must retain the stopped guest and deliver its
 * sequence-bound reply before this callback permits the next pipe command.
 * Serial markers and successful pipe exchanges do not establish a RAM root. */
typedef int (*boundary_fn)(unsigned stage);

static int run_writer(const char *program, const char *name, int dma, boundary_fn boundary) {
  int commands[2], output[2];
  if (pipe2(commands, O_CLOEXEC) != 0) {
    return -1;
  }
  if (pipe2(output, O_CLOEXEC) != 0) {
    int saved = errno;
    close(commands[0]);
    close(commands[1]);
    errno = saved;
    return -1;
  }
  pid_t child = fork();
  if (child < 0) {
    int saved = errno;
    close(commands[0]);
    close(commands[1]);
    close(output[0]);
    close(output[1]);
    errno = saved;
    return -1;
  }
  if (child == 0) {
    if (dup2(commands[0], STDIN_FILENO) < 0
        || dup2(output[1], STDOUT_FILENO) < 0
        || fcntl(STDIN_FILENO, F_SETFD, 0) < 0
        || fcntl(STDOUT_FILENO, F_SETFD, 0) < 0) {
      _exit(126);
    }
    /* PID 1 may start without stdin. A pipe then occupies fd 0, which must
     * survive exec even when dup2's source and destination are identical. */
    int inherited[] = {commands[0], commands[1], output[0], output[1]};
    for (unsigned index = 0; index < sizeof(inherited) / sizeof(inherited[0]); ++index) {
      if (inherited[index] > STDERR_FILENO) {
        close(inherited[index]);
      }
    }
    if (dma) {
      execl(program, program, "--virtio-block", "/dev/vda", (char *)NULL);
    } else {
      execl(program, program, name, (char *)NULL);
    }
    _exit(127);
  }
  close(commands[0]);
  close(output[1]);

  const char *cpu_prefixes[] = {"WRITER_READY_V1 ", "WRITER_STORED_V1 ", "WRITER_ZEROED_V1 "};
  const char *dma_prefixes[] = {"DMA_WRITER_READY_V1 virtio-block ",
                              "DMA_WRITER_READ_READY_V1", "DMA_WRITER_READ_DONE_V1"};
  const char *commands_by_kind = dma ? "WRQ" : "WZQ";
  int saved = 0;
  for (unsigned stage = 0; stage < 3; ++stage) {
    char line[LINE_BYTES];
    if (read_line(output[0], line) != 0) {
      saved = errno;
      break;
    }
    int matches = dma
      ? (stage == 0 ? strcmp(line, "DMA_WRITER_READY_V1 virtio-block 8192\n") == 0
                    : milestone_matches(line, dma_prefixes[stage], NULL, 0))
      : milestone_matches(line, cpu_prefixes[stage], name, stage == 0);
    if (!matches) {
      saved = EPROTO;
      break;
    }
    fputs(line, stdout);
    printf("RAM_WRITER_BOUNDARY_V1 stage=%u\n", stage + 1);
    fflush(stdout);
    if (boundary(stage) != 0) {
      saved = errno != 0 ? errno : EIO;
      break;
    }
    if (write(commands[1], commands_by_kind + stage, 1) != 1) {
      saved = errno;
      break;
    }
  }

  close(commands[1]);
  close(output[0]);
  if (saved != 0) {
    kill(child, SIGKILL);
  }
  int status;
  pid_t reaped;
  do {
    reaped = waitpid(child, &status, 0);
  } while (reaped < 0 && errno == EINTR);
  if (reaped != child && saved == 0) {
    saved = errno;
  }
  if (reaped == child && (!WIFEXITED(status) || WEXITSTATUS(status) != 0) && saved == 0) {
    saved = ECHILD;
  }
  if (saved != 0) {
    errno = saved;
    return -1;
  }
  return 0;
}

static void put_u16(unsigned char *bytes, unsigned offset, uint16_t value) {
  bytes[offset] = value;
  bytes[offset + 1] = value >> 8;
}

static void put_u32(unsigned char *bytes, unsigned offset, uint32_t value) {
  for (unsigned index = 0; index < 4; ++index) {
    bytes[offset + index] = value >> (index * 8);
  }
}

static void put_u64(unsigned char *bytes, unsigned offset, uint64_t value) {
  for (unsigned index = 0; index < 8; ++index) {
    bytes[offset + index] = value >> (index * 8);
  }
}

static void put_range(unsigned char *bytes, unsigned offset, uint32_t start, uint32_t length) {
  put_u32(bytes, offset, start);
  put_u32(bytes, offset + 4, length);
}

static void prepare_registration(unsigned char registration[81]) {
  memset(registration, 0, 81);
  put_u16(registration, 0, 1);
  put_u16(registration, 2, 1);
  put_u16(registration, 4, 56);
  put_u32(registration, 8, 81);
  put_u64(registration, 12, 1);
  put_range(registration, 20, 56, 12);
  put_range(registration, 28, 68, 1);
  put_range(registration, 36, 69, 1);
  put_range(registration, 44, 70, 11);
  put_u16(registration, 52, 1);
  memcpy(registration + 56, "flight.ready", 12);
  registration[68] = 1;
  registration[69] = 1;
  put_u16(registration, 70, 9);
  memcpy(registration + 72, "readiness", 9);
}

static void prepare_request(unsigned char request[128], unsigned stage) {
  memset(request, 0, 128);
  put_u16(request, 0, 1);
  put_u16(request, 2, 2);
  put_u16(request, 4, 48);
  put_u32(request, 8, 128);
  put_u64(request, 12, 2 + stage);
  put_range(request, 20, 48, 12);
  put_range(request, 28, 60, 4);
  put_u32(request, 44, 64);
  memcpy(request + 48, "flight.ready", 12);
  memcpy(request + 60, stage == 0 ? "boot" : stage == 1 ? "w001" : "z001", 4);
}

static uint64_t read_unsigned(const unsigned char *bytes, unsigned length) {
  uint64_t value = 0;
  for (unsigned index = 0; index < length; ++index) {
    value |= (uint64_t)bytes[index] << (8 * index);
  }
  return value;
}

static int validate_reply(const unsigned char reply[128], unsigned stage) {
  /* Existing selectable v1: selected Unit value, exact sequence and dense
   * 96-byte header plus one value byte. Opaque host IDs are not new authority. */
  if (read_unsigned(reply, 2) != 1 || read_unsigned(reply + 2, 2) != 3
      || read_unsigned(reply + 4, 2) != 96 || read_unsigned(reply + 6, 2) != 0
      || read_unsigned(reply + 8, 4) != 97 || read_unsigned(reply + 12, 8) != 2 + stage
      || read_unsigned(reply + 20, 4) != 0 || read_unsigned(reply + 88, 4) != 96
      || read_unsigned(reply + 92, 4) != 1 || reply[96] != 1) {
    errno = EPROTO;
    return -1;
  }
  for (unsigned index = 97; index < 128; ++index) {
    if (reply[index] != 0) {
      errno = EPROTO;
      return -1;
    }
  }
  return 0;
}

#ifndef RAM_WRITER_LOCAL_CONTROL
static void emit_doorbell(void *payload, unsigned length) {
  uintptr_t address = (uintptr_t)payload;
  __asm__ volatile("outb %%al, $0xe7" : : "a"(address), "c"(length) : "memory");
}

static void register_readiness(void) {
  unsigned char registration[81];
  static const unsigned char setup[] = {
    0x43, 0x52, 0x42, 0x4c, 0x03, 0x00, 0x02,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00,
  };
  prepare_registration(registration);
  emit_doorbell(registration, sizeof(registration));
  emit_doorbell((void *)setup, sizeof(setup));
}

static int guest_boundary(unsigned stage) {
  unsigned char request[128];
  prepare_request(request, stage);
  emit_doorbell(request, sizeof(request));
  return validate_reply(request, stage);
}

static int read_case(char name[LINE_BYTES]) {
  FILE *stream = fopen("/proc/cmdline", "r");
  if (stream == NULL) {
    return -1;
  }
  char command[COMMAND_BYTES];
  int success = fgets(command, sizeof(command), stream) != NULL;
  int saved = errno;
  if (success && strchr(command, '\n') == NULL && !feof(stream)) {
    success = 0;
    saved = EMSGSIZE;
  }
  if (fclose(stream) != 0 && success) {
    success = 0;
    saved = errno;
  }
  if (!success) {
    errno = saved != 0 ? saved : EIO;
    return -1;
  }
  unsigned found = 0;
  char *context = NULL;
  for (char *word = strtok_r(command, " \t\n", &context); word != NULL;
       word = strtok_r(NULL, " \t\n", &context)) {
    const char *prefix = "crucible.writer=";
    if (strncmp(word, prefix, strlen(prefix)) != 0) {
      continue;
    }
    const char *value = word + strlen(prefix);
    if (++found != 1 || strlen(value) == 0 || strlen(value) >= LINE_BYTES) {
      errno = EINVAL;
      return -1;
    }
    strcpy(name, value);
  }
  if (found != 1) {
    errno = EINVAL;
    return -1;
  }
  return 0;
}

int main(void) {
  /* This binary is the guest init, never a host admission or VM launcher. */
  if (getpid() != 1) {
    return 2;
  }
  if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0
      || mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0
      || mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, NULL) != 0) {
    return 3;
  }
  int console = open("/dev/ttyS0", O_WRONLY | O_NOCTTY | O_CLOEXEC);
  if (console < 0 || dup2(console, STDOUT_FILENO) < 0 || dup2(console, STDERR_FILENO) < 0
      || fcntl(STDOUT_FILENO, F_SETFD, 0) < 0 || fcntl(STDERR_FILENO, F_SETFD, 0) < 0) {
    return 4;
  }
  if (console > STDERR_FILENO) {
    close(console);
  }
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    return 4;
  }
  cpu_set_t affinity;
  CPU_ZERO(&affinity);
  CPU_SET(0, &affinity);
  if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0 || sched_getcpu() != 0
      || iopl(3) != 0) {
    return 5;
  }
  char name[LINE_BYTES];
  if (read_case(name) != 0) {
    perror("RAM_WRITER_BOOT_REFUSED_V1 cmdline");
    return 6;
  }
  register_readiness();
  int dma = strcmp(name, "dma-virtio") == 0;
  int outcome = run_writer(dma ? "/dma-writer-guest" : "/writer-guest", name, dma, guest_boundary);
  if (outcome != 0) {
    perror("RAM_WRITER_BOOT_FAILED_V1");
    return 7;
  }
  puts("RAM_WRITER_BOOT_COMPLETE_V1");
  fflush(stdout);
  /* Physical retirement belongs to the genuine host owner, without a new
   * guest timeout or a self-reported host resource refund. */
  for (;;) {
    pause();
  }
}
#endif
