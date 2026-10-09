#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define DESCENDANT_PID_FILE "/run/aos-zfs-worker-test/descendant.pid"

static int exact_argument(const char *actual, const char *expected) {
  return strcmp(actual, expected) == 0;
}

static int new_pid1_socket_is_denied(void) {
  int descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (descriptor == -1) {
    return errno == EPERM;
  }

  struct sockaddr_un address = {.sun_family = AF_UNIX};
  (void)snprintf(address.sun_path, sizeof(address.sun_path),
                 "/run/systemd/private");
  (void)connect(descriptor, (const struct sockaddr *)&address, sizeof(address));
  (void)close(descriptor);
  return 0;
}

static void sleep_for_a_minute(void) {
  struct timespec remaining = {.tv_sec = 60, .tv_nsec = 0};

  while (nanosleep(&remaining, &remaining) == -1 && errno == EINTR) {
  }
}

static int record_descendant_pid(void) {
  char rendered[32];
  int length = snprintf(rendered, sizeof(rendered), "%ld\n", (long)getpid());
  if (length <= 0 || (size_t)length >= sizeof(rendered)) {
    return 1;
  }

  int descriptor = open(DESCENDANT_PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (descriptor == -1) {
    return 1;
  }

  ssize_t written = write(descriptor, rendered, (size_t)length);
  int close_result = close(descriptor);
  return written == (ssize_t)length && close_result == 0 ? 0 : 1;
}

int main(int argc, char **argv, char **environment) {
  if (environment[0] != NULL) {
    return 65;
  }
  if (!new_pid1_socket_is_denied()) {
    return 66;
  }

  if (argc == 6 && exact_argument(argv[1], "set") &&
      exact_argument(argv[2], "quota=268435456") &&
      exact_argument(argv[3], "filesystem_limit=8") &&
      exact_argument(argv[4], "snapshot_limit=16") &&
      exact_argument(argv[5], "aosproof/aos/project")) {
    return 0;
  }

  if (argc != 5 || !exact_argument(argv[1], "set") ||
      !exact_argument(argv[2], "refquota=4096") ||
      !exact_argument(argv[3], "reservation=1024")) {
    return 64;
  }
  if (exact_argument(argv[4], "aosproof/aos/project/fast")) {
    return 0;
  }
  if (!exact_argument(argv[4], "aosproof/aos/project/timeout")) {
    return 64;
  }

  pid_t child = fork();
  if (child == -1) {
    return 1;
  }
  if (child == 0) {
    if (setsid() == -1) {
      _exit(1);
    }
    (void)close(STDIN_FILENO);
    (void)close(STDOUT_FILENO);
    (void)close(STDERR_FILENO);
    if (record_descendant_pid() != 0) {
      _exit(1);
    }
    sleep_for_a_minute();
    _exit(0);
  }

  sleep_for_a_minute();
  return 0;
}
