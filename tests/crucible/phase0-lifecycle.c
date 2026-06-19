#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
  WAIT_TIMEOUT = -2,
};

struct counters {
  unsigned int clean_stop;
  unsigned int control_stop;
  unsigned int guest_crash;
  unsigned int plugin_hang;
  unsigned int setup_failure;
  unsigned int host_sigkill;
  unsigned int parent_death;
  unsigned int survivors;
  unsigned int reaped;
};

static void
sleep_ms(long ms)
{
  struct timespec ts = {
      .tv_sec = ms / 1000,
      .tv_nsec = (ms % 1000) * 1000000L,
  };
  while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
  }
}

static bool
pid_exists(pid_t pid)
{
  return kill(pid, 0) == 0 || errno == EPERM;
}

static int
wait_for_exit(pid_t pid, int timeout_ms, int *status_out)
{
  const int step_ms = 10;
  int waited = 0;

  for (;;) {
    int status = 0;
    pid_t rc = waitpid(pid, &status, WNOHANG);
    if (rc == pid) {
      if (status_out != NULL) {
        *status_out = status;
      }
      return 0;
    }
    if (rc == -1) {
      return errno == ECHILD ? 0 : -1;
    }
    if (waited >= timeout_ms) {
      return WAIT_TIMEOUT;
    }
    sleep_ms(step_ms);
    waited += step_ms;
  }
}

static bool
ensure_gone(pid_t pid, struct counters *counters)
{
  int status = 0;
  int rc = wait_for_exit(pid, 100, &status);
  if (rc == 0) {
    counters->reaped++;
    return true;
  }

  if (pid_exists(pid)) {
    kill(pid, SIGKILL);
    wait_for_exit(pid, 2000, &status);
  }
  if (pid_exists(pid)) {
    counters->survivors++;
    return false;
  }
  counters->reaped++;
  return true;
}

static pid_t
spawn_child(char *const argv[], bool die_with_parent)
{
  pid_t pid = fork();
  if (pid == -1) {
    return -1;
  }
  if (pid == 0) {
    if (die_with_parent) {
      if (prctl(PR_SET_PDEATHSIG, SIGKILL) == -1) {
        _exit(127);
      }
      if (getppid() == 1) {
        _exit(126);
      }
    }
    execv(argv[0], argv);
    _exit(125);
  }
  return pid;
}

static char **
base_qemu_argv(const char *qemu)
{
  char **argv = calloc(13, sizeof(*argv));
  if (argv == NULL) {
    return NULL;
  }
  argv[0] = (char *)qemu;
  argv[1] = "-nodefaults";
  argv[2] = "-no-user-config";
  argv[3] = "-display";
  argv[4] = "none";
  argv[5] = "-machine";
  argv[6] = "none";
  argv[7] = "-S";
  argv[8] = "-monitor";
  argv[9] = "none";
  argv[10] = "-serial";
  argv[11] = "none";
  argv[12] = NULL;
  return argv;
}

static int
connect_unix_socket(const char *path, int timeout_ms)
{
  const int step_ms = 10;
  int waited = 0;

  while (waited <= timeout_ms) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
      return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t path_len = strlen(path);
    if (path_len >= sizeof(addr.sun_path)) {
      close(fd);
      return -1;
    }
    memcpy(addr.sun_path, path, path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      return fd;
    }

    close(fd);
    sleep_ms(step_ms);
    waited += step_ms;
  }

  return -1;
}

static bool
qmp_quit(const char *socket_path)
{
  int fd = connect_unix_socket(socket_path, 5000);
  if (fd == -1) {
    return false;
  }

  const char *capabilities = "{\"execute\":\"qmp_capabilities\"}\r\n";
  ssize_t written = write(fd, capabilities, strlen(capabilities));
  if (written != (ssize_t)strlen(capabilities)) {
    close(fd);
    return false;
  }

  sleep_ms(100);

  const char *quit = "{\"execute\":\"quit\"}\r\n";
  written = write(fd, quit, strlen(quit));
  close(fd);
  return written == (ssize_t)strlen(quit);
}

static bool
run_clean_stop(const char *qemu, const char *tmpdir, struct counters *counters)
{
  char qmp_arg[512];
  char qmp_path[256];
  snprintf(qmp_path, sizeof(qmp_path), "%s/lifecycle-clean.qmp", tmpdir);
  unlink(qmp_path);
  snprintf(qmp_arg, sizeof(qmp_arg), "unix:%s,server=on,wait=off", qmp_path);

  char *argv[] = {
      (char *)qemu,
      "-nodefaults",
      "-no-user-config",
      "-display",
      "none",
      "-machine",
      "none",
      "-S",
      "-monitor",
      "none",
      "-serial",
      "none",
      "-qmp",
      qmp_arg,
      NULL,
  };

  pid_t pid = spawn_child(argv, true);
  if (pid == -1 || !qmp_quit(qmp_path)) {
    if (pid > 0) {
      kill(pid, SIGKILL);
      ensure_gone(pid, counters);
    }
    return false;
  }

  int status = 0;
  bool ok = wait_for_exit(pid, 5000, &status) == 0;
  if (ok) {
    counters->reaped++;
  } else {
    kill(pid, SIGKILL);
    ensure_gone(pid, counters);
  }
  counters->clean_stop += ok ? 1U : 0U;
  return ok && !pid_exists(pid);
}

static bool
run_signal_stop(const char *qemu, int signal_number, unsigned int *counter, struct counters *counters)
{
  char **argv = base_qemu_argv(qemu);
  if (argv == NULL) {
    return false;
  }

  pid_t pid = spawn_child(argv, true);
  free(argv);
  if (pid == -1) {
    return false;
  }

  sleep_ms(100);
  int status = 0;
  if (wait_for_exit(pid, 0, &status) == 0 || !pid_exists(pid)) {
    counters->reaped++;
    return false;
  }
  if (kill(pid, signal_number) == -1) {
    ensure_gone(pid, counters);
    return false;
  }

  bool ok = wait_for_exit(pid, 5000, &status) == 0;
  bool expected_status =
      signal_number == SIGKILL
          ? (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)
          : true;
  if (ok && expected_status && !pid_exists(pid)) {
    counters->reaped++;
    (*counter)++;
    return true;
  }
  return ensure_gone(pid, counters) && false;
}

static bool
run_setup_failure(const char *qemu, struct counters *counters)
{
  char *argv[] = {
      (char *)qemu,
      "-definitely-not-a-real-qemu-option",
      NULL,
  };

  pid_t pid = spawn_child(argv, true);
  if (pid == -1) {
    return false;
  }

  int status = 0;
  bool exited = wait_for_exit(pid, 5000, &status) == 0;
  if (exited) {
    counters->reaped++;
  } else {
    kill(pid, SIGKILL);
    ensure_gone(pid, counters);
  }
  bool failed_as_expected = exited && WIFEXITED(status) && WEXITSTATUS(status) != 0;
  counters->setup_failure += failed_as_expected ? 1U : 0U;
  return failed_as_expected && !pid_exists(pid);
}

static bool
run_plugin_hang(const char *qemu, const char *plugin, struct counters *counters)
{
  char plugin_arg[512];
  snprintf(plugin_arg, sizeof(plugin_arg), "%s", plugin);
  char *argv[] = {
      (char *)qemu,
      "-nodefaults",
      "-no-user-config",
      "-display",
      "none",
      "-machine",
      "none",
      "-plugin",
      plugin_arg,
      NULL,
  };

  pid_t pid = spawn_child(argv, true);
  if (pid == -1) {
    return false;
  }

  sleep_ms(250);
  int status = 0;
  if (wait_for_exit(pid, 0, &status) == 0 || !pid_exists(pid)) {
    counters->reaped++;
    return false;
  }

  kill(pid, SIGTERM);
  if (wait_for_exit(pid, 1000, &status) == WAIT_TIMEOUT) {
    kill(pid, SIGKILL);
  }

  bool gone = ensure_gone(pid, counters);
  counters->plugin_hang += gone ? 1U : 0U;
  return gone;
}

static bool
file_contains(const char *path, const char *needle)
{
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    return false;
  }

  bool found = false;
  char line[1024];
  while (fgets(line, sizeof(line), file) != NULL) {
    if (strstr(line, needle) != NULL) {
      found = true;
      break;
    }
  }

  fclose(file);
  return found;
}

static bool
run_guest_crash(
    const char *qemu,
    const char *vmlinuz,
    const char *rootfs,
    const char *serial_log,
    struct counters *counters)
{
  char drive_arg[512];
  snprintf(drive_arg, sizeof(drive_arg), "id=rootfs,file=%s,format=raw,if=none,cache=unsafe", rootfs);

  char serial_arg[1024];
  snprintf(serial_arg, sizeof(serial_arg), "file:%s", serial_log);

  char *argv[] = {
      (char *)qemu,
      "-nodefaults",
      "-no-user-config",
      "-display",
      "none",
      "-monitor",
      "none",
      "-machine",
      "q35",
      "-accel",
      "tcg,thread=single",
      "-cpu",
      "qemu64",
      "-m",
      "512",
      "-smp",
      "1",
      "-kernel",
      (char *)vmlinuz,
      "-append",
      "console=ttyS0 panic=1 root=/dev/vda ro init=/init quiet",
      "-drive",
      drive_arg,
      "-device",
      "virtio-blk-pci,drive=rootfs",
      "-serial",
      serial_arg,
      "-no-reboot",
      NULL,
  };

  pid_t pid = spawn_child(argv, true);
  if (pid == -1) {
    return false;
  }

  int status = 0;
  bool exited = wait_for_exit(pid, 60000, &status) == 0;
  if (exited) {
    counters->reaped++;
  }
  counters->guest_crash += exited ? 1U : 0U;
  if (!exited) {
    kill(pid, SIGKILL);
    ensure_gone(pid, counters);
  }
  return exited && !pid_exists(pid) &&
         file_contains(serial_log, "CRUCIBLE_LIFECYCLE_GUEST_CRASH") &&
         file_contains(serial_log, "sysrq: Trigger a crash") &&
         file_contains(serial_log, "Kernel panic");
}

static bool
run_parent_death(const char *qemu, struct counters *counters)
{
  int pipe_fds[2];
  if (pipe(pipe_fds) == -1) {
    return false;
  }

  pid_t supervisor = fork();
  if (supervisor == -1) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return false;
  }

  if (supervisor == 0) {
    close(pipe_fds[0]);
    char **argv = base_qemu_argv(qemu);
    if (argv == NULL) {
      _exit(120);
    }
    pid_t qemu_pid = spawn_child(argv, true);
    free(argv);
    if (qemu_pid == -1) {
      _exit(121);
    }
    if (write(pipe_fds[1], &qemu_pid, sizeof(qemu_pid)) != (ssize_t)sizeof(qemu_pid)) {
      _exit(122);
    }
    close(pipe_fds[1]);
    _exit(99);
  }

  close(pipe_fds[1]);
  pid_t qemu_pid = -1;
  ssize_t read_bytes = read(pipe_fds[0], &qemu_pid, sizeof(qemu_pid));
  close(pipe_fds[0]);

  int status = 0;
  waitpid(supervisor, &status, 0);
  if (read_bytes != (ssize_t)sizeof(qemu_pid) || qemu_pid <= 0) {
    return false;
  }

  bool reaped_or_gone = false;
  int qemu_status = 0;
  int rc = wait_for_exit(qemu_pid, 5000, &qemu_status);
  if (rc == 0) {
    counters->reaped++;
    reaped_or_gone = WIFSIGNALED(qemu_status) && WTERMSIG(qemu_status) == SIGKILL;
  } else if (!pid_exists(qemu_pid)) {
    reaped_or_gone = false;
  } else {
    kill(qemu_pid, SIGKILL);
    ensure_gone(qemu_pid, counters);
  }

  counters->parent_death += reaped_or_gone ? 1U : 0U;
  return reaped_or_gone && !pid_exists(qemu_pid);
}

int
main(int argc, char **argv)
{
  if (argc != 6) {
    fprintf(stderr, "usage: %s QEMU VMLINUZ ROOTFS HANG_PLUGIN TMPDIR\n", argv[0]);
    return 2;
  }

  const char *qemu = argv[1];
  const char *vmlinuz = argv[2];
  const char *rootfs = argv[3];
  const char *plugin = argv[4];
  const char *tmpdir = argv[5];

  if (prctl(PR_SET_CHILD_SUBREAPER, 1) == -1) {
    fprintf(stderr, "PR_SET_CHILD_SUBREAPER failed: %s\n", strerror(errno));
    return 1;
  }

  struct counters counters = {0};
  char serial_log[512];
  snprintf(serial_log, sizeof(serial_log), "%s/lifecycle-guest-crash.serial", tmpdir);

  bool ok = true;
  ok = run_clean_stop(qemu, tmpdir, &counters) && ok;
  ok = run_signal_stop(qemu, SIGTERM, &counters.control_stop, &counters) && ok;
  ok = run_guest_crash(qemu, vmlinuz, rootfs, serial_log, &counters) && ok;
  ok = run_plugin_hang(qemu, plugin, &counters) && ok;
  ok = run_setup_failure(qemu, &counters) && ok;
  ok = run_signal_stop(qemu, SIGKILL, &counters.host_sigkill, &counters) && ok;
  ok = run_parent_death(qemu, &counters) && ok;

  if (counters.survivors != 0) {
    ok = false;
  }

  printf("%s\n", ok ? "PASS" : "FAIL");
  printf("spike=no-leak-lifecycle\n");
  printf("clean_stop=%u\n", counters.clean_stop);
  printf("control_stop=%u\n", counters.control_stop);
  printf("guest_crash=%u\n", counters.guest_crash);
  printf("plugin_hang=%u\n", counters.plugin_hang);
  printf("setup_failure=%u\n", counters.setup_failure);
  printf("host_sigkill=%u\n", counters.host_sigkill);
  printf("parent_death=%u\n", counters.parent_death);
  printf("survivors=%u\n", counters.survivors);
  printf("reaped=%u\n", counters.reaped);
  printf("serial_log=%s\n", serial_log);

  return ok ? 0 : 1;
}
