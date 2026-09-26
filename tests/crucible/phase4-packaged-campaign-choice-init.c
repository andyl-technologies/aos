/*
 * Diskless PID 1 for the packaged campaign guest-choice flight.
 *
 * The guest registers and consumes one discrete and one integer selectable.
 * Their replies determine the observable result marker. A slow, sequenced
 * suffix then gives the test durable evidence that exact resume progressed
 * beyond the event-log boundary captured before daemon restart.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char recovery_fast_id[] =
    "0101010101010101010101010101010101010101010101010101010101010101";
static const char recovery_safe_id[] =
    "0202020202020202020202020202020202020202020202020202020202020202";

static int initialize_standard_streams(void) {
  if (mkdir("/dev", 0755) != 0 && errno != EEXIST) {
    return -1;
  }
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, "") != 0 && errno != EBUSY) {
    return -1;
  }

  int null_fd = open("/dev/null", O_RDONLY);
  int console_fd = open("/dev/console", O_WRONLY);
  if (null_fd < 0 || console_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
      dup2(console_fd, STDOUT_FILENO) < 0 ||
      dup2(console_fd, STDERR_FILENO) < 0) {
    if (null_fd >= 0) {
      close(null_fd);
    }
    if (console_fd >= 0) {
      close(console_fd);
    }
    return -1;
  }

  if (null_fd > STDERR_FILENO) {
    close(null_fd);
  }
  if (console_fd > STDERR_FILENO) {
    close(console_fd);
  }
  return 0;
}

static int run_guest(char *const argv[], char *output, size_t output_capacity) {
  int output_pipe[2];
  if (pipe(output_pipe) != 0) {
    return -1;
  }

  pid_t child = fork();
  if (child < 0) {
    close(output_pipe[0]);
    close(output_pipe[1]);
    return -1;
  }
  if (child == 0) {
    close(output_pipe[0]);
    if (dup2(output_pipe[1], STDOUT_FILENO) < 0) {
      _exit(126);
    }
    if (output_pipe[1] != STDOUT_FILENO) {
      close(output_pipe[1]);
    }
    execv(argv[0], argv);
    _exit(127);
  }

  close(output_pipe[1]);
  size_t used = 0;
  int overflow = 0;
  for (;;) {
    char scratch[128];
    ssize_t count = read(output_pipe[0], scratch, sizeof(scratch));
    if (count == 0) {
      break;
    }
    if (count < 0) {
      close(output_pipe[0]);
      (void)waitpid(child, 0, 0);
      return -1;
    }

    size_t available = output_capacity > used ? output_capacity - used - 1 : 0;
    size_t copied = (size_t)count < available ? (size_t)count : available;
    if (copied > 0) {
      memcpy(output + used, scratch, copied);
      used += copied;
    }
    if (copied != (size_t)count) {
      overflow = 1;
    }
  }
  close(output_pipe[0]);

  int status = 0;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0 || overflow || output_capacity == 0) {
    return -1;
  }
  while (used > 0 && (output[used - 1] == '\n' || output[used - 1] == '\r')) {
    --used;
  }
  output[used] = '\0';
  return 0;
}

static void park_forever(void) {
  const struct timespec interval = {1, 0};
  for (;;) {
    (void)nanosleep(&interval, 0);
  }
}

static int configure_selectables(int *fast_recovery, uint64_t *retry_quanta) {
  char empty[1];
  char *register_recovery[] = {
      "/crucible-guest",
      "selectable",
      "register-discrete",
      "1",
      "campaign.recovery-policy",
      (char *)recovery_safe_id,
      "0101010101010101010101010101010101010101010101010101010101010101=fast",
      "0202020202020202020202020202020202020202020202020202020202020202=safe",
      0,
  };
  if (run_guest(register_recovery, empty, sizeof(empty)) != 0) {
    return -1;
  }

  char *register_retry[] = {
      "/crucible-guest",
      "selectable",
      "register-u64",
      "2",
      "campaign.retry-quanta",
      "1",
      "9",
      "2",
      "3",
      "quanta",
      0,
  };
  if (run_guest(register_retry, empty, sizeof(empty)) != 0) {
    return -2;
  }

  char *setup_complete[] = {
      "/crucible-guest",
      "setup-complete",
      0,
  };
  if (run_guest(setup_complete, empty, sizeof(empty)) != 0) {
    return -3;
  }

  char recovery[80];
  char *choose_recovery[] = {
      "/crucible-guest",
      "selectable",
      "choose-discrete",
      "1",
      "campaign.recovery-policy",
      "campaign/e2e",
      (char *)recovery_fast_id,
      (char *)recovery_safe_id,
      0,
  };
  if (run_guest(choose_recovery, recovery, sizeof(recovery)) != 0 ||
      strncmp(recovery, "discrete=", 9) != 0) {
    return -4;
  }
  const char *recovery_id = recovery + 9;
  if (strcmp(recovery_id, recovery_fast_id) == 0) {
    *fast_recovery = 1;
  } else if (strcmp(recovery_id, recovery_safe_id) == 0) {
    *fast_recovery = 0;
  } else {
    return -5;
  }

  char retry[32];
  char *choose_retry[] = {
      "/crucible-guest",
      "selectable",
      "choose-u64",
      "2",
      "campaign.retry-quanta",
      "campaign/e2e",
      "1",
      "9",
      "2",
      0,
  };
  if (run_guest(choose_retry, retry, sizeof(retry)) != 0 ||
      strncmp(retry, "u64=", 4) != 0) {
    return -6;
  }
  char *end = 0;
  unsigned long long parsed = strtoull(retry + 4, &end, 10);
  if (end == retry + 4 || *end != '\0' || parsed < 1 || parsed > 9 ||
      ((parsed - 1) % 2) != 0) {
    return -7;
  }
  *retry_quanta = (uint64_t)parsed;
  return 0;
}

static int emit_selection_event(const char *selection, int fast_recovery,
                                uint64_t retry_quanta) {
  char policy_detail[32];
  int policy_length =
      snprintf(policy_detail, sizeof(policy_detail), "policy=%s",
               fast_recovery ? "fast" : "safe");
  char retry_detail[32];
  int retry_length =
      snprintf(retry_detail, sizeof(retry_detail), "retry=%llu",
               (unsigned long long)retry_quanta);
  if (policy_length <= 0 || policy_length >= (int)sizeof(policy_detail) ||
      retry_length <= 0 || retry_length >= (int)sizeof(retry_detail)) {
    return -1;
  }

  char empty[1];
  char *selected[] = {
      "/crucible-guest",
      "event",
      (char *)selection,
      policy_detail,
      retry_detail,
      0,
  };
  return run_guest(selected, empty, sizeof(empty));
}

static void emit_progress_forever(const char *selection) {
  const struct timespec interval = {0, 1000000};
  uint64_t sequence = 1;

  for (;;) {
    (void)nanosleep(&interval, 0);

    char marker[96];
    int marker_length =
        snprintf(marker, sizeof(marker), "%s-progress-%06llu", selection,
                 (unsigned long long)sequence);
    char sequence_detail[32];
    int detail_length =
        snprintf(sequence_detail, sizeof(sequence_detail), "sequence=%llu",
                 (unsigned long long)sequence);
    if (marker_length <= 0 || marker_length >= (int)sizeof(marker) ||
        detail_length <= 0 || detail_length >= (int)sizeof(sequence_detail)) {
      park_forever();
    }

    char empty[1];
    char *progress[] = {
        "/crucible-guest",
        "event",
        marker,
        sequence_detail,
        0,
    };
    if (run_guest(progress, empty, sizeof(empty)) != 0) {
      park_forever();
    }
    if (sequence == UINT64_MAX) {
      park_forever();
    }
    ++sequence;
  }
}

int main(void) {
  if (initialize_standard_streams() != 0) {
    park_forever();
  }

  int fast_recovery = 0;
  uint64_t retry_quanta = 0;
  if (configure_selectables(&fast_recovery, &retry_quanta) != 0) {
    char *failed[] = {
        "/crucible-guest",
        "event",
        "selection-configuration-failed",
        0,
    };
    char empty[1];
    (void)run_guest(failed, empty, sizeof(empty));
    park_forever();
  }

  char selection[64];
  int selection_length =
      snprintf(selection, sizeof(selection), "selected-%s-q%llu",
               fast_recovery ? "fast" : "safe",
               (unsigned long long)retry_quanta);
  if (selection_length <= 0 || selection_length >= (int)sizeof(selection) ||
      emit_selection_event(selection, fast_recovery, retry_quanta) != 0) {
    park_forever();
  }

  emit_progress_forever(selection);
}
