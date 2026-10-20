#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define HOST_POLICY_MARKER "/run/aos/host-policy-live"
#define POLL_ATTEMPTS 150
#define POLL_INTERVAL_NANOSECONDS 100000000L

static void sleep_for_poll_interval(void)
{
  struct timespec remaining = {
    .tv_sec = 0,
    .tv_nsec = POLL_INTERVAL_NANOSECONDS,
  };

  while (nanosleep(&remaining, &remaining) < 0 && errno == EINTR)
    ;
}

int main(void)
{
  for (unsigned int attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
    if (access(HOST_POLICY_MARKER, F_OK) == 0)
      return 0;
    sleep_for_poll_interval();
  }

  if (access(HOST_POLICY_MARKER, F_OK) != 0) {
    fprintf(stderr,
            "aos-openssh-host-policy-wait: host policy did not activate within "
            "15 seconds; allowing recovery SSH startup\n");
  }
  return 0;
}
