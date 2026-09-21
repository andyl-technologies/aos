/* Exercises Guile's blocking API with its private wakeup pipe above FD_SETSIZE. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <libguile.h>

static int
check (int condition, const char *message)
{
  if (!condition)
    fprintf (stderr, "%s (errno=%d)\n", message, errno);
  return condition;
}

int
main (void)
{
  struct rlimit limit;
  struct timeval timeout;
  struct timespec before, after;
  fd_set reads, writes, exceptions;
  int sockets[2], descriptor, result;
  long long elapsed_ns;
  char byte = 'x';

  if (getrlimit (RLIMIT_NOFILE, &limit) < 0)
    return 1;
  limit.rlim_cur = limit.rlim_max;
  if (setrlimit (RLIMIT_NOFILE, &limit) < 0)
    return 1;

  /* Keep caller-visible descriptors low, then occupy every remaining low slot
     before Guile creates its private wakeup pipe. */
  if (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets) < 0)
    return 1;
  do
    {
      descriptor = open ("/dev/null", O_RDONLY | O_CLOEXEC);
      if (!check (descriptor >= 0, "reserve descriptors"))
        return 1;
    }
  while (descriptor < FD_SETSIZE);

  scm_init_guile ();

  timeout = (struct timeval) { 0, 20000 };
  if (clock_gettime (CLOCK_MONOTONIC, &before) < 0)
    return 1;
  result = scm_std_select (0, NULL, NULL, NULL, &timeout);
  if (clock_gettime (CLOCK_MONOTONIC, &after) < 0)
    return 1;
  elapsed_ns = (after.tv_sec - before.tv_sec) * 1000000000LL
    + after.tv_nsec - before.tv_nsec;
  if (!check (result == 0 && timeout.tv_sec == 0 && timeout.tv_usec == 0,
              "timeout returns no ready descriptors and no remaining time")
      || !check (elapsed_ns >= 19000000, "timeout does not return early"))
    return 1;

  if (write (sockets[1], &byte, 1) != 1)
    return 1;
  FD_ZERO (&reads);
  FD_ZERO (&writes);
  FD_ZERO (&exceptions);
  FD_SET (sockets[0], &reads);
  FD_SET (sockets[0], &writes);
  FD_SET (sockets[0], &exceptions);
  timeout = (struct timeval) { 0, 0 };
  result = scm_std_select (sockets[0] + 1, &reads, &writes, &exceptions,
                           &timeout);
  if (!check (result == 2 && FD_ISSET (sockets[0], &reads)
              && FD_ISSET (sockets[0], &writes)
              && !FD_ISSET (sockets[0], &exceptions),
              "readiness counts each ready set, not each descriptor"))
    return 1;

  FD_ZERO (&reads);
  FD_SET (sockets[0], &reads);
  result = scm_std_select (sockets[0] + 1, &reads, NULL, NULL, NULL);
  if (!check (result == 1 && FD_ISSET (sockets[0], &reads),
              "an unbounded wait returns ready input"))
    return 1;

  if (close (sockets[1]) < 0)
    return 1;
  FD_ZERO (&reads);
  FD_SET (sockets[1], &reads);
  timeout = (struct timeval) { 0, 0 };
  result = scm_std_select (sockets[1] + 1, &reads, NULL, NULL, &timeout);
  if (!check (result == -1 && errno == EBADF,
              "closed descriptors return EBADF"))
    return 1;

  result = scm_std_select (-1, NULL, NULL, NULL, &timeout);
  if (!check (result == -1 && errno == EINVAL,
              "negative descriptor counts return EINVAL"))
    return 1;

  puts ("high wakeup descriptor checks passed");
  return 0;
}
