#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SSH_KEYGEN_PATH
#error "SSH_KEYGEN_PATH must name the package-owned ssh-keygen binary"
#endif

#define HOST_KEY_PATH "/var/etc/ssh/ssh_host_ed25519_key"

static int host_key_is_present(void)
{
  struct stat metadata;

  if (stat(HOST_KEY_PATH, &metadata) == 0)
    return metadata.st_size > 0;
  if (errno == ENOENT)
    return 0;

  fprintf(stderr, "aos-openssh-host-key: failed to inspect %s: %s\n",
          HOST_KEY_PATH, strerror(errno));
  return -1;
}

static int wait_for_keygen(pid_t child)
{
  int status;

  while (waitpid(child, &status, 0) < 0) {
    if (errno == EINTR)
      continue;
    fprintf(stderr, "aos-openssh-host-key: failed to wait for ssh-keygen: %s\n",
            strerror(errno));
    return 1;
  }

  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) {
    fprintf(stderr, "aos-openssh-host-key: ssh-keygen terminated by signal %d\n",
            WTERMSIG(status));
  } else {
    fprintf(stderr, "aos-openssh-host-key: ssh-keygen terminated unexpectedly\n");
  }
  return 1;
}

int main(void)
{
  int present = host_key_is_present();
  if (present < 0)
    return 1;
  if (present > 0)
    return 0;

  printf("aos-openssh-host-key: generating ed25519 host key at %s\n",
         HOST_KEY_PATH);
  fflush(stdout);

  pid_t child = fork();
  if (child < 0) {
    fprintf(stderr, "aos-openssh-host-key: failed to start ssh-keygen: %s\n",
            strerror(errno));
    return 1;
  }
  if (child == 0) {
    int null_input = open("/dev/null", O_RDONLY);
    if (null_input < 0 || dup2(null_input, STDIN_FILENO) < 0) {
      fprintf(stderr, "aos-openssh-host-key: failed to connect /dev/null: %s\n",
              strerror(errno));
      _exit(127);
    }
    if (null_input != STDIN_FILENO)
      close(null_input);

    execl(SSH_KEYGEN_PATH, "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
          "-f", HOST_KEY_PATH, (char *)NULL);
    fprintf(stderr, "aos-openssh-host-key: failed to execute %s: %s\n",
            SSH_KEYGEN_PATH, strerror(errno));
    _exit(127);
  }

  return wait_for_keygen(child);
}
