// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AOS_KERNEL_EXPORT_DENY_LOADER
#error "AOS_KERNEL_EXPORT_DENY_LOADER must name the built loader"
#endif

static int invoke_loader(const char *action, int source_fd)
{
  char fd_text[32];
  pid_t child;
  int status;

  snprintf(fd_text, sizeof(fd_text), "%d", source_fd);
  child = fork();
  if (child == 0) {
    execl(AOS_KERNEL_EXPORT_DENY_LOADER,
          AOS_KERNEL_EXPORT_DENY_LOADER, action, fd_text, (char *)NULL);
    _exit(127);
  }
  if (child < 0 || waitpid(child, &status, 0) != child ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0)
    return -1;
  return 0;
}

static int deny_existing_fd_in_child(int source_fd)
{
  pid_t child = fork();
  int status;
  char byte;

  if (child == 0) {
    errno = 0;
    _exit(pread(source_fd, &byte, 1, 0) == -1 && errno == EACCES ? 0 : 1);
  }
  return child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int deny_scm_rights(int source_fd)
{
  int sockets[2];
  char byte = 'x';
  char control[CMSG_SPACE(sizeof(source_fd))];
  struct iovec io = {.iov_base = &byte, .iov_len = 1};
  struct msghdr message = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  struct cmsghdr *header;
  int result = -1;

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0)
    return -1;
  memset(control, 0, sizeof(control));
  header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(source_fd));
  memcpy(CMSG_DATA(header), &source_fd, sizeof(source_fd));
  if (sendmsg(sockets[0], &message, 0) != 1)
    goto out;

  memset(control, 0, sizeof(control));
  errno = 0;
  if (recvmsg(sockets[1], &message, 0) == -1 && errno == EACCES)
    result = 0;

out:
  close(sockets[0]);
  close(sockets[1]);
  return result;
}

int main(int argc, char **argv)
{
  int source_fd;
  int unrelated_fd;
  void *mapping;
  char byte;

  if (argc != 2)
    return 2;
  source_fd = open(argv[1], O_RDONLY);
  if (source_fd < 0 || pread(source_fd, &byte, 1, 0) != 1 ||
      invoke_loader("install", source_fd) != 0 ||
      invoke_loader("inspect", source_fd) != 0) {
    fprintf(stderr, "kernel-export-deny-probe: setup or readback failed\n");
    return 1;
  }

  errno = 0;
  if (pread(source_fd, &byte, 1, 0) != -1 || errno != EACCES)
    return 1;
  errno = 0;
  mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, source_fd, 0);
  if (mapping != MAP_FAILED || errno != EACCES)
    return 1;
  if (deny_existing_fd_in_child(source_fd) != 0 ||
      deny_scm_rights(source_fd) != 0)
    return 1;

  unrelated_fd = open("/etc/os-release", O_RDONLY);
  if (unrelated_fd < 0 || read(unrelated_fd, &byte, 1) != 1)
    return 1;
  close(unrelated_fd);
  close(source_fd);
  return 0;
}
