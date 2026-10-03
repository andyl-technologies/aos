// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef AOS_KERNEL_EXPORT_DENY_LOADER
#error "AOS_KERNEL_EXPORT_DENY_LOADER must name the built loader"
#endif

static int owner_action(const char *action, int source_fd,
                        int cgroup_fd, const char *ttl_ms)
{
  char source_text[32];
  char cgroup_text[32];
  pid_t child;
  int status;

  snprintf(source_text, sizeof(source_text), "%d", source_fd);
  snprintf(cgroup_text, sizeof(cgroup_text), "%d", cgroup_fd);
  child = fork();
  if (child == 0) {
    if (ttl_ms != NULL)
      execl(AOS_KERNEL_EXPORT_DENY_LOADER, AOS_KERNEL_EXPORT_DENY_LOADER,
            action, source_text, cgroup_text, ttl_ms, (char *)NULL);
    else if (cgroup_fd >= 0)
      execl(AOS_KERNEL_EXPORT_DENY_LOADER, AOS_KERNEL_EXPORT_DENY_LOADER,
            action, source_text, cgroup_text, (char *)NULL);
    else
      execl(AOS_KERNEL_EXPORT_DENY_LOADER, AOS_KERNEL_EXPORT_DENY_LOADER,
            action, source_text, (char *)NULL);
    _exit(127);
  }
  return child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int move_to_cgroup(const char *directory)
{
  char path[256];
  char pid_text[32];
  int fd;
  int length;
  int result;

  if (snprintf(path, sizeof(path), "%s/cgroup.procs", directory) >=
      (int)sizeof(path))
    return -1;
  fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  length = snprintf(pid_text, sizeof(pid_text), "%ld", (long)getpid());
  result = write(fd, pid_text, (size_t)length) == length ? 0 : -1;
  close(fd);
  return result;
}

static int denied_read(int source_fd)
{
  char byte;

  errno = 0;
  return pread(source_fd, &byte, 1, 0) == -1 && errno == EACCES ? 0 : -1;
}

static int denied_open(const char *path)
{
  int fd;

  errno = 0;
  fd = open(path, O_RDONLY);
  if (fd >= 0)
    close(fd);
  return fd < 0 && errno == EACCES ? 0 : -1;
}

static int denied_scm_receive(int socket_fd)
{
  char byte;
  char control[CMSG_SPACE(sizeof(int))] = {0};
  struct iovec io = {.iov_base = &byte, .iov_len = 1};
  struct msghdr message = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  struct cmsghdr *header;
  ssize_t received = recvmsg(socket_fd, &message, 0);

  header = CMSG_FIRSTHDR(&message);
  /* Linux drops a denied FD and reports truncated ancillary data. */
  return received == 1 && (message.msg_flags & MSG_CTRUNC) != 0 &&
         (header == NULL || header->cmsg_len < CMSG_LEN(sizeof(int))) ? 0 : -1;
}

static int send_source_fd(int socket_fd, int source_fd)
{
  char byte = 'x';
  char control[CMSG_SPACE(sizeof(source_fd))] = {0};
  struct iovec io = {.iov_base = &byte, .iov_len = 1};
  struct msghdr message = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);

  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(source_fd));
  memcpy(CMSG_DATA(header), &source_fd, sizeof(source_fd));
  return sendmsg(socket_fd, &message, 0) == 1 ? 0 : -1;
}

static int denied_outside_cgroup(const char *directory, const char *path,
                                 int source_fd)
{
  int sockets[2];
  pid_t child;
  int status;

  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0)
    return -1;
  child = fork();
  if (child == 0) {
    close(sockets[0]);
    if (move_to_cgroup(directory) != 0 || denied_read(source_fd) != 0 ||
        denied_open(path) != 0 || denied_scm_receive(sockets[1]) != 0)
      _exit(1);
    _exit(0);
  }
  close(sockets[1]);
  if (child < 0 || send_source_fd(sockets[0], source_fd) != 0 ||
      waitpid(child, &status, 0) != child ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "kernel-export-grant-probe: outside cgroup access survived\n");
    close(sockets[0]);
    return -1;
  }
  close(sockets[0]);
  return 0;
}

int main(int argc, char **argv)
{
  char allowed_path[160];
  char outside_path[160];
  char byte;
  int source_fd;
  int allowed_fd;
  int opened_fd;
  int unrelated_fd;
  int write_fd;
  void *mapping;

  if (argc != 2)
    return 2;
  if (snprintf(allowed_path, sizeof(allowed_path),
               "/sys/fs/cgroup/kernel-export-allowed-%ld", (long)getpid()) >=
          (int)sizeof(allowed_path) ||
      snprintf(outside_path, sizeof(outside_path),
               "/sys/fs/cgroup/kernel-export-outside-%ld", (long)getpid()) >=
          (int)sizeof(outside_path) ||
      mkdir(allowed_path, 0700) != 0 || mkdir(outside_path, 0700) != 0) {
    perror("kernel-export-grant-probe: cgroup setup");
    return 1;
  }
  allowed_fd = open(allowed_path, O_PATH | O_DIRECTORY);
  source_fd = open(argv[1], O_RDONLY);
  if (allowed_fd < 0 || source_fd < 0 ||
      pread(source_fd, &byte, 1, 0) != 1 ||
      owner_action("install", source_fd, -1, NULL) != 0 ||
      owner_action("inspect", source_fd, -1, NULL) != 0) {
    fprintf(stderr, "kernel-export-grant-probe: install/readback failed\n");
    return 1;
  }

  if (denied_read(source_fd) != 0 || denied_open(argv[1]) != 0 ||
      owner_action("grant", source_fd, allowed_fd, "5000") != 0 ||
      denied_read(source_fd) != 0) {
    fprintf(stderr, "kernel-export-grant-probe: default or out-of-scope denial failed\n");
    return 1;
  }
  if (move_to_cgroup(allowed_path) != 0 ||
      pread(source_fd, &byte, 1, 0) != 1) {
    fprintf(stderr, "kernel-export-grant-probe: allowed retained read failed: %s\n",
            strerror(errno));
    return 1;
  }
  opened_fd = open(argv[1], O_RDONLY);
  mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, source_fd, 0);
  errno = 0;
  write_fd = open(argv[1], O_WRONLY);
  if (opened_fd < 0 || mapping == MAP_FAILED ||
      write_fd >= 0 || errno != EACCES ||
      mprotect(mapping, 4096, PROT_READ | PROT_WRITE) != -1 ||
      errno != EACCES ||
      denied_outside_cgroup(outside_path, argv[1], source_fd) != 0) {
    fprintf(stderr, "kernel-export-grant-probe: current use or transfer scope failed\n");
    return 1;
  }

  sleep(6);
  if (denied_read(source_fd) != 0 || denied_open(argv[1]) != 0 ||
      owner_action("grant", source_fd, allowed_fd, "5000") != 0 ||
      pread(source_fd, &byte, 1, 0) != 1 ||
      owner_action("revoke", source_fd, allowed_fd, NULL) != 0 ||
      denied_read(source_fd) != 0 || denied_open(argv[1]) != 0) {
    fprintf(stderr, "kernel-export-grant-probe: expiry, renewal, or revocation failed\n");
    return 1;
  }
  if (owner_action("inspect", source_fd, -1, NULL) != 0 ||
      owner_action("grant", source_fd, allowed_fd, "0") == 0 ||
      owner_action("install", source_fd, -1, NULL) == 0) {
    fprintf(stderr, "kernel-export-grant-probe: owner readback or invalid action failed\n");
    return 1;
  }
  unrelated_fd = open("/etc/os-release", O_RDONLY);
  if (unrelated_fd < 0 || read(unrelated_fd, &byte, 1) != 1) {
    fprintf(stderr, "kernel-export-grant-probe: unrelated mount became inaccessible\n");
    return 1;
  }
  munmap(mapping, 4096);
  close(unrelated_fd);
  close(opened_fd);
  close(allowed_fd);
  close(source_fd);
  return 0;
}
