/* SPDX-License-Identifier: Apache-2.0 */
#include "helper.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define PIDFD_GET_INFO 0xc048ff0b
#define PIDFD_INFO_PID (1ULL << 0)

struct aos_pidfd_info {
  uint64_t mask;
  uint64_t cgroup_id;
  uint32_t pid;
  uint32_t tgid;
  uint32_t ppid;
  uint32_t ruid;
  uint32_t rgid;
  uint32_t euid;
  uint32_t egid;
  uint32_t suid;
  uint32_t sgid;
  uint32_t fsuid;
  uint32_t fsgid;
  int32_t exit_code;
  uint32_t coredump_mask;
  uint32_t spare;
};

static int fail(const char *message)
{
  fprintf(stderr, "aos-namespace-inspector-manager-query: %s\n", message);
  return -1;
}

static int set_cloexec(int fd)
{
  int flags = fcntl(fd, F_GETFD);

  if (flags < 0 || (flags & FD_CLOEXEC) != 0)
    return fail("inherited descriptor CLOEXEC contract is invalid");
  if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
    return fail("cannot protect inherited descriptor");
  return 0;
}

static int socket_contract(int fd, int expected_type, bool nonblocking)
{
  struct sockaddr_storage peer;
  socklen_t peer_length = sizeof(peer);
  int type = 0;
  int domain = 0;
  socklen_t type_length = sizeof(type);
  socklen_t domain_length = sizeof(domain);
  int status_flags;

  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) != 0 ||
      type != expected_type ||
      getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_length) != 0 ||
      domain != AF_UNIX || getpeername(fd, (struct sockaddr *)&peer,
                                           &peer_length) != 0)
    return -1;

  status_flags = fcntl(fd, F_GETFL);
  if (status_flags < 0 || ((status_flags & O_NONBLOCK) != 0) != nonblocking)
    return -1;
  return 0;
}

static int validate_manager_peer(void)
{
  struct ucred credentials;
  socklen_t length = sizeof(credentials);

  if (getsockopt(AOS_QUERY_MANAGER_FD, SOL_SOCKET, SO_PEERCRED, &credentials,
                 &length) != 0 || length != sizeof(credentials) ||
      credentials.pid != 1 || credentials.uid != 0 || credentials.gid != 0)
    return -1;
  return 0;
}

static int task_count(void)
{
  DIR *directory = opendir("/proc/self/task");
  struct dirent *entry;
  unsigned int count = 0;

  if (directory == NULL)
    return -1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    char *end = NULL;

    if (entry->d_name[0] == '.')
      continue;
    errno = 0;
    (void)strtoul(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0') {
      closedir(directory);
      return -1;
    }
    count++;
  }
  if (errno != 0 || closedir(directory) != 0)
    return -1;
  return count == 1 ? 0 : -1;
}

int aos_query_capture_fd_table(uint32_t *mask)
{
  DIR *directory = opendir("/proc/self/fd");
  struct dirent *entry;
  int directory_fd;
  uint32_t found = 0;

  if (directory == NULL)
    return -1;
  directory_fd = dirfd(directory);
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    char *end = NULL;
    unsigned long descriptor;

    if (entry->d_name[0] == '.')
      continue;
    errno = 0;
    descriptor = strtoul(entry->d_name, &end, 10);
    if (errno != 0 || end == entry->d_name || *end != '\0' ||
        descriptor > INT32_MAX) {
      closedir(directory);
      return -1;
    }
    if ((int)descriptor == directory_fd)
      continue;
    if (descriptor >= AOS_QUERY_FD_LIMIT) {
      closedir(directory);
      return -1;
    }
    found |= UINT32_C(1) << descriptor;
  }
  if (errno != 0 || closedir(directory) != 0)
    return -1;
  *mask = found;
  return 0;
}

static int validate_standard_descriptors(void)
{
  struct stat actual;
  struct stat null_device;
  int access_mode;

  if (fstat(AOS_QUERY_MANAGER_FD, &actual) != 0)
    return -1;

  if (fstat(0, &actual) != 0 || stat("/dev/null", &null_device) != 0 ||
      !S_ISCHR(actual.st_mode) || actual.st_rdev != null_device.st_rdev)
    return -1;
  access_mode = fcntl(0, F_GETFL);
  if (access_mode < 0 || (access_mode & O_ACCMODE) != O_RDONLY)
    return -1;

  for (int fd = 1; fd <= 2; fd++) {
    if (fstat(fd, &actual) != 0 || !S_ISFIFO(actual.st_mode))
      return -1;
    access_mode = fcntl(fd, F_GETFL);
    if (access_mode < 0 || (access_mode & O_ACCMODE) != O_WRONLY)
      return -1;
  }
  return 0;
}

static int validate_execution_descriptor(void)
{
  struct stat descriptor;
  struct stat running;
  int descriptor_flags;
  int status_flags;

  descriptor_flags = fcntl(AOS_QUERY_EXECUTABLE_FD, F_GETFD);
  status_flags = fcntl(AOS_QUERY_EXECUTABLE_FD, F_GETFL);
  if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) != 0 ||
      status_flags < 0 || (status_flags & O_ACCMODE) != O_RDONLY ||
      fstat(AOS_QUERY_EXECUTABLE_FD, &descriptor) != 0 ||
      stat("/proc/self/exe", &running) != 0 || !S_ISREG(descriptor.st_mode) ||
      descriptor.st_dev != running.st_dev || descriptor.st_ino != running.st_ino)
    return -1;
  if (close(AOS_QUERY_EXECUTABLE_FD) != 0)
    return -1;
  return 0;
}

static int validate_parent(struct aos_query_context *context)
{
  struct aos_pidfd_info info = {.mask = PIDFD_INFO_PID};
  struct stat status;
  struct ucred credentials;
  socklen_t length = sizeof(credentials);

  if (ioctl(AOS_QUERY_PARENT_PIDFD, PIDFD_GET_INFO, &info) != 0 ||
      (info.mask & PIDFD_INFO_PID) == 0 || info.pid != (uint32_t)getppid() ||
      info.euid != 0 || fstat(AOS_QUERY_PARENT_PIDFD, &status) != 0)
    return -1;
  if (getsockopt(AOS_QUERY_CONTROL_FD, SOL_SOCKET, SO_PEERCRED, &credentials,
                 &length) != 0 || length != sizeof(credentials) ||
      credentials.pid != getppid() || credentials.uid != 0 ||
      credentials.gid != 0)
    return -1;

  context->parent.pid = credentials.pid;
  context->parent.uid = credentials.uid;
  context->parent.gid = credentials.gid;
  context->parent.pidfd_inode = status.st_ino;
  return 0;
}

static int validate_process_state(void)
{
  struct __user_cap_header_struct header = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
  };
  struct __user_cap_data_struct data[2] = {0};

  int dumpable = prctl(PR_GET_DUMPABLE);
  int no_new_privileges = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);

  /* The descriptor-backed launcher must remove active authority before the
   * ELF interpreter runs. Locked root semantics prevent exec from recreating
   * a permitted set merely because this helper retains UID 0. */
  if (dumpable != 0 && prctl(PR_SET_DUMPABLE, 0) == 0)
    dumpable = prctl(PR_GET_DUMPABLE);
  if (dumpable != 0 || no_new_privileges != 1 ||
      prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) !=
          (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
           SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED)) {
    fprintf(stderr, "aos-namespace-inspector-manager-query: process flags %d/%d\n",
            dumpable, no_new_privileges);
    return -1;
  }
  if (syscall(SYS_capget, &header, data) != 0) {
    perror("aos-namespace-inspector-manager-query: capget");
    return -1;
  }
  for (size_t index = 0; index < 2; index++) {
    if (data[index].effective != 0 || data[index].permitted != 0 ||
        data[index].inheritable != 0) {
      fprintf(stderr, "aos-namespace-inspector-manager-query: capability word %zu %x/%x/%x\n",
              index, data[index].effective, data[index].permitted,
              data[index].inheritable);
      return -1;
    }
  }
  for (int capability = 0; capability <= 63; capability++) {
    int bounding = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
    int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);

    if (bounding < 0 || ambient < 0) {
      if (errno == EINVAL && capability > 40)
        break;
      return -1;
    }
    if (bounding != (capability == CAP_SYS_PTRACE ? 1 : 0) || ambient != 0)
      return -1;
  }
  if (task_count() != 0) {
    perror("aos-namespace-inspector-manager-query: task inventory");
    return -1;
  }
  return 0;
}

int aos_query_validate_entry(struct aos_query_context *context)
{
  uint32_t descriptors;
  int enabled;
  socklen_t length = sizeof(enabled);

  if (validate_execution_descriptor() != 0)
    return fail("entry executable descriptor is invalid");
  if (aos_query_capture_fd_table(&descriptors) != 0 || descriptors != 0x3fU)
    return fail("entry descriptor table is not exactly 0 through 5");
  if (validate_standard_descriptors() != 0 ||
      socket_contract(AOS_QUERY_MANAGER_FD, SOCK_STREAM, false) != 0 ||
      socket_contract(AOS_QUERY_CONTROL_FD, SOCK_SEQPACKET, true) != 0 ||
      validate_manager_peer() != 0)
    return fail("entry descriptor shape is invalid");
  if (getsockopt(AOS_QUERY_CONTROL_FD, SOL_SOCKET, SO_PASSCRED, &enabled,
                 &length) != 0 || enabled != 1)
    return fail("control socket does not pass credentials");
  length = sizeof(enabled);
  if (getsockopt(AOS_QUERY_CONTROL_FD, SOL_SOCKET, SO_PASSPIDFD, &enabled,
                 &length) != 0 || enabled != 1)
    return fail("control socket does not pass pidfds");
  if (validate_parent(context) != 0)
    return fail("entry parent authority is invalid");
  if (validate_process_state() != 0)
    return fail("entry process state is invalid");
  for (int fd = AOS_QUERY_MANAGER_FD; fd <= AOS_QUERY_CONTROL_FD; fd++) {
    if (set_cloexec(fd) != 0)
      return -1;
  }
  return 0;
}

int aos_query_set_runtime_limits(void)
{
  static const struct {
    int resource;
    rlim_t value;
  } limits[] = {
      {RLIMIT_CORE, 0},
      {RLIMIT_FSIZE, 0},
      {RLIMIT_NOFILE, AOS_QUERY_FD_LIMIT},
      {RLIMIT_AS, 128U * 1024U * 1024U},
  };

  for (size_t index = 0; index < sizeof(limits) / sizeof(limits[0]); index++) {
    struct rlimit inherited;
    struct rlimit requested = {
        .rlim_cur = limits[index].value,
        .rlim_max = limits[index].value,
    };

    if (getrlimit(limits[index].resource, &inherited) != 0 ||
        inherited.rlim_max < requested.rlim_max ||
        setrlimit(limits[index].resource, &requested) != 0)
      return fail("cannot establish exact runtime limits");
    if (getrlimit(limits[index].resource, &inherited) != 0 ||
        inherited.rlim_cur != requested.rlim_cur ||
        inherited.rlim_max != requested.rlim_max)
      return fail("runtime limit verification failed");
  }
  return 0;
}

int aos_query_fill_fd_table(int fillers[AOS_QUERY_FD_LIMIT], size_t *count,
                            uint32_t *prefill_mask)
{
  uint32_t before;
  uint32_t occupied;
  size_t used = 0;
  int probe;

  if (aos_query_capture_fd_table(&before) != 0)
    return -1;
  while (used < AOS_QUERY_FD_LIMIT) {
    int fd = fcntl(0, F_DUPFD_CLOEXEC, 0);

    if (fd < 0) {
      if (errno == EMFILE)
        break;
      goto fail;
    }
    if (fd >= AOS_QUERY_FD_LIMIT) {
      close(fd);
      goto fail;
    }
    fillers[used++] = fd;
  }
  probe = fcntl(0, F_DUPFD_CLOEXEC, 0);
  if (probe >= 0) {
    close(probe);
    goto fail;
  }
  if (used == AOS_QUERY_FD_LIMIT || errno != EMFILE)
    goto fail;

  occupied = before;
  for (size_t index = 0; index < used; index++)
    occupied |= UINT32_C(1) << fillers[index];
  if (occupied != UINT32_MAX)
    goto fail;

  *count = used;
  *prefill_mask = before;
  return 0;

fail:
  for (size_t index = 0; index < used; index++)
    close(fillers[index]);
  return -1;
}

int aos_query_release_fd_table(const int fillers[AOS_QUERY_FD_LIMIT],
                               size_t count, uint32_t expected_mask)
{
  int result = 0;
  uint32_t after;

  for (size_t index = 0; index < count; index++) {
    if (close(fillers[index]) != 0)
      result = -1;
  }
  if (aos_query_capture_fd_table(&after) != 0 || after != expected_mask)
    result = -1;
  return result;
}
