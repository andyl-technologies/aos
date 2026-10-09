/* SPDX-License-Identifier: Apache-2.0 */
/* The broker build requires an empty bounding set. The separately compiled
 * inspector worker mode uses the same PID 1 transaction with the inspector's
 * exact CAP_SYS_PTRACE bounding set and a worker pidfd at FD 6. */
#include "helper.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AOS_BROKER_QUERY_PROGRAM
#error "AOS_BROKER_QUERY_PROGRAM must name the installed broker helper"
#endif

#define BROKER_TARGET_FD 6
#define BROKER_EXECUTABLE_FD 7
#define BROKER_MAGIC "AOSNIBQ3"
#define BROKER_VERSION 3U
#define BROKER_MAX_RECORD 8192U
#define BROKER_MAX_UNIT 192U
#define BROKER_MAX_PATH 512U
#define BROKER_MAX_CGROUP 512U
#define BROKER_MAX_ARGUMENTS 8U
#ifdef AOS_INSPECTOR_WORKER_MODE
#define BROKER_EXPECTED_BOUNDING(capability) ((capability) == CAP_SYS_PTRACE)
#else
#define BROKER_EXPECTED_BOUNDING(capability) 0
#endif
#define PIDFD_GET_INFO 0xc048ff0b
#define PIDFD_INFO_PID (1ULL << 0)
#define PIDFD_INFO_CREDS (1ULL << 1)
#define PIDFD_INFO_CGROUP (1ULL << 2)
#define PIDFD_INFO_ALL (PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_CGROUP)

enum broker_phase {
  BROKER_START = 1,
  BROKER_SNAPSHOT_A = 2,
  BROKER_CONTINUE = 3,
  BROKER_SNAPSHOT_B = 4,
  BROKER_ACK = 5,
};

struct broker_pidfd_info {
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

struct broker_query {
  struct aos_query_context shared;
  struct broker_pidfd_info subject;
  uint8_t nonce[32];
  uint64_t subject_inode;
  uint8_t role;
  char unit[BROKER_MAX_UNIT + 1U];
  char executable[BROKER_MAX_PATH + 1U];
  char unit_path[512];
};

struct broker_snapshot {
  uint8_t invocation[16];
  uint32_t main_pid;
  uint64_t cgroup_id;
  char cgroup[BROKER_MAX_CGROUP + 1U];
  char fragment[BROKER_MAX_PATH + 1U];
  char executable[BROKER_MAX_PATH + 1U];
  char arguments[BROKER_MAX_ARGUMENTS][BROKER_MAX_PATH + 1U];
  uint8_t argument_count;
};

struct broker_reply {
  sd_bus_message *message;
  int failed;
  bool complete;
};

extern char **environ;

static uint16_t load_u16(const uint8_t *bytes)
{
  return (uint16_t)((uint16_t)bytes[0] << 8U | bytes[1]);
}

static uint32_t load_u32(const uint8_t *bytes)
{
  return (uint32_t)bytes[0] << 24U | (uint32_t)bytes[1] << 16U |
         (uint32_t)bytes[2] << 8U | bytes[3];
}

static uint64_t load_u64(const uint8_t *bytes)
{
  uint64_t value = 0;
  for (size_t index = 0; index < 8; index++)
    value = value << 8U | bytes[index];
  return value;
}

static void store_u16(uint8_t *bytes, uint16_t value)
{
  bytes[0] = (uint8_t)(value >> 8U);
  bytes[1] = (uint8_t)value;
}

static int now_ns(uint64_t *value)
{
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
    return -1;
  *value = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
           (uint64_t)now.tv_nsec;
  return 0;
}

static int remaining_usec(const struct broker_query *query, uint64_t *value)
{
  uint64_t now;
  uint64_t deadline = (uint64_t)query->shared.deadline.tv_sec *
                          UINT64_C(1000000000) +
                      (uint64_t)query->shared.deadline.tv_nsec;
  if (now_ns(&now) != 0 || now >= deadline || deadline - now < 1000U)
    return -1;
  *value = (deadline - now + 999U) / 1000U;
  return 0;
}

static int poll_fd(const struct broker_query *query, int fd, short events)
{
  struct pollfd item = {.fd = fd, .events = events};
  uint64_t remaining;
  if (remaining_usec(query, &remaining) != 0 ||
      ppoll(&item, 1,
            &(struct timespec){.tv_sec = (time_t)(remaining / 1000000U),
                               .tv_nsec = (long)(remaining % 1000000U) * 1000L},
            NULL) != 1)
    return -1;
  return (item.revents & events) != 0 ? 0 : -1;
}

static int copy_text(char *target, size_t capacity, const uint8_t *source,
                     size_t length)
{
  if (length == 0 || length >= capacity || memchr(source, 0, length) != NULL)
    return -1;
  memcpy(target, source, length);
  target[length] = '\0';
  return 0;
}

static int exact_text(char *target, size_t capacity, const char *source)
{
  size_t length;
  if (source == NULL ||
      (length = strnlen(source, capacity)) == 0 || length >= capacity)
    return -1;
  memcpy(target, source, length + 1U);
  return 0;
}

static void close_received_fds(struct msghdr *message)
{
  const uint8_t *control_end =
      (uint8_t *)message->msg_control + message->msg_controllen;

  for (struct cmsghdr *item = CMSG_FIRSTHDR(message); item != NULL;
       item = CMSG_NXTHDR(message, item)) {
    const uint8_t *data = CMSG_DATA(item);
    if (item->cmsg_level != SOL_SOCKET ||
        (item->cmsg_type != AOS_SCM_PIDFD && item->cmsg_type != SCM_RIGHTS) ||
        item->cmsg_len < CMSG_LEN(0))
      continue;
    size_t length = item->cmsg_len - CMSG_LEN(0);
    if (data > control_end)
      continue;
    if (length > (size_t)(control_end - data))
      length = (size_t)(control_end - data);
    for (size_t offset = 0; offset + sizeof(int) <= length;
         offset += sizeof(int)) {
      int descriptor;
      memcpy(&descriptor, data + offset, sizeof(descriptor));
      if (descriptor >= 0)
        close(descriptor);
    }
  }
}

static int receive_control(struct broker_query *query, enum broker_phase phase,
                           uint8_t record[BROKER_MAX_RECORD], size_t *size)
{
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
  } ancillary;
  struct iovec iov = {.iov_base = record, .iov_len = BROKER_MAX_RECORD};
  struct msghdr message = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = ancillary.bytes,
      .msg_controllen = sizeof(ancillary.bytes),
  };
  struct ucred sender = {0};
  bool credentials = false;
  bool pidfd_seen = false;
  ssize_t received;
  int result = -1;

  for (;;) {
    message.msg_controllen = sizeof(ancillary.bytes);
    message.msg_flags = 0;
    received = recvmsg(AOS_QUERY_CONTROL_FD, &message,
                       MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (received >= 0)
      break;
    if ((errno != EAGAIN && errno != EWOULDBLOCK) ||
        poll_fd(query, AOS_QUERY_CONTROL_FD, POLLIN) != 0)
      return -1;
  }
  if (received < 16 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
    goto out;
  for (struct cmsghdr *item = CMSG_FIRSTHDR(&message); item != NULL;
       item = CMSG_NXTHDR(&message, item)) {
    if (item->cmsg_level != SOL_SOCKET)
      goto out;
    if (item->cmsg_type == SCM_CREDENTIALS &&
        item->cmsg_len == CMSG_LEN(sizeof(sender)) && !credentials) {
      memcpy(&sender, CMSG_DATA(item), sizeof(sender));
      credentials = true;
    } else if (item->cmsg_type == AOS_SCM_PIDFD &&
               item->cmsg_len == CMSG_LEN(sizeof(int)) && !pidfd_seen) {
      struct broker_pidfd_info info = {.mask = PIDFD_INFO_ALL};
      struct stat status;
      int descriptor;
      memcpy(&descriptor, CMSG_DATA(item), sizeof(descriptor));
      if (ioctl(descriptor, PIDFD_GET_INFO, &info) != 0 ||
          (info.mask & PIDFD_INFO_ALL) != PIDFD_INFO_ALL ||
          info.pid != (uint32_t)query->shared.parent.pid ||
          fstat(descriptor, &status) != 0 ||
          status.st_ino != query->shared.parent.pidfd_inode)
        goto out;
      pidfd_seen = true;
    } else {
      goto out;
    }
  }
  if (!credentials || !pidfd_seen ||
      sender.pid != query->shared.parent.pid || sender.uid != 0 ||
      sender.gid != 0 || memcmp(record, BROKER_MAGIC, 8) != 0 ||
      load_u16(record + 8) != BROKER_VERSION ||
      load_u16(record + 10) != phase ||
      load_u32(record + 12) != (uint32_t)received - 16U)
    goto out;
  *size = (size_t)received - 16U;
  memmove(record, record + 16, *size);
  if (recv(AOS_QUERY_CONTROL_FD, &(uint8_t){0}, 1,
           MSG_PEEK | MSG_DONTWAIT) >= 0 ||
      (errno != EAGAIN && errno != EWOULDBLOCK))
    goto out;
  result = 0;
out:
  close_received_fds(&message);
  return result;
}

static int send_control(struct broker_query *query, enum broker_phase phase,
                        const uint8_t *payload, size_t size)
{
  uint8_t record[BROKER_MAX_RECORD];
  ssize_t written;
  if (size > sizeof(record) - 16U)
    return -1;
  memcpy(record, BROKER_MAGIC, 8);
  store_u16(record + 8, BROKER_VERSION);
  store_u16(record + 10, (uint16_t)phase);
  record[12] = (uint8_t)(size >> 24U);
  record[13] = (uint8_t)(size >> 16U);
  record[14] = (uint8_t)(size >> 8U);
  record[15] = (uint8_t)size;
  memcpy(record + 16, payload, size);
  for (;;) {
    written = send(AOS_QUERY_CONTROL_FD, record, size + 16U,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
    if (written == (ssize_t)(size + 16U))
      return 0;
    if (written >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
        poll_fd(query, AOS_QUERY_CONTROL_FD, POLLOUT) != 0)
      return -1;
  }
}

static int decode_start(struct broker_query *query, const uint8_t *bytes,
                        size_t size)
{
  uint64_t now;
  uint64_t deadline;
  uint16_t unit_length;
  uint16_t executable_length;
  struct stat status;
  const char *prefix;
  size_t prefix_length;
  bool nonce_nonzero = false;

  if (size < 66U)
    return -1;
  memcpy(query->nonce, bytes, 32);
  for (size_t index = 0; index < 32; index++)
    nonce_nonzero |= query->nonce[index] != 0;
  deadline = load_u64(bytes + 32);
  query->subject_inode = load_u64(bytes + 44);
  query->subject.mask = PIDFD_INFO_ALL;
  query->role = bytes[60];
  unit_length = load_u16(bytes + 62);
  executable_length = load_u16(bytes + 64);
  if (!nonce_nonzero || now_ns(&now) != 0 || deadline <= now ||
      deadline - now > UINT64_C(2000000000) ||
      (query->role != 1 && query->role != 2) || bytes[61] != 0 ||
      size != 66U + unit_length + executable_length ||
      copy_text(query->unit, sizeof(query->unit), bytes + 66, unit_length) != 0 ||
      copy_text(query->executable, sizeof(query->executable),
                bytes + 66 + unit_length, executable_length) != 0 ||
      strncmp(query->executable, "/nix/store/", 11) != 0 ||
      ioctl(BROKER_TARGET_FD, PIDFD_GET_INFO, &query->subject) != 0 ||
      (query->subject.mask & PIDFD_INFO_ALL) != PIDFD_INFO_ALL ||
      query->subject.pid != load_u32(bytes + 40) ||
      query->subject.pid != query->subject.tgid ||
      query->subject.pid == (uint32_t)query->shared.parent.pid ||
      query->subject.euid != 0 || query->subject.cgroup_id == 0 ||
      query->subject.cgroup_id != load_u64(bytes + 52) ||
      fstat(BROKER_TARGET_FD, &status) != 0 ||
      status.st_ino != query->subject_inode)
    return -1;
  prefix = query->role == 1
               ? "aos-sandbox-network-namespace-inspector@"
               : "aos-sandbox-network-lifecycle-worker@";
  prefix_length = strlen(prefix);
  if (strncmp(query->unit, prefix, prefix_length) != 0 ||
      strlen(query->unit) <= prefix_length + strlen(".service") ||
      strcmp(query->unit + strlen(query->unit) - strlen(".service"),
             ".service") != 0)
    return -1;
  query->shared.deadline.tv_sec = (time_t)(deadline / UINT64_C(1000000000));
  query->shared.deadline.tv_nsec = (long)(deadline % UINT64_C(1000000000));
  return 0;
}

static int validate_entry(struct broker_query *query)
{
  struct broker_pidfd_info parent = {.mask = PIDFD_INFO_ALL};
  struct __user_cap_header_struct header = {
      .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
  struct __user_cap_data_struct capabilities[2] = {0};
  struct ucred peer;
  struct stat status;
  struct stat running;
  struct stat null_device;
  const int socket_fds[] = {AOS_QUERY_MANAGER_FD, AOS_QUERY_CONTROL_FD};
  const int socket_options[] = {SO_PASSCRED, SO_PASSPIDFD};
  socklen_t length;
  uint32_t table;
  int type;
  int domain;
  int enabled;

  if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0 ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
      prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) !=
          (SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
           SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED) ||
      syscall(SYS_capget, &header, capabilities) != 0)
    return -1;
  for (size_t index = 0; index < 2; index++) {
    if (capabilities[index].effective != 0 ||
        capabilities[index].permitted != 0 ||
        capabilities[index].inheritable != 0)
      return -1;
  }
  for (int capability = 0; capability <= 63; capability++) {
    int bounding = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
    int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
                        capability, 0, 0);
    if (bounding < 0 || ambient < 0) {
      if (errno == EINVAL && capability > 40)
        break;
      return -1;
    }
    if (bounding != BROKER_EXPECTED_BOUNDING(capability) || ambient != 0)
      return -1;
  }
  if (prctl(PR_GET_DUMPABLE) != 0 && prctl(PR_SET_DUMPABLE, 0) != 0)
    return -1;
  if (prctl(PR_GET_DUMPABLE) != 0 ||
      fstat(BROKER_EXECUTABLE_FD, &status) != 0 ||
      stat("/proc/self/exe", &running) != 0 ||
      !S_ISREG(status.st_mode) || status.st_dev != running.st_dev ||
      status.st_ino != running.st_ino ||
      (fcntl(BROKER_EXECUTABLE_FD, F_GETFL) & O_ACCMODE) != O_RDONLY ||
      (fcntl(BROKER_EXECUTABLE_FD, F_GETFD) & FD_CLOEXEC) != 0 ||
      close(BROKER_EXECUTABLE_FD) != 0 ||
      aos_query_capture_fd_table(&table) != 0 || table != 0x7fU ||
      fstat(0, &status) != 0 || stat("/dev/null", &null_device) != 0 ||
      !S_ISCHR(status.st_mode) || status.st_rdev != null_device.st_rdev)
    return -1;
  for (int fd = 1; fd <= 2; fd++) {
    if (fstat(fd, &status) != 0 || !S_ISFIFO(status.st_mode) ||
        (fcntl(fd, F_GETFL) & O_ACCMODE) != O_WRONLY)
      return -1;
  }
  for (size_t index = 0; index < 2; index++) {
    int fd = socket_fds[index];
    int flags = fcntl(fd, F_GETFL);
    struct sockaddr_storage address;
    socklen_t address_length = sizeof(address);
    length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0 ||
        type != (fd == AOS_QUERY_MANAGER_FD ? SOCK_STREAM : SOCK_SEQPACKET))
      return -1;
    length = sizeof(domain);
    if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &domain, &length) != 0 ||
        domain != AF_UNIX || flags < 0 ||
        ((flags & O_NONBLOCK) != 0) != (fd == AOS_QUERY_CONTROL_FD) ||
        getpeername(fd, (struct sockaddr *)&address, &address_length) != 0)
      return -1;
  }
  length = sizeof(peer);
  if (getsockopt(AOS_QUERY_MANAGER_FD, SOL_SOCKET, SO_PEERCRED,
                 &peer, &length) != 0 || length != sizeof(peer) ||
      peer.pid != 1 || peer.uid != 0 || peer.gid != 0)
    return -1;
  length = sizeof(peer);
  if (getsockopt(AOS_QUERY_CONTROL_FD, SOL_SOCKET, SO_PEERCRED,
                 &peer, &length) != 0 || length != sizeof(peer) ||
      peer.pid != getppid() || peer.uid != 0 || peer.gid != 0)
    return -1;
  query->shared.parent.pid = peer.pid;
  query->shared.parent.uid = peer.uid;
  query->shared.parent.gid = peer.gid;
  if (ioctl(AOS_QUERY_PARENT_PIDFD, PIDFD_GET_INFO, &parent) != 0 ||
      (parent.mask & PIDFD_INFO_ALL) != PIDFD_INFO_ALL ||
      parent.pid != (uint32_t)peer.pid || parent.tgid != parent.pid ||
      parent.euid != 0 || fstat(AOS_QUERY_PARENT_PIDFD, &status) != 0)
    return -1;
  query->shared.parent.pidfd_inode = status.st_ino;
  for (size_t index = 0; index < 2; index++) {
    length = sizeof(enabled);
    if (getsockopt(AOS_QUERY_CONTROL_FD, SOL_SOCKET, socket_options[index],
                   &enabled, &length) != 0 || enabled != 1)
      return -1;
  }
  for (int fd = AOS_QUERY_MANAGER_FD; fd <= BROKER_TARGET_FD; fd++) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || (flags & FD_CLOEXEC) != 0 ||
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
      return -1;
  }
  if (fcntl(0, F_GETFL) < 0 || (fcntl(0, F_GETFL) & O_ACCMODE) != O_RDONLY)
    return -1;
  return 0;
}

static int encode_unit_path(const char *name, char *path, size_t capacity)
{
  static const char hex[] = "0123456789abcdef";
  int start = snprintf(path, capacity, "/org/freedesktop/systemd1/unit/");
  size_t offset;
  if (start < 0 || (size_t)start >= capacity)
    return -1;
  offset = (size_t)start;
  for (size_t index = 0; name[index] != '\0'; index++) {
    uint8_t byte = (uint8_t)name[index];
    if ((byte >= 'a' && byte <= 'z') ||
        (byte >= 'A' && byte <= 'Z') ||
        (byte >= '0' && byte <= '9')) {
      if (offset + 1U >= capacity)
        return -1;
      path[offset++] = (char)byte;
    } else {
      if (offset + 3U >= capacity)
        return -1;
      path[offset++] = '_';
      path[offset++] = hex[byte >> 4U];
      path[offset++] = hex[byte & 0x0fU];
    }
  }
  path[offset] = '\0';
  return 0;
}

static int bus_callback(sd_bus_message *message, void *userdata,
                        sd_bus_error *error)
{
  struct broker_reply *reply = userdata;
  (void)error;
  reply->message = sd_bus_message_ref(message);
  reply->failed = sd_bus_message_is_method_error(message, NULL);
  reply->complete = true;
  return 1;
}

static int bus_ready(struct broker_query *query)
{
  while (sd_bus_is_ready(query->shared.bus) == 0) {
    int processed = sd_bus_process(query->shared.bus, NULL);
    int events;
    if (processed < 0 || remaining_usec(query, &(uint64_t){0}) != 0)
      return -1;
    if (processed != 0)
      continue;
    events = sd_bus_get_events(query->shared.bus);
    if (events < 0 || poll_fd(query, AOS_QUERY_MANAGER_FD, (short)events) != 0)
      return -1;
  }
  return 0;
}

typedef int (*broker_decoder)(struct broker_query *, sd_bus_message *, void *);

static int bus_call(struct broker_query *query, sd_bus_message *request,
                    broker_decoder decoder, void *userdata)
{
  struct broker_reply reply = {0};
  int fillers[AOS_QUERY_FD_LIMIT];
  size_t filler_count = 0;
  uint32_t prefill_mask = 0;
  sd_bus_slot *slot = NULL;
  uint64_t remaining;
  int result = -1;
  bool filled = false;

  if (remaining_usec(query, &remaining) != 0)
    goto out;
  if (remaining > 100000U)
    remaining = 100000U;
  if (sd_bus_call_async(query->shared.bus, &slot, request,
                        bus_callback, &reply, remaining) < 0 ||
      aos_query_fill_fd_table(fillers, &filler_count, &prefill_mask) != 0)
    goto fatal;
  filled = true;
  while (!reply.complete) {
    int processed = sd_bus_process(query->shared.bus, NULL);
    int events;
    if (processed < 0 || remaining_usec(query, &remaining) != 0)
      goto fatal;
    if (processed != 0)
      continue;
    events = sd_bus_get_events(query->shared.bus);
    if (events < 0 || poll_fd(query, AOS_QUERY_MANAGER_FD, (short)events) != 0)
      goto fatal;
  }
  if (reply.failed || reply.message == NULL ||
      decoder(query, reply.message, userdata) != 0)
    goto fatal;
  if (aos_query_release_fd_table(fillers, filler_count, prefill_mask) != 0) {
    filled = false;
    goto fatal;
  }
  filled = false;
  result = 0;
  goto out;
fatal:
  if (query->shared.bus != NULL)
    sd_bus_close(query->shared.bus);
  if (filled)
    (void)aos_query_release_fd_table(fillers, filler_count, prefill_mask);
out:
  sd_bus_message_unref(reply.message);
  sd_bus_slot_unref(slot);
  sd_bus_message_unref(request);
  return result;
}

static int decode_unit(struct broker_query *query, sd_bus_message *message,
                       void *userdata)
{
  const char *path = NULL;
  const char *name = NULL;
  const void *invocation = NULL;
  size_t length = 0;
  struct broker_snapshot *snapshot = userdata;
  bool nonzero = false;
  if (sd_bus_message_read(message, "os", &path, &name) <= 0 ||
      sd_bus_message_read_array(message, SD_BUS_TYPE_BYTE,
                                &invocation, &length) <= 0 ||
      length != sizeof(snapshot->invocation) ||
      sd_bus_message_at_end(message, true) <= 0 ||
      strcmp(name, query->unit) != 0 || strcmp(path, query->unit_path) != 0)
    return -1;
  for (size_t index = 0; index < length; index++)
    nonzero |= ((const uint8_t *)invocation)[index] != 0;
  if (!nonzero)
    return -1;
  memcpy(snapshot->invocation, invocation, length);
  return 0;
}

enum broker_property {
  BROKER_MANAGER_ENVIRONMENT,
  BROKER_UNIT_ID,
  BROKER_INVOCATION,
  BROKER_FRAGMENT,
  BROKER_SOURCE_PATH,
  BROKER_DROP_IN_PATHS,
  BROKER_NEED_DAEMON_RELOAD,
  BROKER_TRANSIENT,
  BROKER_MAIN_PID,
  BROKER_CGROUP_ID,
  BROKER_CGROUP,
  BROKER_EXEC_START,
  BROKER_SERVICE_ENVIRONMENT,
  BROKER_ENVIRONMENT_FILES,
  BROKER_PASS_ENVIRONMENT,
  BROKER_PROPERTY_COUNT,
};

static const struct {
  const char *interface;
  const char *name;
  const char *signature;
} properties[BROKER_PROPERTY_COUNT] = {
    {"org.freedesktop.systemd1.Manager", "Environment", "as"},
    {"org.freedesktop.systemd1.Unit", "Id", "s"},
    {"org.freedesktop.systemd1.Unit", "InvocationID", "ay"},
    {"org.freedesktop.systemd1.Unit", "FragmentPath", "s"},
    {"org.freedesktop.systemd1.Unit", "SourcePath", "s"},
    {"org.freedesktop.systemd1.Unit", "DropInPaths", "as"},
    {"org.freedesktop.systemd1.Unit", "NeedDaemonReload", "b"},
    {"org.freedesktop.systemd1.Unit", "Transient", "b"},
    {"org.freedesktop.systemd1.Service", "MainPID", "u"},
    {"org.freedesktop.systemd1.Service", "ControlGroupId", "t"},
    {"org.freedesktop.systemd1.Service", "ControlGroup", "s"},
    {"org.freedesktop.systemd1.Service", "ExecStart", "a(sasbttttuii)"},
    {"org.freedesktop.systemd1.Service", "Environment", "as"},
    {"org.freedesktop.systemd1.Service", "EnvironmentFiles", "a(sb)"},
    {"org.freedesktop.systemd1.Service", "PassEnvironment", "as"},
};

static bool loader_environment_name(const char *assignment)
{
  static const char *const names[] = {
      "GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH", "NLSPATH",
      "BASH_ENV", "ENV", "NODE_OPTIONS", "NODE_PATH", "PERL5LIB",
      "PERLLIB", "PYTHONHOME", "PYTHONPATH", "RUBYLIB", "RUBYOPT",
  };
  const char *separator = strchr(assignment, '=');
  size_t length;

  if (separator == NULL || separator == assignment)
    return true;
  length = (size_t)(separator - assignment);
  if ((length >= 3U && strncmp(assignment, "LD_", 3U) == 0) ||
      (length >= 7U && strncmp(assignment, "MALLOC_", 7U) == 0) ||
      (length >= 18U &&
       strncmp(assignment, "LIBC_FATAL_STDERR_", 18U) == 0))
    return true;
  for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); index++) {
    if (strlen(names[index]) == length &&
        strncmp(assignment, names[index], length) == 0)
      return true;
  }
  return false;
}

static int decode_environment(sd_bus_message *message)
{
  const char *assignment;
  int item;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "s") <= 0)
    return -1;
  for (size_t count = 0; count < 256U; count++) {
    item = sd_bus_message_read(message, "s", &assignment);
    if (item < 0)
      return -1;
    if (item == 0)
      return sd_bus_message_exit_container(message) < 0 ? -1 : 0;
    /* PID 1 may report ordinary service variables, but no setting that could
     * redirect the loader or provide an unbounded environment record. */
    if (strnlen(assignment, 2049U) > 2048U ||
        loader_environment_name(assignment))
      return -1;
  }
  return -1;
}

static int decode_empty_array(sd_bus_message *message, const char *signature)
{
  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, signature) <= 0 ||
      sd_bus_message_at_end(message, false) <= 0 ||
      sd_bus_message_exit_container(message) < 0)
    return -1;
  return 0;
}

struct broker_property_decode {
  enum broker_property property;
  struct broker_snapshot *snapshot;
};

static int decode_exec_start(struct broker_query *query, sd_bus_message *message,
                             struct broker_snapshot *snapshot)
{
  const char *path = NULL;
  uint64_t stamps[4];
  uint32_t pid;
  int32_t code;
  int32_t status;
  int ignore_errors;
  int entry;
  int argument;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY,
                                     "(sasbttttuii)") <= 0 ||
      sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT,
                                     "sasbttttuii") <= 0 ||
      sd_bus_message_read(message, "s", &path) <= 0 ||
      exact_text(snapshot->executable, sizeof(snapshot->executable), path) != 0 ||
      strcmp(snapshot->executable, query->executable) != 0 ||
      sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "s") <= 0)
    return -1;
  for (;;) {
    const char *text = NULL;
    argument = sd_bus_message_read(message, "s", &text);
    if (argument < 0)
      return -1;
    if (argument == 0)
      break;
    if (snapshot->argument_count >= BROKER_MAX_ARGUMENTS ||
        exact_text(snapshot->arguments[snapshot->argument_count],
                   sizeof(snapshot->arguments[0]), text) != 0)
      return -1;
    snapshot->argument_count++;
  }
  if (sd_bus_message_exit_container(message) < 0 ||
      sd_bus_message_read(message, "bttttuii", &ignore_errors,
                          &stamps[0], &stamps[1], &stamps[2], &stamps[3],
                          &pid, &code, &status) <= 0 || ignore_errors != 0 ||
      sd_bus_message_exit_container(message) < 0)
    return -1;
  entry = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT,
                                         "sasbttttuii");
  if (entry != 0 || sd_bus_message_exit_container(message) < 0 ||
      snapshot->argument_count != (query->role == 1 ? 1U : 8U) ||
      strcmp(snapshot->arguments[0], query->executable) != 0)
    return -1;
  return 0;
}

static int decode_property(struct broker_query *query, sd_bus_message *message,
                           void *userdata)
{
  struct broker_property_decode *decode = userdata;
  struct broker_snapshot *snapshot = decode->snapshot;
  enum broker_property property = decode->property;
  const char *text = NULL;
  const void *bytes = NULL;
  size_t length = 0;
  int flag;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_VARIANT,
                                     properties[property].signature) <= 0)
    return -1;
  switch (property) {
  case BROKER_MANAGER_ENVIRONMENT:
  case BROKER_SERVICE_ENVIRONMENT:
    if (decode_environment(message) != 0)
      return -1;
    break;
  case BROKER_ENVIRONMENT_FILES:
    if (decode_empty_array(message, "(sb)") != 0)
      return -1;
    break;
  case BROKER_PASS_ENVIRONMENT:
    if (decode_empty_array(message, "s") != 0)
      return -1;
    break;
  case BROKER_UNIT_ID:
    if (sd_bus_message_read(message, "s", &text) <= 0 ||
        strcmp(text, query->unit) != 0)
      return -1;
    break;
  case BROKER_INVOCATION:
    if (sd_bus_message_read_array(message, SD_BUS_TYPE_BYTE,
                                  &bytes, &length) <= 0 ||
        length != sizeof(snapshot->invocation) ||
        memcmp(bytes, snapshot->invocation, length) != 0)
      return -1;
    break;
  case BROKER_FRAGMENT:
    if (sd_bus_message_read(message, "s", &text) <= 0 ||
        exact_text(snapshot->fragment, sizeof(snapshot->fragment), text) != 0 ||
        snapshot->fragment[0] != '/')
      return -1;
    break;
  case BROKER_SOURCE_PATH:
    if (sd_bus_message_read(message, "s", &text) <= 0 || text[0] != '\0')
      return -1;
    break;
  case BROKER_DROP_IN_PATHS:
    if (decode_empty_array(message, "s") != 0)
      return -1;
    break;
  case BROKER_NEED_DAEMON_RELOAD:
  case BROKER_TRANSIENT:
    if (sd_bus_message_read(message, "b", &flag) <= 0 || flag != 0)
      return -1;
    break;
  case BROKER_MAIN_PID:
    if (sd_bus_message_read(message, "u", &snapshot->main_pid) <= 0 ||
        snapshot->main_pid != query->subject.pid)
      return -1;
    break;
  case BROKER_CGROUP_ID:
    if (sd_bus_message_read(message, "t", &snapshot->cgroup_id) <= 0 ||
        snapshot->cgroup_id != query->subject.cgroup_id)
      return -1;
    break;
  case BROKER_CGROUP:
    if (sd_bus_message_read(message, "s", &text) <= 0 ||
        exact_text(snapshot->cgroup, sizeof(snapshot->cgroup), text) != 0)
      return -1;
    break;
  case BROKER_EXEC_START:
    if (decode_exec_start(query, message, snapshot) != 0)
      return -1;
    break;
  default:
    return -1;
  }
  return sd_bus_message_exit_container(message) >= 0 &&
                 sd_bus_message_at_end(message, true) > 0
             ? 0
             : -1;
}

static int get_unit(struct broker_query *query,
                    struct broker_snapshot *snapshot)
{
  sd_bus_message *request = NULL;
  if (sd_bus_message_new_method_call(
          query->shared.bus, &request, NULL,
          "/org/freedesktop/systemd1",
          "org.freedesktop.systemd1.Manager", "GetUnitByPIDFD") < 0 ||
      sd_bus_message_append(request, "h", BROKER_TARGET_FD) < 0) {
    sd_bus_message_unref(request);
    return -1;
  }
  return bus_call(query, request, decode_unit, snapshot);
}

static int get_property(struct broker_query *query,
                        enum broker_property property,
                        struct broker_snapshot *snapshot)
{
  sd_bus_message *request = NULL;
  struct broker_property_decode decode = {
      .property = property, .snapshot = snapshot};
  if (sd_bus_message_new_method_call(
          query->shared.bus, &request, NULL,
          property == BROKER_MANAGER_ENVIRONMENT
              ? "/org/freedesktop/systemd1"
              : query->unit_path,
          "org.freedesktop.DBus.Properties", "Get") < 0 ||
      sd_bus_message_append(request, "ss", properties[property].interface,
                            properties[property].name) < 0) {
    sd_bus_message_unref(request);
    return -1;
  }
  return bus_call(query, request, decode_property, &decode);
}

static int query_snapshot(struct broker_query *query,
                          struct broker_snapshot *snapshot)
{
  struct broker_pidfd_info final = {.mask = PIDFD_INFO_ALL};
  char expected_cgroup[BROKER_MAX_CGROUP + 1U];
  int written;
  if (get_unit(query, snapshot) != 0)
    return -1;
  for (int property = 0; property < BROKER_PROPERTY_COUNT; property++) {
    if (get_property(query, (enum broker_property)property, snapshot) != 0)
      return -1;
  }
  written = snprintf(expected_cgroup, sizeof(expected_cgroup),
                     "/aos.slice/aos-control.slice/%s", query->unit);
  if (written <= 0 || (size_t)written >= sizeof(expected_cgroup) ||
      strcmp(snapshot->cgroup, expected_cgroup) != 0 ||
      ioctl(BROKER_TARGET_FD, PIDFD_GET_INFO, &final) != 0 ||
      (final.mask & PIDFD_INFO_ALL) != PIDFD_INFO_ALL ||
      final.pid != query->subject.pid ||
      final.tgid != query->subject.tgid ||
      final.cgroup_id != query->subject.cgroup_id ||
      final.euid != query->subject.euid)
    return -1;
  return 0;
}

static int append_bytes(uint8_t record[BROKER_MAX_RECORD], size_t *used,
                        const void *source, size_t length)
{
  if (*used > BROKER_MAX_RECORD || length > BROKER_MAX_RECORD - *used)
    return -1;
  memcpy(record + *used, source, length);
  *used += length;
  return 0;
}

static int append_u8(uint8_t record[BROKER_MAX_RECORD], size_t *used,
                     uint8_t value)
{
  return append_bytes(record, used, &value, 1);
}

static int append_u16(uint8_t record[BROKER_MAX_RECORD], size_t *used,
                      uint16_t value)
{
  uint8_t bytes[2];
  store_u16(bytes, value);
  return append_bytes(record, used, bytes, sizeof(bytes));
}

static int append_u32(uint8_t record[BROKER_MAX_RECORD], size_t *used,
                      uint32_t value)
{
  uint8_t bytes[4] = {(uint8_t)(value >> 24U),
                      (uint8_t)(value >> 16U),
                      (uint8_t)(value >> 8U), (uint8_t)value};
  return append_bytes(record, used, bytes, sizeof(bytes));
}

static int append_u64(uint8_t record[BROKER_MAX_RECORD], size_t *used,
                      uint64_t value)
{
  uint8_t bytes[8];
  for (size_t index = 0; index < 8; index++) {
    bytes[7 - index] = (uint8_t)value;
    value >>= 8U;
  }
  return append_bytes(record, used, bytes, sizeof(bytes));
}

static int append_text(uint8_t record[BROKER_MAX_RECORD], size_t *used,
                       const char *value)
{
  size_t length = strlen(value);
  if (length == 0 || length > UINT16_MAX ||
      append_u16(record, used, (uint16_t)length) != 0)
    return -1;
  return append_bytes(record, used, value, length);
}

static int send_snapshot(struct broker_query *query, enum broker_phase phase,
                         const struct broker_snapshot *snapshot)
{
  uint8_t record[BROKER_MAX_RECORD];
  size_t used = 0;
  if (append_bytes(record, &used, query->nonce, sizeof(query->nonce)) != 0 ||
      append_u8(record, &used, query->role) != 0 ||
      append_u32(record, &used, snapshot->main_pid) != 0 ||
      append_u64(record, &used, query->subject_inode) != 0 ||
      append_u64(record, &used, snapshot->cgroup_id) != 0 ||
      append_text(record, &used, query->unit) != 0 ||
      append_bytes(record, &used, snapshot->invocation,
                   sizeof(snapshot->invocation)) != 0 ||
      append_text(record, &used, snapshot->cgroup) != 0 ||
      append_text(record, &used, snapshot->fragment) != 0 ||
      append_text(record, &used, snapshot->executable) != 0 ||
      append_u8(record, &used, snapshot->argument_count) != 0)
    return -1;
  for (size_t index = 0; index < snapshot->argument_count; index++) {
    if (append_text(record, &used, snapshot->arguments[index]) != 0)
      return -1;
  }
  /* V3 states that both fresh PID 1 snapshots passed the loader-input gate. */
  if (append_u8(record, &used, 1U) != 0)
    return -1;
  return send_control(query, phase, record, used);
}

static int nonce_record(const uint8_t *record, size_t size,
                        const struct broker_query *query)
{
  return size == sizeof(query->nonce) &&
                 memcmp(record, query->nonce, size) == 0
             ? 0
             : -1;
}

static int run_broker_query(void)
{
  struct broker_query query = {0};
  struct broker_snapshot first = {0};
  struct broker_snapshot second = {0};
  uint8_t control[BROKER_MAX_RECORD];
  size_t size;
  uint64_t started;
  int result = -1;

  if (now_ns(&started) != 0 || started > UINT64_MAX - UINT64_C(2000000000))
    return -1;
  query.shared.deadline.tv_sec =
      (time_t)((started + UINT64_C(2000000000)) /
               UINT64_C(1000000000));
  query.shared.deadline.tv_nsec =
      (long)((started + UINT64_C(2000000000)) %
             UINT64_C(1000000000));
  if (validate_entry(&query) != 0 ||
      receive_control(&query, BROKER_START, control, &size) != 0 ||
      decode_start(&query, control, size) != 0 ||
      aos_query_set_runtime_limits() != 0 ||
      encode_unit_path(query.unit, query.unit_path,
                       sizeof(query.unit_path)) != 0 ||
      sd_bus_new(&query.shared.bus) < 0 ||
      sd_bus_set_fd(query.shared.bus, AOS_QUERY_MANAGER_FD,
                    AOS_QUERY_MANAGER_FD) < 0 ||
      sd_bus_set_bus_client(query.shared.bus, 0) < 0 ||
      sd_bus_set_anonymous(query.shared.bus, 0) < 0 ||
      sd_bus_negotiate_fds(query.shared.bus, 1) < 0 ||
      sd_bus_start(query.shared.bus) < 0 || bus_ready(&query) != 0)
    goto out;

  if (query_snapshot(&query, &first) != 0 ||
      send_snapshot(&query, BROKER_SNAPSHOT_A, &first) != 0 ||
      receive_control(&query, BROKER_CONTINUE, control, &size) != 0 ||
      nonce_record(control, size, &query) != 0 ||
      query_snapshot(&query, &second) != 0 ||
      memcmp(&first, &second, sizeof(first)) != 0 ||
      send_snapshot(&query, BROKER_SNAPSHOT_B, &second) != 0 ||
      receive_control(&query, BROKER_ACK, control, &size) != 0 ||
      nonce_record(control, size, &query) != 0)
    goto out;
  result = 0;
out:
  if (query.shared.bus != NULL) {
    sd_bus_close(query.shared.bus);
    sd_bus_unref(query.shared.bus);
  }
  return result;
}

#ifdef AOS_INSPECTOR_WORKER_MODE
int aos_query_run_worker_mode(int argc, char **argv)
#else
int main(int argc, char **argv)
#endif
{
  if (argc != 1 || argv == NULL || argv[0] == NULL || argv[1] != NULL ||
      strcmp(argv[0], AOS_BROKER_QUERY_PROGRAM) != 0 ||
      environ == NULL || environ[0] != NULL)
    return 254;
  return run_broker_query() == 0 ? 0 : 254;
}
