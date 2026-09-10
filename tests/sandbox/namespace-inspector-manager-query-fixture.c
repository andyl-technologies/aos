/* SPDX-License-Identifier: Apache-2.0 */
#include "namespace-inspector-manager-query-fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const uint8_t fixture_query_schema_digest[32] = {
    116, 242, 223, 173, 18, 235, 224, 170, 160, 88, 155, 79, 88, 28, 110, 116,
    19,  12,  27,  31,  143, 150, 14,  25,  153, 188, 92, 134, 151, 138, 20, 154,
};

#define AOS_SYSTEMD_V259_PROPERTY(id, object, interface, property, signature,  \
                                  binding, shape)                              \
  {id, #object, #interface, property, signature, #binding, #shape},
static const struct aos_query_property snapshot_properties[] = {
#include "systemd_v259_properties.def"
};
#undef AOS_SYSTEMD_V259_PROPERTY

_Static_assert(sizeof(snapshot_properties) / sizeof(snapshot_properties[0]) ==
                   AOS_QUERY_PROPERTY_COUNT,
               "snapshot parser manifest count changed");

#define PIDFD_GET_INFO 0xc048ff0b
#define PIDFD_INFO_PID (1ULL << 0)

struct fixture_control_pidfd_info {
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

static void store_u16be(uint8_t *bytes, uint16_t value)
{
  bytes[0] = (uint8_t)(value >> 8U);
  bytes[1] = (uint8_t)value;
}

static void store_u32be(uint8_t *bytes, uint32_t value)
{
  bytes[0] = (uint8_t)(value >> 24U);
  bytes[1] = (uint8_t)(value >> 16U);
  bytes[2] = (uint8_t)(value >> 8U);
  bytes[3] = (uint8_t)value;
}

static void store_u64be(uint8_t *bytes, uint64_t value)
{
  for (size_t index = 0; index < 8; index++) {
    bytes[7 - index] = (uint8_t)value;
    value >>= 8U;
  }
}

static uint16_t load_u16be(const uint8_t *bytes)
{
  return (uint16_t)((uint16_t)bytes[0] << 8U | bytes[1]);
}

static uint32_t load_u32be(const uint8_t *bytes)
{
  return (uint32_t)bytes[0] << 24U | (uint32_t)bytes[1] << 16U |
         (uint32_t)bytes[2] << 8U | bytes[3];
}

static uint64_t load_u64be(const uint8_t *bytes)
{
  uint64_t value = 0;

  for (size_t index = 0; index < 8; index++)
    value = value << 8U | bytes[index];
  return value;
}

static uint16_t load_u16le(const uint8_t *bytes)
{
  return (uint16_t)(bytes[0] | (uint16_t)bytes[1] << 8U);
}

static uint32_t load_u32le(const uint8_t *bytes)
{
  return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8U |
         (uint32_t)bytes[2] << 16U | (uint32_t)bytes[3] << 24U;
}

static uint64_t load_u64le(const uint8_t *bytes)
{
  uint64_t value = 0;

  for (size_t index = 0; index < 8; index++)
    value |= (uint64_t)bytes[index] << (8U * index);
  return value;
}

static int valid_sent_payload(enum aos_query_phase phase, size_t length)
{
  switch (phase) {
  case AOS_QUERY_PHASE_START:
    return length == AOS_QUERY_START_PAYLOAD_SIZE ? 0 : -1;
  case AOS_QUERY_PHASE_CONTINUE:
  case AOS_QUERY_PHASE_ACK:
    return length == AOS_QUERY_NONCE_PAYLOAD_SIZE ? 0 : -1;
  default:
    return -1;
  }
}

static int valid_received_payload(enum aos_query_phase phase, size_t length)
{
  switch (phase) {
  case AOS_QUERY_PHASE_A:
  case AOS_QUERY_PHASE_B:
    if (length < AOS_QUERY_PHASE_BINDING_SIZE ||
        length > AOS_QUERY_MAX_CONTROL_PAYLOAD)
      return -1;
    return 0;
  case AOS_QUERY_PHASE_ABORT:
    return length == AOS_QUERY_ABORT_PAYLOAD_SIZE ? 0 : -1;
  default:
    return -1;
  }
}

static void close_received_fds(struct msghdr *message)
{
  const uint8_t *control_end =
      (uint8_t *)message->msg_control + message->msg_controllen;

  for (struct cmsghdr *header = CMSG_FIRSTHDR(message); header != NULL;
       header = CMSG_NXTHDR(message, header)) {
    const uint8_t *data = CMSG_DATA(header);
    size_t data_length;

    if (header->cmsg_level != SOL_SOCKET ||
        (header->cmsg_type != SCM_RIGHTS &&
         header->cmsg_type != AOS_SCM_PIDFD) ||
        header->cmsg_len < CMSG_LEN(0))
      continue;
    data_length = header->cmsg_len - CMSG_LEN(0);
    if (data > control_end)
      continue;
    if (data_length > (size_t)(control_end - data))
      data_length = (size_t)(control_end - data);
    for (size_t offset = 0; offset + sizeof(int) <= data_length;
         offset += sizeof(int)) {
      int descriptor;

      memcpy(&descriptor, data + offset, sizeof(descriptor));
      if (descriptor >= 0)
        close(descriptor);
    }
  }
}

static int write_file(const char *path, const char *contents)
{
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  size_t length = strlen(contents);
  ssize_t written;

  if (fd < 0)
    return -1;
  written = write(fd, contents, length);
  if (close(fd) != 0 || written != (ssize_t)length)
    return -1;
  return 0;
}

int aos_fixture_enter_root_user_namespace(void)
{
  uid_t uid = geteuid();
  gid_t gid = getegid();
  char mapping[64];

  if (uid == 0 && gid == 0)
    return 0;
  if (unshare(CLONE_NEWUSER) != 0 ||
      write_file("/proc/self/setgroups", "deny\n") != 0)
    return -1;
  if (snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)uid) < 0 ||
      write_file("/proc/self/uid_map", mapping) != 0)
    return -1;
  if (snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)gid) < 0 ||
      write_file("/proc/self/gid_map", mapping) != 0 || setresgid(0, 0, 0) != 0 ||
      setresuid(0, 0, 0) != 0)
    return -1;
  return 0;
}

static int configure_control(int fd, bool pass_pidfd)
{
  int enabled = 1;

  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0)
    return -1;
  if (pass_pidfd &&
      setsockopt(fd, SOL_SOCKET, SO_PASSPIDFD, &enabled, sizeof(enabled)) != 0)
    return -1;
  return 0;
}

static int drop_child_authority(void)
{
  struct __user_cap_header_struct header = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
  };
  struct __user_cap_data_struct data[2] = {0};

  for (int capability = 0; capability <= 40; capability++) {
    if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0)
      return -1;
  }
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 ||
      syscall(SYS_capset, &header, data) != 0 ||
      prctl(PR_SET_DUMPABLE, 0) != 0)
    return -1;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    return -1;
  return 0;
}

static int install_child_fds(int null_fd, int stdout_fd, int stderr_fd,
                             int bus_fd, int parent_pidfd, int control_fd,
                             const struct aos_fixture_case *test_case)
{
  int inherited_parent = test_case->fault == AOS_FIXTURE_ENTRY_BAD_PIDFD
                             ? null_fd
                             : parent_pidfd;
  int sources[] = {null_fd, stdout_fd, stderr_fd, bus_fd, inherited_parent,
                   control_fd};
  int copies[6];

  for (size_t index = 0; index < 6; index++) {
    copies[index] = fcntl(sources[index], F_DUPFD_CLOEXEC, 64);
    if (copies[index] < 0)
      return -1;
  }
  for (int target = 0; target < 6; target++) {
    if (dup2(copies[target], target) != target)
      return -1;
  }
  if (syscall(SYS_close_range, 6U, UINT_MAX, 0U) != 0)
    return -1;
  if (test_case->fault == AOS_FIXTURE_ENTRY_EXTRA_FD && dup2(0, 6) != 6)
    return -1;
  if (test_case->fault == AOS_FIXTURE_ENTRY_LOW_NOFILE) {
    struct rlimit limit = {.rlim_cur = 31, .rlim_max = 31};

    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
      return -1;
  }
  return 0;
}

static int saturate_control_send_buffer(void)
{
  const uint8_t filler = 0;
  size_t records = 0;

  for (;;) {
    ssize_t written = send(AOS_QUERY_CONTROL_FD, &filler, sizeof(filler),
                           MSG_DONTWAIT | MSG_NOSIGNAL);

    if (written == (ssize_t)sizeof(filler)) {
      records++;
      continue;
    }
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && records > 0)
      return 0;
    return -1;
  }
}

static int pause_for_nonblocking_retry(void)
{
  struct timespec remaining = {.tv_nsec = 50000000};

  while (nanosleep(&remaining, &remaining) != 0) {
    if (errno != EINTR)
      return -1;
  }
  return 0;
}

static int spawn_helper(const char *helper, int bus_fd, int parent_pidfd,
                        int control_fd, int stdout_fd, int stderr_fd,
                        const struct aos_fixture_case *test_case, pid_t *child)
{
  int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  pid_t pid;

  if (null_fd < 0)
    return -1;
  pid = fork();
  if (pid < 0) {
    close(null_fd);
    return -1;
  }
  if (pid == 0) {
    char *const arguments[] = {(char *)helper, NULL};
    char *const empty_environment[] = {NULL};
    char *const nonempty_environment[] = {(char *)"AOS_INVALID=1", NULL};
    char *const *environment = test_case->fault == AOS_FIXTURE_ENTRY_NONEMPTY_ENV
                                   ? nonempty_environment
                                   : empty_environment;

    if (install_child_fds(null_fd, stdout_fd, stderr_fd, bus_fd, parent_pidfd,
                          control_fd, test_case) != 0 ||
        drop_child_authority() != 0)
      _exit(253);
    if (test_case->fault == AOS_FIXTURE_CONTROL_SEND_RETRY &&
        saturate_control_send_buffer() != 0)
      _exit(253);
    execve(helper, arguments, environment);
    _exit(253);
  }
  close(null_fd);
  *child = pid;
  return 0;
}

static int send_record(int control_fd, enum aos_query_phase phase,
                       const void *payload, size_t payload_length)
{
  struct aos_fixture_wire wire = {0};
  struct aos_query_wire_header header = {0};

  if (valid_sent_payload(phase, payload_length) != 0 ||
      payload_length > UINT32_MAX)
    return -1;
  memcpy(header.magic, AOS_QUERY_PROTOCOL_MAGIC, sizeof(header.magic));
  store_u16be(header.version_be, AOS_QUERY_PROTOCOL_VERSION);
  store_u16be(header.phase_be, (uint16_t)phase);
  store_u32be(header.length_be, (uint32_t)payload_length);
  if (aos_fixture_wire_append(&wire, &header, sizeof(header)) != 0 ||
      aos_fixture_wire_append(&wire, payload, payload_length) != 0)
    return -1;
  return send(control_fd, wire.bytes, wire.length, MSG_NOSIGNAL) ==
                 (ssize_t)wire.length
             ? 0
             : -1;
}

static int send_record_with_rights(int control_fd, enum aos_query_phase phase,
                                   const void *payload, size_t payload_length)
{
  struct aos_fixture_wire wire = {0};
  struct aos_query_wire_header protocol_header = {0};
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(int))];
  } control;
  struct iovec iovec;
  struct msghdr message = {0};
  struct cmsghdr *header;
  int descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);
  int result = -1;

  if (descriptor < 0)
    return -1;
  if (valid_sent_payload(phase, payload_length) != 0 ||
      payload_length > UINT32_MAX)
    goto out;
  memcpy(protocol_header.magic, AOS_QUERY_PROTOCOL_MAGIC,
         sizeof(protocol_header.magic));
  store_u16be(protocol_header.version_be, AOS_QUERY_PROTOCOL_VERSION);
  store_u16be(protocol_header.phase_be, (uint16_t)phase);
  store_u32be(protocol_header.length_be, (uint32_t)payload_length);
  if (aos_fixture_wire_append(&wire, &protocol_header,
                              sizeof(protocol_header)) != 0 ||
      aos_fixture_wire_append(&wire, payload, payload_length) != 0)
    goto out;

  iovec.iov_base = wire.bytes;
  iovec.iov_len = wire.length;
  message.msg_iov = &iovec;
  message.msg_iovlen = 1;
  message.msg_control = control.bytes;
  message.msg_controllen = sizeof(control.bytes);
  header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(descriptor));
  memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  if (sendmsg(control_fd, &message, MSG_NOSIGNAL) == (ssize_t)wire.length)
    result = 0;

out:
  close(descriptor);
  return result;
}

static int send_start(int control_fd, int parent_pidfd,
                      struct aos_fixture_identity *identity,
                      const struct aos_fixture_case *test_case)
{
  struct stat status;
  struct timespec now;
  uint8_t payload[104] = {0};
  uint8_t *cursor = payload;
  uint64_t deadline_ns;

  if (fstat(parent_pidfd, &status) != 0 ||
      clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return -1;
  deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                (uint64_t)now.tv_nsec + UINT64_C(950000000);
  if (test_case->fault == AOS_FIXTURE_START_PAST_DEADLINE)
    deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                  (uint64_t)now.tv_nsec - 1U;
  else if (test_case->fault == AOS_FIXTURE_START_LONG_DEADLINE)
    deadline_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                  (uint64_t)now.tv_nsec + UINT64_C(2000000000);
  memcpy(identity->start.query_schema_digest, fixture_query_schema_digest,
         sizeof(identity->start.query_schema_digest));
  identity->start.deadline_ns = deadline_ns;
  identity->start.ordinal = UINT64_C(0x1020304050607080);
  identity->start.cookie = UINT64_C(0x8877665544332211);
  if (test_case->fault == AOS_FIXTURE_START_MIN_IDENTITY) {
    identity->start.ordinal = 0;
    identity->start.cookie = 1;
  } else if (test_case->fault == AOS_FIXTURE_START_MAX_IDENTITY) {
    identity->start.ordinal = UINT64_MAX;
    identity->start.cookie = UINT64_MAX;
  }
  /* The activation connector is intentionally not the spawned helper's
   * invoking parent. The fake manager binds these independent fields to the
   * service instance returned for GetUnitByPIDFD(parent_pidfd). */
  identity->start.connector_pid =
      (uint32_t)getpid() == 1U ? 2U : (uint32_t)getpid() ^ 1U;
  identity->start.connector_pidfd_inode =
      (uint64_t)status.st_ino == 1U ? 2U : (uint64_t)status.st_ino ^ UINT64_C(1);
  identity->start.connector_uid = (uint32_t)geteuid();
  if (test_case->fault == AOS_FIXTURE_START_EQUAL_PARENT_CONNECTOR) {
    identity->start.connector_pid = (uint32_t)getpid();
    identity->start.connector_pidfd_inode = (uint64_t)status.st_ino;
  } else if (test_case->fault == AOS_FIXTURE_START_SAME_PID_DIFFERENT_INODE) {
    identity->start.connector_pid = (uint32_t)getpid();
  } else if (test_case->fault == AOS_FIXTURE_START_DIFFERENT_PID_SAME_INODE) {
    identity->start.connector_pidfd_inode = (uint64_t)status.st_ino;
  }
  for (size_t index = 0; index < sizeof(identity->invocation_id); index++)
    identity->invocation_id[index] = (uint8_t)(0xa0U + index);
  if (aos_fixture_prepare_identity(identity) != 0)
    return -1;

  memcpy(cursor, identity->start.nonce, sizeof(identity->start.nonce));
  cursor += 32;
  store_u64be(cursor, identity->start.deadline_ns);
  cursor += 8;
  memcpy(cursor, identity->start.query_schema_digest,
         sizeof(identity->start.query_schema_digest));
  if (test_case->fault == AOS_FIXTURE_START_WRONG_DIGEST)
    cursor[0] ^= 0x80U;
  cursor += 32;
  store_u64be(cursor, identity->start.ordinal);
  cursor += 8;
  store_u64be(cursor, identity->start.cookie);
  cursor += 8;
  store_u32be(cursor, identity->start.connector_pid +
                          (test_case->fault == AOS_FIXTURE_START_WRONG_CONNECTOR));
  cursor += 4;
  store_u64be(cursor, identity->start.connector_pidfd_inode);
  if (test_case->fault == AOS_FIXTURE_START_WRONG_CONNECTOR_INODE)
    cursor[7] ^= 1U;
  cursor += 8;
  store_u32be(cursor, identity->start.connector_uid);
  return send_record(control_fd, AOS_QUERY_PHASE_START, payload, sizeof(payload));
}

static int receive_phase(int control_fd, pid_t child,
                         enum aos_query_phase *phase,
                         struct aos_fixture_wire *payload)
{
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
  } control;
  struct aos_fixture_wire record = {0};
  struct iovec iovec = {.iov_base = record.bytes, .iov_len = sizeof(record.bytes)};
  struct msghdr message = {
      .msg_iov = &iovec,
      .msg_iovlen = 1,
      .msg_control = control.bytes,
      .msg_controllen = sizeof(control.bytes),
  };
  bool credentials = false;
  bool pidfd = false;
  int received_pidfd = -1;
  struct ucred received_credentials = {0};
  ssize_t length = recvmsg(control_fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  struct aos_query_wire_header *header;

  if (length < 0)
    return -1;
  if (length < (ssize_t)sizeof(*header) ||
      (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
    goto fail;
  for (struct cmsghdr *item = CMSG_FIRSTHDR(&message); item != NULL;
       item = CMSG_NXTHDR(&message, item)) {
    if (item->cmsg_level != SOL_SOCKET)
      goto fail;
    if (item->cmsg_type == SCM_CREDENTIALS &&
        item->cmsg_len == CMSG_LEN(sizeof(struct ucred)) && !credentials) {
      memcpy(&received_credentials, CMSG_DATA(item),
             sizeof(received_credentials));
      if (received_credentials.pid != child || received_credentials.uid != 0 ||
          received_credentials.gid != 0)
        goto fail;
      credentials = true;
    } else if (item->cmsg_type == AOS_SCM_PIDFD &&
               item->cmsg_len == CMSG_LEN(sizeof(int)) && !pidfd) {
      memcpy(&received_pidfd, CMSG_DATA(item), sizeof(received_pidfd));
      pidfd = true;
    } else {
      goto fail;
    }
  }
  if (!credentials || !pidfd)
    goto fail;
  {
    struct fixture_control_pidfd_info info = {.mask = PIDFD_INFO_PID};

    if (ioctl(received_pidfd, PIDFD_GET_INFO, &info) != 0 ||
        (info.mask & PIDFD_INFO_PID) == 0 || info.pid != (uint32_t)child ||
        info.euid != 0)
      goto fail;
  }
  header = (struct aos_query_wire_header *)record.bytes;
  if (memcmp(header->magic, AOS_QUERY_PROTOCOL_MAGIC, sizeof(header->magic)) != 0 ||
      load_u16be(header->version_be) != AOS_QUERY_PROTOCOL_VERSION ||
      load_u32be(header->length_be) != (uint32_t)length - sizeof(*header) ||
      valid_received_payload(
          (enum aos_query_phase)load_u16be(header->phase_be),
          (size_t)length - sizeof(*header)) != 0)
    goto fail;

  *phase = (enum aos_query_phase)load_u16be(header->phase_be);
  payload->length = (size_t)length - sizeof(*header);
  memcpy(payload->bytes, record.bytes + sizeof(*header), payload->length);
  close_received_fds(&message);
  return 0;

fail:
  close_received_fds(&message);
  return -1;
}

struct snapshot_decoder {
  const uint8_t *bytes;
  size_t length;
  size_t offset;
};

static int snapshot_take(struct snapshot_decoder *decoder, size_t length,
                         const uint8_t **bytes)
{
  if (decoder->offset > decoder->length ||
      length > decoder->length - decoder->offset)
    return -1;
  *bytes = decoder->bytes + decoder->offset;
  decoder->offset += length;
  return 0;
}

static int snapshot_u8(struct snapshot_decoder *decoder, uint8_t *value)
{
  const uint8_t *bytes;

  if (snapshot_take(decoder, 1, &bytes) != 0)
    return -1;
  *value = bytes[0];
  return 0;
}

static int snapshot_u16(struct snapshot_decoder *decoder, uint16_t *value)
{
  const uint8_t *bytes;

  if (snapshot_take(decoder, 2, &bytes) != 0)
    return -1;
  *value = load_u16le(bytes);
  return 0;
}

static int snapshot_u32(struct snapshot_decoder *decoder, uint32_t *value)
{
  const uint8_t *bytes;

  if (snapshot_take(decoder, 4, &bytes) != 0)
    return -1;
  *value = load_u32le(bytes);
  return 0;
}

static int snapshot_u64(struct snapshot_decoder *decoder, uint64_t *value)
{
  const uint8_t *bytes;

  if (snapshot_take(decoder, 8, &bytes) != 0)
    return -1;
  *value = load_u64le(bytes);
  return 0;
}

static int snapshot_exact_text(struct snapshot_decoder *decoder,
                               const char *expected, size_t maximum)
{
  const uint8_t *bytes;
  uint16_t length;
  size_t expected_length = strlen(expected);

  if (expected_length > maximum || expected_length > UINT16_MAX ||
      snapshot_u16(decoder, &length) != 0 ||
      length != expected_length ||
      snapshot_take(decoder, length, &bytes) != 0 ||
      memcmp(bytes, expected, length) != 0)
    return -1;
  return 0;
}

static int snapshot_blob(struct snapshot_decoder *decoder,
                         const uint8_t **bytes, size_t *length)
{
  uint32_t encoded_length;

  if (snapshot_u32(decoder, &encoded_length) != 0 ||
      encoded_length > AOS_QUERY_MAX_ELEMENT ||
      snapshot_take(decoder, encoded_length, bytes) != 0)
    return -1;
  *length = encoded_length;
  return 0;
}

static int expected_text(struct aos_fixture_wire *expected, const char *text)
{
  size_t length = strlen(text);

  if (length > UINT16_MAX ||
      aos_fixture_wire_u16le(expected, (uint16_t)length) != 0)
    return -1;
  return aos_fixture_wire_append(expected, text, length);
}

static int expected_strings(struct aos_fixture_wire *expected,
                            const char *first, const char *second)
{
  if (aos_fixture_wire_u16le(expected, 2) != 0 ||
      expected_text(expected, first) != 0 ||
      expected_text(expected, second) != 0)
    return -1;
  return 0;
}

static int expected_property_label(const struct aos_query_property *property,
                                   char label[64])
{
  int written = snprintf(label, 64, "value-%u", property->id);

  return written > 0 && written < 64 ? 0 : -1;
}

static int expected_scalar(const struct aos_query_property *property,
                           const struct aos_fixture_identity *identity,
                           struct aos_fixture_wire *expected)
{
  const char *signature = property->signature;
  char label[64];

  if (expected_property_label(property, label) != 0)
    return -1;
  if (strcmp(signature, "s") == 0) {
    const char *value = property->id == 1 ? identity->service_name : label;

    return aos_fixture_wire_append(expected, value, strlen(value));
  }
  if (strcmp(signature, "b") == 0)
    return aos_fixture_wire_u8(expected, 1);
  if (strcmp(signature, "u") == 0)
    return aos_fixture_wire_u32le(expected, (uint32_t)property->id + 1U);
  if (strcmp(signature, "i") == 0)
    return aos_fixture_wire_u32le(expected,
                                  (uint32_t)(-(int32_t)property->id - 1));
  if (strcmp(signature, "t") == 0)
    return aos_fixture_wire_u64le(
        expected, UINT64_C(0x100000000) + property->id);
  if (strcmp(signature, "ay") == 0)
    return aos_fixture_wire_append(expected, identity->invocation_id,
                                   sizeof(identity->invocation_id));
  if (strcmp(signature, "(uo)") == 0) {
    if (aos_fixture_wire_u32le(expected, property->id) != 0 ||
        expected_text(expected, "/org/freedesktop/systemd1/job/1") != 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "(bs)") == 0) {
    if (aos_fixture_wire_u8(expected, 1) != 0 ||
        expected_text(expected, label) != 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "(bas)") == 0) {
    if (aos_fixture_wire_u8(expected, 1) != 0 ||
        expected_strings(expected, "alpha", label) != 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "(ss)") == 0) {
    if (expected_text(expected, "first") != 0 ||
        expected_text(expected, label) != 0)
      return -1;
    return 0;
  }
  return -1;
}

static int expected_array_element(const struct aos_query_property *property,
                                  size_t index,
                                  struct aos_fixture_wire *expected)
{
  const char *signature = property->signature;
  char label[64];

  if (expected_property_label(property, label) != 0)
    return -1;
  if (strcmp(signature, "as") == 0) {
    const char *value;

    if (property->id == 0)
      value = index == 0 ? "LANG=C" : "PATH=/bin";
    else
      value = index == 0 ? "alpha" : label;
    return aos_fixture_wire_append(expected, value, strlen(value));
  }
  if (strcmp(signature, "a(sb)") == 0) {
    if (expected_text(expected, label) != 0 ||
        aos_fixture_wire_u8(expected, 1) != 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "a(ss)") == 0) {
    if (expected_text(expected, "first") != 0 ||
        expected_text(expected, label) != 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "a(sasbttttuii)") == 0 ||
      strcmp(signature, "a(sasasttttuii)") == 0) {
    bool extended = strcmp(signature, "a(sasasttttuii)") == 0;

    if (expected_text(expected, "/bin/true") != 0 ||
        expected_strings(expected, "/bin/true", "argument") != 0)
      return -1;
    if (extended) {
      if (expected_strings(expected, "ambient", "ignore-failure") != 0)
        return -1;
    } else if (aos_fixture_wire_u8(expected, 0) != 0) {
      return -1;
    }
    for (uint64_t value = 1; value <= 4; value++) {
      if (aos_fixture_wire_u64le(expected, value) != 0)
        return -1;
    }
    if (aos_fixture_wire_u32le(expected, 5) != 0 ||
        aos_fixture_wire_u32le(expected, 6) != 0 ||
        aos_fixture_wire_u32le(expected, 7) != 0)
      return -1;
    return 0;
  }
  return -1;
}

static int expected_boundary_element(size_t index,
                                     struct aos_fixture_wire *expected)
{
  size_t length = index + 1U == AOS_FIXTURE_BOUNDARY_ELEMENT_COUNT
                      ? AOS_FIXTURE_BOUNDARY_FINAL_LENGTH
                      : AOS_FIXTURE_BOUNDARY_ELEMENT_LENGTH;

  if (length > sizeof(expected->bytes) - expected->length)
    return -1;
  memset(expected->bytes + expected->length, 'x', length);
  expected->length += length;
  return 0;
}

static int expected_shape(const struct aos_query_property *property,
                          uint8_t *shape)
{
  if (strcmp(property->shape, "SCALAR") == 0)
    *shape = 1;
  else if (strcmp(property->shape, "ORDERED_ARRAY") == 0)
    *shape = 2;
  else if (strcmp(property->shape, "UNORDERED_SET") == 0)
    *shape = 3;
  else
    return -1;
  return 0;
}

static int validate_snapshot_properties(
    struct snapshot_decoder *decoder,
    const struct aos_fixture_identity *identity,
    const struct aos_fixture_case *test_case)
{
  uint16_t count;

  if (snapshot_u16(decoder, &count) != 0 ||
      count != AOS_QUERY_PROPERTY_COUNT)
    return -1;
  for (size_t index = 0; index < AOS_QUERY_PROPERTY_COUNT; index++) {
    const struct aos_query_property *property = &snapshot_properties[index];
    struct aos_fixture_wire expected = {0};
    const uint8_t *actual;
    size_t actual_length;
    uint16_t id;
    uint16_t element_count;
    uint8_t shape;
    uint8_t required_shape;
    bool boundary_property =
        test_case->fault == AOS_FIXTURE_MAXIMUM_SNAPSHOT &&
        property->id == AOS_FIXTURE_BOUNDARY_PROPERTY_ID;

    if (snapshot_u16(decoder, &id) != 0 || id != index ||
        id != property->id || snapshot_u8(decoder, &shape) != 0 ||
        expected_shape(property, &required_shape) != 0 ||
        shape != required_shape)
      return -1;
    if (shape == 1) {
      if (snapshot_blob(decoder, &actual, &actual_length) != 0 ||
          expected_scalar(property, identity, &expected) != 0 ||
          actual_length != expected.length ||
          memcmp(actual, expected.bytes, actual_length) != 0)
        return -1;
      continue;
    }

    if (snapshot_u16(decoder, &element_count) != 0 ||
        element_count !=
            (boundary_property
                 ? AOS_FIXTURE_BOUNDARY_ELEMENT_COUNT
                 : (strcmp(property->signature, "as") == 0 ? 2 : 1)))
      return -1;
    for (size_t element = 0; element < element_count; element++) {
      expected.length = 0;
      if (snapshot_blob(decoder, &actual, &actual_length) != 0 ||
          (boundary_property
               ? expected_boundary_element(element, &expected)
               : expected_array_element(property, element, &expected)) != 0 ||
          actual_length != expected.length ||
          memcmp(actual, expected.bytes, actual_length) != 0)
        return -1;
    }
  }
  return 0;
}

static int validate_phase_snapshot(
    const struct aos_fixture_wire *payload,
    const struct aos_fixture_identity *identity,
    const struct aos_fixture_case *test_case)
{
  struct snapshot_decoder outer = {
      .bytes = payload->bytes,
      .length = payload->length,
  };
  struct snapshot_decoder snapshot;
  const uint8_t *bytes;
  uint64_t number64;
  uint32_t snapshot_length;
  uint32_t number32;
  uint16_t version;
  uint8_t kind;
  uint8_t reserved;

  if (snapshot_take(&outer, sizeof(identity->start.nonce), &bytes) != 0 ||
      memcmp(bytes, identity->start.nonce, sizeof(identity->start.nonce)) != 0 ||
      snapshot_take(&outer, sizeof(fixture_query_schema_digest), &bytes) != 0 ||
      memcmp(bytes, fixture_query_schema_digest,
             sizeof(fixture_query_schema_digest)) !=
          0 ||
      snapshot_take(&outer, 8, &bytes) != 0 ||
      load_u64be(bytes) != identity->start.ordinal ||
      snapshot_take(&outer, 8, &bytes) != 0 ||
      load_u64be(bytes) != identity->start.cookie ||
      snapshot_take(&outer, 4, &bytes) != 0)
    return -1;
  snapshot_length = load_u32be(bytes);
  if (snapshot_length != outer.length - outer.offset ||
      snapshot_length > AOS_QUERY_MAX_SNAPSHOT ||
      (test_case->fault == AOS_FIXTURE_MAXIMUM_SNAPSHOT &&
       (snapshot_length != AOS_QUERY_MAX_SNAPSHOT ||
        payload->length != AOS_QUERY_MAX_CONTROL_PAYLOAD)))
    return -1;
  snapshot.bytes = outer.bytes + outer.offset;
  snapshot.length = snapshot_length;
  snapshot.offset = 0;

  if (snapshot_take(&snapshot, 8, &bytes) != 0 ||
      memcmp(bytes, "AOSNIMS1", 8) != 0 ||
      snapshot_u16(&snapshot, &version) != 0 ||
      version != AOS_QUERY_PROTOCOL_VERSION ||
      snapshot_u8(&snapshot, &kind) != 0 ||
      kind != AOS_QUERY_SNAPSHOT_KIND ||
      snapshot_u8(&snapshot, &reserved) != 0 || reserved != 0 ||
      snapshot_u32(&snapshot, &number32) != 0 ||
      number32 != snapshot.length ||
      snapshot_take(&snapshot, sizeof(fixture_query_schema_digest), &bytes) != 0 ||
      memcmp(bytes, fixture_query_schema_digest,
             sizeof(fixture_query_schema_digest)) !=
          0 ||
      snapshot_exact_text(&snapshot, identity->service_name,
                          AOS_QUERY_MAX_UNIT_ID) != 0 ||
      snapshot_exact_text(&snapshot, identity->service_instance,
                          AOS_QUERY_MAX_INSTANCE) != 0 ||
      snapshot_take(&snapshot, sizeof(identity->invocation_id), &bytes) != 0 ||
      memcmp(bytes, identity->invocation_id,
             sizeof(identity->invocation_id)) != 0 ||
      snapshot_u32(&snapshot, &number32) != 0 || number32 != 25 ||
      snapshot_exact_text(&snapshot, "value-17", AOS_QUERY_MAX_CGROUP) != 0 ||
      snapshot_u64(&snapshot, &number64) != 0 ||
      number64 != UINT64_C(0x100000012) ||
      snapshot_u64(&snapshot, &number64) != 0 ||
      number64 != identity->start.ordinal ||
      snapshot_u64(&snapshot, &number64) != 0 ||
      number64 != identity->start.cookie ||
      snapshot_u32(&snapshot, &number32) != 0 ||
      number32 != identity->start.connector_pid ||
      snapshot_u64(&snapshot, &number64) != 0 ||
      number64 != identity->start.connector_pidfd_inode ||
      snapshot_u32(&snapshot, &number32) != 0 ||
      number32 != identity->start.connector_uid ||
      validate_snapshot_properties(&snapshot, identity, test_case) != 0 ||
      snapshot.offset != snapshot.length)
    return -1;
  return 0;
}

static int start_server(int bus_fd, sd_bus **server)
{
  const sd_id128_t server_id =
      SD_ID128_MAKE(10, 32, 54, 76, 98, ba, dc, fe, 01, 23, 45, 67, 89, ab, cd, ef);

  if (sd_bus_new(server) < 0 || sd_bus_set_fd(*server, bus_fd, bus_fd) < 0 ||
      sd_bus_set_server(*server, 1, server_id) < 0 ||
      sd_bus_set_anonymous(*server, 0) < 0 || sd_bus_negotiate_fds(*server, 1) < 0 ||
      sd_bus_start(*server) < 0)
    return -1;
  return 0;
}

static bool reply_fault_stops_bus(enum aos_fixture_fault fault)
{
  if (fault >= AOS_FIXTURE_RIGHTS_FIRST_UNIT &&
      fault <= AOS_FIXTURE_RIGHTS_LAST_PROPERTY)
    return true;
  switch (fault) {
  case AOS_FIXTURE_UNIT_INVOCATION_WRONG_LENGTH:
  case AOS_FIXTURE_UNIT_INVOCATION_ZERO:
  case AOS_FIXTURE_PROPERTY_SOCKET_INVOCATION_ZERO:
  case AOS_FIXTURE_PROPERTY_UNIT_ID_MISMATCH:
  case AOS_FIXTURE_PROPERTY_INVOCATION_MISMATCH:
  case AOS_FIXTURE_PROPERTY_EMPTY_CONTROL_GROUP:
  case AOS_FIXTURE_PROPERTY_ZERO_CONTROL_GROUP_ID:
  case AOS_FIXTURE_PROPERTY_ZERO_MAIN_PID:
  case AOS_FIXTURE_DUPLICATE_UNORDERED_SET:
  case AOS_FIXTURE_INVALID_MANAGER_ENVIRONMENT:
  case AOS_FIXTURE_DUPLICATE_MANAGER_ENVIRONMENT_NAME:
  case AOS_FIXTURE_WRONG_PROPERTY:
  case AOS_FIXTURE_TRAILING_VARIANT:
  case AOS_FIXTURE_OVERSIZE_TEXT:
  case AOS_FIXTURE_OVERSIZE_ARRAY:
  case AOS_FIXTURE_WRONG_UNIT_IDENTITY:
  case AOS_FIXTURE_WRONG_UNIT_PATH:
  case AOS_FIXTURE_DECLARED_FD_MISSING:
    return true;
  default:
    return false;
  }
}

static int exercise_case(int control_fd, int raw_bus_fd, sd_bus *server,
                         int helper_stdout, int helper_stderr, pid_t child,
                         const struct aos_fixture_identity *identity,
                         const struct aos_fixture_case *test_case)
{
  struct aos_fixture_wire first = {0};
  unsigned int calls = 0;
  bool have_first = false;
  bool have_abort = false;
  bool stopped_bus = false;
  bool send_retry_pause_complete = false;
  bool bus_fault = reply_fault_stops_bus(test_case->fault);
  bool expects_abort = bus_fault || test_case->fault == AOS_FIXTURE_STALLED_REPLY ||
                       test_case->fault == AOS_FIXTURE_ENTRY_LOW_NOFILE ||
                       test_case->fault == AOS_FIXTURE_OVERSIZE_SNAPSHOT ||
                       test_case->fault == AOS_FIXTURE_CONTINUE_WRONG_NONCE ||
                       test_case->fault == AOS_FIXTURE_CONTINUE_DUPLICATE ||
                       test_case->fault == AOS_FIXTURE_CONTINUE_RIGHTS;
  struct timespec start;

  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
    return -1;
  for (;;) {
    struct pollfd descriptors[] = {
        {.fd = raw_bus_fd, .events = POLLIN | POLLOUT},
        {.fd = control_fd, .events = POLLIN},
    };
    struct timespec now;
    int child_status;
    pid_t waited;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec - start.tv_sec > 2) {
      fprintf(stderr, "manager-query fixture: case timeout after %u calls\n", calls);
      return -1;
    }
    waited = waitpid(child, &child_status, WNOHANG);
    if (waited == child) {
      int exit_status = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;
      unsigned int expected_calls = test_case->expected_calls;

      if (exit_status != test_case->expected_exit || calls != expected_calls ||
          (expects_abort && !have_abort)) {
        char diagnostics[4096];
        ssize_t count;

        fprintf(stderr,
                "manager-query fixture: exit=%d calls=%u abort=%d expected=%d/%u/%d\n",
                exit_status, calls, have_abort, test_case->expected_exit,
                expected_calls, expects_abort);
        while ((count = read(helper_stderr, diagnostics, sizeof(diagnostics))) > 0) {
          if (write(STDERR_FILENO, diagnostics, (size_t)count) < 0)
            break;
        }
        while ((count = read(helper_stdout, diagnostics, sizeof(diagnostics))) > 0) {
          if (write(STDERR_FILENO, diagnostics, (size_t)count) < 0)
            break;
        }
        return -1;
      }
      return 0;
    }
    if (waited < 0) {
      perror("manager-query fixture: waitpid");
      return -1;
    }

    (void)poll(descriptors, 2, 10);
    if (!stopped_bus) {
      for (;;) {
        sd_bus_message *request = NULL;
        int processed = sd_bus_process(server, &request);

        if (processed < 0) {
          sd_bus_message_unref(request);
          if (test_case->expected_exit == 254 || calls == AOS_QUERY_CALL_COUNT) {
            sd_bus_close(server);
            stopped_bus = true;
            break;
          }
          fprintf(stderr, "manager-query fixture: server process error %d after %u calls\n",
                  processed, calls);
          return -1;
        }
        if (processed == 0)
          break;
        if (request != NULL) {
          if (sd_bus_message_is_method_call(request, NULL, NULL) == 0) {
            sd_bus_message_unref(request);
            continue;
          }
          if (aos_fixture_serve_call(server, raw_bus_fd, request, test_case,
                                     identity, calls) != 0) {
            fprintf(stderr, "manager-query fixture: rejected call %u\n", calls);
            sd_bus_message_unref(request);
            sd_bus_close(server);
            stopped_bus = true;
            break;
          }
          calls++;
          sd_bus_message_unref(request);
          if (bus_fault && calls == test_case->expected_calls) {
            sd_bus_close(server);
            stopped_bus = true;
            break;
          }
        }
      }
    }

    if (test_case->fault == AOS_FIXTURE_CONTROL_SEND_RETRY && calls == 127U &&
        !send_retry_pause_complete) {
      if (pause_for_nonblocking_retry() != 0)
        return -1;
      send_retry_pause_complete = true;
    }

    if ((descriptors[1].revents & POLLIN) != 0 &&
        (test_case->fault != AOS_FIXTURE_CONTROL_SEND_RETRY || calls >= 127U)) {
      struct aos_fixture_wire payload = {0};
      enum aos_query_phase phase;

      if (receive_phase(control_fd, child, &phase, &payload) != 0)
      {
        continue;
      }
      if (phase == AOS_QUERY_PHASE_A && !have_first && calls == 127U) {
        uint8_t continue_nonce[32];

        if (validate_phase_snapshot(&payload, identity, test_case) != 0) {
          fprintf(stderr,
                  "manager-query fixture: invalid Rust-format phase A snapshot\n");
          return -1;
        }
        first = payload;
        have_first = true;
        memcpy(continue_nonce, identity->start.nonce, sizeof(continue_nonce));
        if (test_case->fault == AOS_FIXTURE_CONTINUE_WRONG_NONCE)
          continue_nonce[0] ^= 0x80U;
        if (test_case->fault == AOS_FIXTURE_CONTINUE_RIGHTS) {
          if (send_record_with_rights(control_fd, AOS_QUERY_PHASE_CONTINUE,
                                      continue_nonce, sizeof(continue_nonce)) != 0)
            return -1;
        } else if (send_record(control_fd, AOS_QUERY_PHASE_CONTINUE,
                               continue_nonce, sizeof(continue_nonce)) != 0)
          return -1;
        if (test_case->fault == AOS_FIXTURE_CONTINUE_DUPLICATE &&
            send_record(control_fd, AOS_QUERY_PHASE_CONTINUE, continue_nonce,
                        sizeof(continue_nonce)) != 0)
          return -1;
      } else if (phase == AOS_QUERY_PHASE_B && have_first && calls == 254U &&
                 validate_phase_snapshot(&payload, identity, test_case) == 0 &&
                 payload.length == first.length &&
                 memcmp(payload.bytes, first.bytes, first.length) == 0) {
        if (send_record(control_fd, AOS_QUERY_PHASE_ACK,
                        identity->start.nonce,
                        sizeof(identity->start.nonce)) != 0)
          return -1;
      } else if (phase == AOS_QUERY_PHASE_ABORT && test_case->expected_exit == 254 &&
                 !have_abort &&
                 payload.length == 36U &&
                 memcmp(payload.bytes, identity->start.nonce,
                        sizeof(identity->start.nonce)) == 0 &&
                 load_u32be(payload.bytes + 32) == 1U) {
        have_abort = true;
        continue;
      } else {
        fprintf(stderr, "manager-query fixture: unexpected phase %u after %u calls\n",
                (unsigned int)phase, calls);
        return -1;
      }
    }
  }
}

int aos_fixture_run_case(const char *helper,
                         const struct aos_fixture_case *test_case)
{
  int bus_pair[2] = {-1, -1};
  int control_pair[2] = {-1, -1};
  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  int parent_pidfd = -1;
  pid_t child = -1;
  sd_bus *server = NULL;
  struct aos_fixture_identity identity = {0};
  int result = -1;
  int control_type = SOCK_SEQPACKET | SOCK_CLOEXEC;

  if (test_case->fault != AOS_FIXTURE_ENTRY_BLOCKING_CONTROL)
    control_type |= SOCK_NONBLOCK;

  for (size_t index = 0; index < sizeof(identity.start.nonce); index++)
    identity.start.nonce[index] = (uint8_t)(index + 1U);
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, bus_pair) != 0 ||
      socketpair(AF_UNIX, control_type, 0, control_pair) != 0 ||
      pipe2(stdout_pipe, O_CLOEXEC) != 0 || pipe2(stderr_pipe, O_CLOEXEC) != 0 ||
      configure_control(control_pair[0], true) != 0 ||
      configure_control(control_pair[1],
                        test_case->fault != AOS_FIXTURE_ENTRY_NO_PASSPIDFD) != 0)
    goto setup_fail;
  parent_pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0U);
  if (parent_pidfd < 0 ||
      spawn_helper(helper, bus_pair[1], parent_pidfd, control_pair[1], stdout_pipe[1],
                   stderr_pipe[1], test_case, &child) != 0)
    goto setup_fail;

  close(bus_pair[1]);
  bus_pair[1] = -1;
  close(control_pair[1]);
  control_pair[1] = -1;
  close(stdout_pipe[1]);
  stdout_pipe[1] = -1;
  close(stderr_pipe[1]);
  stderr_pipe[1] = -1;
  if (test_case->fault == AOS_FIXTURE_CONTROL_RECEIVE_RETRY &&
      pause_for_nonblocking_retry() != 0)
    goto setup_fail;
  if (send_start(control_pair[0], parent_pidfd, &identity, test_case) != 0 ||
      start_server(bus_pair[0], &server) != 0)
    goto setup_fail;
  bus_pair[0] = -1;

  result = exercise_case(control_pair[0], sd_bus_get_fd(server), server,
                         stdout_pipe[0], stderr_pipe[0], child, &identity,
                         test_case);
  goto out;

setup_fail:
  perror("manager-query fixture: case setup");

out:
  if (child > 0) {
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
  }
  sd_bus_unref(server);
  for (size_t index = 0; index < 2; index++) {
    if (bus_pair[index] >= 0)
      close(bus_pair[index]);
    if (control_pair[index] >= 0)
      close(control_pair[index]);
    if (stdout_pipe[index] >= 0)
      close(stdout_pipe[index]);
    if (stderr_pipe[index] >= 0)
      close(stderr_pipe[index]);
  }
  if (parent_pidfd >= 0)
    close(parent_pidfd);
  return result;
}

static int run_cases(const char *helper)
{
  for (size_t index = 0; index < aos_fixture_case_count; index++) {
    if (aos_fixture_run_case(helper, &aos_fixture_cases[index]) != 0) {
      fprintf(stderr, "manager-query fixture: case failed: %s\n",
              aos_fixture_cases[index].name);
      return 1;
    }
    printf("PASS %s\n", aos_fixture_cases[index].name);
  }
  return 0;
}

int main(int argc, char **argv)
{
  pid_t namespace_init;
  int status;

  if (argc != 2 || aos_fixture_enter_root_user_namespace() != 0 ||
      unshare(CLONE_NEWPID) != 0) {
    fprintf(stderr, "manager-query fixture: cannot establish fixture namespaces\n");
    return 1;
  }
  namespace_init = fork();
  if (namespace_init < 0)
    return 1;
  if (namespace_init == 0) {
    int result = run_cases(argv[1]);

    if (fflush(NULL) != 0)
      result = 1;
    _exit(result);
  }
  if (waitpid(namespace_init, &status, 0) != namespace_init ||
      !WIFEXITED(status))
    return 1;
  return WEXITSTATUS(status);
}
