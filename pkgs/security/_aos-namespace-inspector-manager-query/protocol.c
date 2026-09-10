/* SPDX-License-Identifier: Apache-2.0 */
#include "helper.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PIDFD_GET_INFO 0xc048ff0b
#define PIDFD_INFO_PID (1ULL << 0)

struct aos_control_pidfd_info {
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

static void store_u32(uint8_t *bytes, uint32_t value)
{
  bytes[0] = (uint8_t)(value >> 24U);
  bytes[1] = (uint8_t)(value >> 16U);
  bytes[2] = (uint8_t)(value >> 8U);
  bytes[3] = (uint8_t)value;
}

static void store_u64(uint8_t *bytes, uint64_t value)
{
  for (size_t index = 0; index < 8; index++) {
    bytes[7 - index] = (uint8_t)value;
    value >>= 8U;
  }
}

static void store_u16le(uint8_t *bytes, uint16_t value)
{
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
}

static void store_u32le(uint8_t *bytes, uint32_t value)
{
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
  bytes[2] = (uint8_t)(value >> 16U);
  bytes[3] = (uint8_t)(value >> 24U);
}

static void store_u64le(uint8_t *bytes, uint64_t value)
{
  for (size_t index = 0; index < 8; index++) {
    bytes[index] = (uint8_t)value;
    value >>= 8U;
  }
}

static int poll_control(const struct aos_query_context *context, short events)
{
  struct pollfd descriptor = {
      .fd = AOS_QUERY_CONTROL_FD,
      .events = events,
  };
  uint64_t remaining;

  if (aos_query_remaining_usec(context, &remaining) != 0)
    return -1;
  if (ppoll(&descriptor, 1,
            &(struct timespec){
                .tv_sec = (time_t)(remaining / 1000000U),
                .tv_nsec = (long)(remaining % 1000000U) * 1000L,
            },
            NULL) != 1)
    return -1;
  return (descriptor.revents & events) != 0 ? 0 : -1;
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

static int incoming_payload_length(enum aos_query_phase phase, size_t *length)
{
  switch (phase) {
  case AOS_QUERY_PHASE_START:
    *length = AOS_QUERY_START_PAYLOAD_SIZE;
    return 0;
  case AOS_QUERY_PHASE_CONTINUE:
  case AOS_QUERY_PHASE_ACK:
    *length = AOS_QUERY_NONCE_PAYLOAD_SIZE;
    return 0;
  default:
    return -1;
  }
}

static int valid_outgoing_payload(enum aos_query_phase phase, size_t length)
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

static int validate_pidfd(const struct aos_query_context *context, int pidfd)
{
  struct aos_control_pidfd_info info = {.mask = PIDFD_INFO_PID};
  struct stat status;

  if (ioctl(pidfd, PIDFD_GET_INFO, &info) != 0 ||
      (info.mask & PIDFD_INFO_PID) == 0 || info.pid != (uint32_t)context->parent.pid ||
      info.euid != context->parent.uid || fstat(pidfd, &status) != 0 ||
      status.st_ino != context->parent.pidfd_inode)
    return -1;
  return 0;
}

static int receive_record(struct aos_query_context *context,
                          struct aos_query_buffer *record)
{
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
  } control;
  struct iovec iovec = {
      .iov_base = record->bytes,
      .iov_len = sizeof(record->bytes),
  };
  struct msghdr message = {
      .msg_iov = &iovec,
      .msg_iovlen = 1,
      .msg_control = control.bytes,
      .msg_controllen = sizeof(control.bytes),
  };
  struct ucred credentials = {0};
  bool have_credentials = false;
  bool have_pidfd = false;
  int received_pidfd = -1;
  ssize_t length;
  int result = -1;

  for (;;) {
    message.msg_controllen = sizeof(control.bytes);
    message.msg_flags = 0;
    length = recvmsg(AOS_QUERY_CONTROL_FD, &message,
                     MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (length >= 0)
      break;
    if (errno != EAGAIN && errno != EWOULDBLOCK)
      return -1;
    if (poll_control(context, POLLIN) != 0)
      return -1;
  }
  if (length <= 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
    goto out;

  for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET)
      goto out;
    if (header->cmsg_type == SCM_CREDENTIALS &&
        header->cmsg_len == CMSG_LEN(sizeof(credentials)) &&
        !have_credentials) {
      memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
      have_credentials = true;
    } else if (header->cmsg_type == AOS_SCM_PIDFD &&
               header->cmsg_len == CMSG_LEN(sizeof(received_pidfd)) &&
               !have_pidfd) {
      memcpy(&received_pidfd, CMSG_DATA(header), sizeof(received_pidfd));
      have_pidfd = true;
    } else {
      goto out;
    }
  }
  if (!have_credentials || !have_pidfd ||
      credentials.pid != context->parent.pid ||
      credentials.uid != context->parent.uid ||
      credentials.gid != context->parent.gid ||
      validate_pidfd(context, received_pidfd) != 0)
    goto out;

  record->length = (size_t)length;
  result = 0;

out:
  /* recvmsg installs exposed descriptor cmsgs even when ancillary data
   * truncates, so every post-receive path owns this cleanup. */
  close_received_fds(&message);
  return result;
}

int aos_query_receive_control(struct aos_query_context *context,
                              enum aos_query_phase phase,
                              struct aos_query_buffer *payload)
{
  struct aos_query_buffer record = {0};
  struct aos_query_wire_header *header;
  size_t expected_length;
  uint8_t queued;

  if (incoming_payload_length(phase, &expected_length) != 0 ||
      receive_record(context, &record) != 0 ||
      record.length != sizeof(struct aos_query_wire_header) + expected_length)
    return -1;
  header = (struct aos_query_wire_header *)record.bytes;
  if (memcmp(header->magic, AOS_QUERY_PROTOCOL_MAGIC, sizeof(header->magic)) != 0 ||
      load_u16(header->version_be) != AOS_QUERY_PROTOCOL_VERSION ||
      load_u16(header->phase_be) != phase ||
      load_u32(header->length_be) != expected_length)
    return -1;

  payload->length = expected_length;
  memcpy(payload->bytes, record.bytes + sizeof(*header), payload->length);
  if (recv(AOS_QUERY_CONTROL_FD, &queued, sizeof(queued),
           MSG_PEEK | MSG_DONTWAIT) >= 0 ||
      (errno != EAGAIN && errno != EWOULDBLOCK))
    return -1;
  return 0;
}

int aos_query_send_control(struct aos_query_context *context,
                           enum aos_query_phase phase,
                           const struct aos_query_buffer *payload)
{
  struct aos_query_buffer record = {0};
  struct aos_query_wire_header header = {0};
  ssize_t written;

  if (valid_outgoing_payload(phase, payload->length) != 0 ||
      payload->length > UINT32_MAX)
    return -1;
  memcpy(header.magic, AOS_QUERY_PROTOCOL_MAGIC, sizeof(header.magic));
  store_u16(header.version_be, AOS_QUERY_PROTOCOL_VERSION);
  store_u16(header.phase_be, (uint16_t)phase);
  store_u32(header.length_be, (uint32_t)payload->length);
  if (aos_query_buffer_append(&record, &header, sizeof(header)) != 0 ||
      aos_query_buffer_append(&record, payload->bytes, payload->length) != 0)
    return -1;

  for (;;) {
    written = send(AOS_QUERY_CONTROL_FD, record.bytes, record.length,
                   MSG_DONTWAIT | MSG_NOSIGNAL);
    if (written == (ssize_t)record.length)
      return 0;
    if (written >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
      return -1;
    if (poll_control(context, POLLOUT) != 0)
      return -1;
  }
}

int aos_query_decode_start(struct aos_query_context *context,
                           const struct aos_query_buffer *payload)
{
  const uint8_t *cursor = payload->bytes;
  struct timespec now;
  uint64_t now_ns;

  if (payload->length != AOS_QUERY_START_PAYLOAD_SIZE)
    return -1;
  memcpy(context->start.nonce, cursor, 32);
  cursor += 32;
  context->start.deadline_ns = load_u64(cursor);
  cursor += 8;
  memcpy(context->start.contract_digest, cursor, 32);
  cursor += 32;
  context->start.ordinal = load_u64(cursor);
  cursor += 8;
  context->start.cookie = load_u64(cursor);
  cursor += 8;
  context->start.subject_pid = load_u32(cursor);
  cursor += 4;
  context->start.subject_pidfd_inode = load_u64(cursor);
  cursor += 8;
  context->start.subject_uid = load_u32(cursor);

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return -1;
  now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
  if (context->start.deadline_ns <= now_ns ||
      context->start.deadline_ns - now_ns > UINT64_C(1000000000) ||
      memcmp(context->start.contract_digest, aos_query_contract_digest, 32) != 0 ||
      context->start.subject_pid != (uint32_t)context->parent.pid ||
      context->start.subject_pidfd_inode != context->parent.pidfd_inode ||
      context->start.subject_uid != context->parent.uid)
    return -1;

  context->deadline.tv_sec = (time_t)(context->start.deadline_ns / UINT64_C(1000000000));
  context->deadline.tv_nsec = (long)(context->start.deadline_ns % UINT64_C(1000000000));
  return 0;
}

int aos_query_remaining_usec(const struct aos_query_context *context,
                             uint64_t *remaining)
{
  struct timespec now;
  uint64_t deadline_ns;
  uint64_t now_ns;
  uint64_t difference;

  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return -1;
  deadline_ns = (uint64_t)context->deadline.tv_sec * UINT64_C(1000000000) +
                (uint64_t)context->deadline.tv_nsec;
  now_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
  if (now_ns >= deadline_ns)
    return -1;
  difference = deadline_ns - now_ns;
  if (difference < 1000U)
    return -1;
  *remaining = (difference + 999U) / 1000U;
  return 0;
}

int aos_query_buffer_append(struct aos_query_buffer *buffer, const void *data,
                            size_t length)
{
  if (buffer->length > sizeof(buffer->bytes) ||
      length > sizeof(buffer->bytes) - buffer->length)
    return -1;
  if (length == 0)
    return 0;
  memcpy(buffer->bytes + buffer->length, data, length);
  buffer->length += length;
  return 0;
}

int aos_query_buffer_u8(struct aos_query_buffer *buffer, uint8_t value)
{
  return aos_query_buffer_append(buffer, &value, sizeof(value));
}

int aos_query_buffer_u16(struct aos_query_buffer *buffer, uint16_t value)
{
  uint8_t bytes[2];

  store_u16(bytes, value);
  return aos_query_buffer_append(buffer, bytes, sizeof(bytes));
}

int aos_query_buffer_u32(struct aos_query_buffer *buffer, uint32_t value)
{
  uint8_t bytes[4];

  store_u32(bytes, value);
  return aos_query_buffer_append(buffer, bytes, sizeof(bytes));
}

int aos_query_buffer_u64(struct aos_query_buffer *buffer, uint64_t value)
{
  uint8_t bytes[8];

  store_u64(bytes, value);
  return aos_query_buffer_append(buffer, bytes, sizeof(bytes));
}

int aos_query_buffer_u16le(struct aos_query_buffer *buffer, uint16_t value)
{
  uint8_t bytes[2];

  store_u16le(bytes, value);
  return aos_query_buffer_append(buffer, bytes, sizeof(bytes));
}

int aos_query_buffer_u32le(struct aos_query_buffer *buffer, uint32_t value)
{
  uint8_t bytes[4];

  store_u32le(bytes, value);
  return aos_query_buffer_append(buffer, bytes, sizeof(bytes));
}

int aos_query_buffer_u64le(struct aos_query_buffer *buffer, uint64_t value)
{
  uint8_t bytes[8];

  store_u64le(bytes, value);
  return aos_query_buffer_append(buffer, bytes, sizeof(bytes));
}

int aos_query_buffer_text_le(struct aos_query_buffer *buffer, const char *text)
{
  size_t length = strlen(text);

  if (length > AOS_QUERY_MAX_TEXT || length > UINT16_MAX ||
      aos_query_buffer_u16le(buffer, (uint16_t)length) != 0)
    return -1;
  return aos_query_buffer_append(buffer, text, length);
}
