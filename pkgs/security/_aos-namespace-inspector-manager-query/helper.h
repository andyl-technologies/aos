/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AOS_NAMESPACE_INSPECTOR_MANAGER_QUERY_HELPER_H
#define AOS_NAMESPACE_INSPECTOR_MANAGER_QUERY_HELPER_H

#define _GNU_SOURCE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <systemd/sd-bus.h>

#define AOS_QUERY_MANAGER_FD 3
#define AOS_QUERY_PARENT_PIDFD 4
#define AOS_QUERY_CONTROL_FD 5
#define AOS_QUERY_FD_LIMIT 32

#define AOS_QUERY_PROPERTY_COUNT 126U
#define AOS_QUERY_CALL_COUNT 254U
#define AOS_QUERY_MAX_SNAPSHOT (128U * 1024U)
#define AOS_QUERY_PHASE_BINDING_SIZE 84U
#define AOS_QUERY_WIRE_HEADER_SIZE 16U
#define AOS_QUERY_START_PAYLOAD_SIZE 104U
#define AOS_QUERY_NONCE_PAYLOAD_SIZE 32U
#define AOS_QUERY_ABORT_PAYLOAD_SIZE 36U
#define AOS_QUERY_MAX_CONTROL_PAYLOAD                                      \
  (AOS_QUERY_PHASE_BINDING_SIZE + AOS_QUERY_MAX_SNAPSHOT)
#define AOS_QUERY_MAX_CONTROL_RECORD                                       \
  (AOS_QUERY_WIRE_HEADER_SIZE + AOS_QUERY_MAX_CONTROL_PAYLOAD)
#define AOS_QUERY_MAX_ELEMENTS 256U
#define AOS_QUERY_MAX_TEXT 2048U
#define AOS_QUERY_MAX_ELEMENT 4096U
#define AOS_QUERY_MAX_UNIT_ID 256U
#define AOS_QUERY_MAX_INSTANCE 192U
#define AOS_QUERY_MAX_CGROUP 512U

#define AOS_QUERY_PROTOCOL_MAGIC "AOSNIMS1"
#define AOS_QUERY_PROTOCOL_VERSION 1U
#define AOS_QUERY_SNAPSHOT_KIND 2U

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif
#define AOS_SCM_PIDFD 0x04

enum aos_query_phase {
  AOS_QUERY_PHASE_START = 1,
  AOS_QUERY_PHASE_A = 2,
  AOS_QUERY_PHASE_CONTINUE = 3,
  AOS_QUERY_PHASE_B = 4,
  AOS_QUERY_PHASE_ACK = 5,
  AOS_QUERY_PHASE_ABORT = 6,
};

struct aos_query_wire_header {
  uint8_t magic[8];
  uint8_t version_be[2];
  uint8_t phase_be[2];
  uint8_t length_be[4];
};

_Static_assert(sizeof(struct aos_query_wire_header) ==
                   AOS_QUERY_WIRE_HEADER_SIZE,
               "control wire header size changed");
_Static_assert(AOS_QUERY_MAX_CONTROL_RECORD ==
                   AOS_QUERY_MAX_SNAPSHOT + 100U,
               "maximum A/B control record overhead changed");

struct aos_query_start {
  uint8_t nonce[32];
  uint64_t deadline_ns;
  uint8_t contract_digest[32];
  uint64_t ordinal;
  uint64_t cookie;
  uint32_t subject_pid;
  uint64_t subject_pidfd_inode;
  uint32_t subject_uid;
};

struct aos_query_peer {
  pid_t pid;
  uid_t uid;
  gid_t gid;
  ino_t pidfd_inode;
};

struct aos_query_buffer {
  /* The largest internal use is a complete A/B control record. */
  uint8_t bytes[AOS_QUERY_MAX_CONTROL_RECORD];
  size_t length;
};

struct aos_query_property {
  uint16_t id;
  const char *object;
  const char *interface;
  const char *name;
  const char *signature;
  const char *binding;
  const char *shape;
};

struct aos_query_context {
  struct aos_query_start start;
  struct aos_query_peer parent;
  struct timespec deadline;
  sd_bus *bus;
  const char *unit_path;
  char unit_path_storage[512];
  char unit_name[AOS_QUERY_MAX_UNIT_ID + 1U];
  char service_instance[AOS_QUERY_MAX_INSTANCE + 1U];
  uint8_t invocation_id[16];
  char socket_path[512];
  uint32_t runtime_fd_mask;
};

extern const struct aos_query_property aos_query_properties[];
extern const uint8_t aos_query_contract_digest[32];

int aos_query_validate_entry(struct aos_query_context *context);
int aos_query_set_runtime_limits(void);
int aos_query_capture_fd_table(uint32_t *mask);
int aos_query_fill_fd_table(int fillers[AOS_QUERY_FD_LIMIT], size_t *count,
                            uint32_t *prefill_mask);
int aos_query_release_fd_table(const int fillers[AOS_QUERY_FD_LIMIT],
                               size_t count, uint32_t expected_mask);

int aos_query_receive_control(struct aos_query_context *context,
                              enum aos_query_phase phase,
                              struct aos_query_buffer *payload);
int aos_query_send_control(struct aos_query_context *context,
                           enum aos_query_phase phase,
                           const struct aos_query_buffer *payload);
int aos_query_decode_start(struct aos_query_context *context,
                           const struct aos_query_buffer *payload);
int aos_query_remaining_usec(const struct aos_query_context *context,
                             uint64_t *remaining);

int aos_query_connect_bus(struct aos_query_context *context);
int aos_query_snapshot(struct aos_query_context *context,
                       struct aos_query_buffer *snapshot);
void aos_query_close_bus(struct aos_query_context *context);

int aos_query_buffer_append(struct aos_query_buffer *buffer, const void *data,
                            size_t length);
int aos_query_buffer_u8(struct aos_query_buffer *buffer, uint8_t value);
int aos_query_buffer_u16(struct aos_query_buffer *buffer, uint16_t value);
int aos_query_buffer_u32(struct aos_query_buffer *buffer, uint32_t value);
int aos_query_buffer_u64(struct aos_query_buffer *buffer, uint64_t value);
int aos_query_buffer_u16le(struct aos_query_buffer *buffer, uint16_t value);
int aos_query_buffer_u32le(struct aos_query_buffer *buffer, uint32_t value);
int aos_query_buffer_u64le(struct aos_query_buffer *buffer, uint64_t value);
int aos_query_buffer_text_le(struct aos_query_buffer *buffer, const char *text);

#endif
