/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AOS_NAMESPACE_INSPECTOR_MANAGER_QUERY_FIXTURE_H
#define AOS_NAMESPACE_INSPECTOR_MANAGER_QUERY_FIXTURE_H

#define _GNU_SOURCE

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <systemd/sd-bus.h>

#include "helper.h"

#define AOS_FIXTURE_BOUNDARY_PROPERTY_ID 9U
#define AOS_FIXTURE_BOUNDARY_ELEMENT_COUNT 64U
#define AOS_FIXTURE_BOUNDARY_ELEMENT_LENGTH 1986U
#define AOS_FIXTURE_BOUNDARY_FINAL_LENGTH 2002U
#define AOS_FIXTURE_BOUNDARY_REMAINDER 3691U

/* The known canonical remainder plus property 9 fills AOSNIMS1 exactly. */
_Static_assert(AOS_FIXTURE_BOUNDARY_REMAINDER + 3U + 2U +
                       AOS_FIXTURE_BOUNDARY_ELEMENT_COUNT * 4U +
                       (AOS_FIXTURE_BOUNDARY_ELEMENT_COUNT - 1U) *
                           AOS_FIXTURE_BOUNDARY_ELEMENT_LENGTH +
                       AOS_FIXTURE_BOUNDARY_FINAL_LENGTH ==
                   AOS_QUERY_MAX_SNAPSHOT,
               "boundary snapshot fixture no longer fills 128 KiB");

enum aos_fixture_fault {
  AOS_FIXTURE_SUCCESS,
  AOS_FIXTURE_RIGHTS_FIRST_UNIT,
  AOS_FIXTURE_RIGHTS_MIDDLE_PROPERTY,
  AOS_FIXTURE_RIGHTS_SECOND_UNIT,
  AOS_FIXTURE_RIGHTS_LAST_PROPERTY,
  AOS_FIXTURE_RAW_UNIT_NO_FD,
  AOS_FIXTURE_RAW_PROPERTY_NO_FD,
  AOS_FIXTURE_UNIT_INVOCATION_WRONG_LENGTH,
  AOS_FIXTURE_UNIT_INVOCATION_ZERO,
  AOS_FIXTURE_PROPERTY_SOCKET_INVOCATION_ZERO,
  AOS_FIXTURE_PROPERTY_UNIT_ID_MISMATCH,
  AOS_FIXTURE_PROPERTY_INVOCATION_MISMATCH,
  AOS_FIXTURE_PROPERTY_EMPTY_CONTROL_GROUP,
  AOS_FIXTURE_PROPERTY_ZERO_CONTROL_GROUP_ID,
  AOS_FIXTURE_PROPERTY_ZERO_MAIN_PID,
  AOS_FIXTURE_DUPLICATE_UNORDERED_SET,
  AOS_FIXTURE_INVALID_MANAGER_ENVIRONMENT,
  AOS_FIXTURE_DUPLICATE_MANAGER_ENVIRONMENT_NAME,
  AOS_FIXTURE_WRONG_PROPERTY,
  AOS_FIXTURE_TRAILING_VARIANT,
  AOS_FIXTURE_OVERSIZE_TEXT,
  AOS_FIXTURE_OVERSIZE_ARRAY,
  AOS_FIXTURE_MAXIMUM_SNAPSHOT,
  AOS_FIXTURE_OVERSIZE_SNAPSHOT,
  AOS_FIXTURE_WRONG_UNIT_IDENTITY,
  AOS_FIXTURE_WRONG_UNIT_PATH,
  AOS_FIXTURE_DECLARED_FD_MISSING,
  AOS_FIXTURE_STALLED_REPLY,
  AOS_FIXTURE_ENTRY_EXTRA_FD,
  AOS_FIXTURE_ENTRY_BLOCKING_CONTROL,
  AOS_FIXTURE_ENTRY_NO_PASSPIDFD,
  AOS_FIXTURE_ENTRY_BAD_PIDFD,
  AOS_FIXTURE_ENTRY_LOW_NOFILE,
  AOS_FIXTURE_ENTRY_NONEMPTY_ENV,
  AOS_FIXTURE_START_PAST_DEADLINE,
  AOS_FIXTURE_START_LONG_DEADLINE,
  AOS_FIXTURE_START_WRONG_DIGEST,
  AOS_FIXTURE_START_WRONG_SUBJECT,
  AOS_FIXTURE_START_MIN_IDENTITY,
  AOS_FIXTURE_START_MAX_IDENTITY,
  AOS_FIXTURE_CONTINUE_WRONG_NONCE,
  AOS_FIXTURE_CONTINUE_DUPLICATE,
  AOS_FIXTURE_CONTINUE_RIGHTS,
};

struct aos_fixture_case {
  const char *name;
  enum aos_fixture_fault fault;
  unsigned int fault_call;
  unsigned int expected_calls;
  int expected_exit;
};

struct aos_fixture_wire {
  uint8_t bytes[AOS_QUERY_MAX_CONTROL_RECORD];
  size_t length;
};

struct aos_fixture_identity {
  struct aos_query_start start;
  uint8_t invocation_id[16];
  char service_instance[AOS_QUERY_MAX_INSTANCE + 1U];
  char service_name[AOS_QUERY_MAX_UNIT_ID + 1U];
  char service_path[512];
  char socket_path[512];
};

extern const struct aos_fixture_case aos_fixture_cases[];
extern const size_t aos_fixture_case_count;

int aos_fixture_run_case(const char *helper,
                         const struct aos_fixture_case *test_case);
int aos_fixture_serve_call(sd_bus *bus, int raw_bus_fd,
                           sd_bus_message *request,
                           const struct aos_fixture_case *test_case,
                           const struct aos_fixture_identity *identity,
                           unsigned int call_index);
int aos_fixture_prepare_identity(struct aos_fixture_identity *identity);
int aos_fixture_enter_root_user_namespace(void);

int aos_fixture_wire_append(struct aos_fixture_wire *wire, const void *data,
                            size_t length);
int aos_fixture_wire_u8(struct aos_fixture_wire *wire, uint8_t value);
int aos_fixture_wire_u16le(struct aos_fixture_wire *wire, uint16_t value);
int aos_fixture_wire_u32le(struct aos_fixture_wire *wire, uint32_t value);
int aos_fixture_wire_u64le(struct aos_fixture_wire *wire, uint64_t value);
int aos_fixture_wire_align(struct aos_fixture_wire *wire, size_t alignment);

#endif
