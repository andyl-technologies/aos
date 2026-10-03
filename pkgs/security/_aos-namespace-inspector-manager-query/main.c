/* SPDX-License-Identifier: Apache-2.0 */
#include "helper.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

extern char **environ;

#ifndef AOS_MANAGER_QUERY_PROGRAM
#error "AOS_MANAGER_QUERY_PROGRAM must name the installed helper"
#endif

int aos_query_run_worker_mode(int argc, char **argv);

static int phase_payload(const struct aos_query_context *context,
                         const struct aos_query_buffer *snapshot,
                         struct aos_query_buffer *payload)
{
  if (payload->length != 0 || snapshot->length > AOS_QUERY_MAX_SNAPSHOT ||
      snapshot->length > UINT32_MAX)
    return -1;
  if (aos_query_buffer_append(payload, context->start.nonce,
                              sizeof(context->start.nonce)) != 0 ||
      aos_query_buffer_append(payload, aos_query_schema_digest,
                              sizeof(aos_query_schema_digest)) != 0 ||
      aos_query_buffer_u64(payload, context->start.ordinal) != 0 ||
      aos_query_buffer_u64(payload, context->start.cookie) != 0 ||
      aos_query_buffer_u32(payload, (uint32_t)snapshot->length) != 0 ||
      aos_query_buffer_append(payload, snapshot->bytes, snapshot->length) != 0)
    return -1;
  if (payload->length != AOS_QUERY_PHASE_BINDING_SIZE + snapshot->length)
    return -1;
  return 0;
}

static int nonce_record(const struct aos_query_context *context,
                        const struct aos_query_buffer *payload)
{
  if (payload->length != AOS_QUERY_NONCE_PAYLOAD_SIZE ||
      memcmp(payload->bytes, context->start.nonce,
             sizeof(context->start.nonce)) != 0)
    return -1;
  return 0;
}

static void send_abort(struct aos_query_context *context)
{
  struct aos_query_buffer payload = {0};

  if (aos_query_buffer_append(&payload, context->start.nonce,
                              sizeof(context->start.nonce)) != 0 ||
      aos_query_buffer_u32(&payload, 1) != 0)
    return;
  (void)aos_query_send_control(context, AOS_QUERY_PHASE_ABORT, &payload);
}

static int run_query(void)
{
  struct aos_query_context context = {0};
  struct aos_query_buffer control = {0};
  struct aos_query_buffer first = {0};
  struct aos_query_buffer second = {0};
  struct aos_query_buffer first_phase = {0};
  struct aos_query_buffer second_phase = {0};
  bool start_bound = false;
  int result = -1;

  if (clock_gettime(CLOCK_MONOTONIC, &context.deadline) != 0)
    return -1;
  context.deadline.tv_sec++;

  if (aos_query_validate_entry(&context) != 0 ||
      aos_query_receive_control(&context, AOS_QUERY_PHASE_START, &control) != 0 ||
      aos_query_decode_start(&context, &control) != 0)
    goto out;
  start_bound = true;

  if (aos_query_set_runtime_limits() != 0 || aos_query_connect_bus(&context) != 0 ||
      aos_query_snapshot(&context, &first) != 0 ||
      phase_payload(&context, &first, &first_phase) != 0 ||
      aos_query_send_control(&context, AOS_QUERY_PHASE_A, &first_phase) != 0)
    goto out;

  if (aos_query_receive_control(&context, AOS_QUERY_PHASE_CONTINUE, &control) != 0 ||
      nonce_record(&context, &control) != 0 ||
      aos_query_snapshot(&context, &second) != 0 ||
      phase_payload(&context, &second, &second_phase) != 0 ||
      aos_query_send_control(&context, AOS_QUERY_PHASE_B, &second_phase) != 0)
    goto out;
  if (first.length != second.length ||
      memcmp(first.bytes, second.bytes, first.length) != 0)
    goto out;

  if (aos_query_receive_control(&context, AOS_QUERY_PHASE_ACK, &control) != 0 ||
      nonce_record(&context, &control) != 0)
    goto out;

  result = 0;

out:
  aos_query_close_bus(&context);
  if (result != 0 && start_bound)
    send_abort(&context);
  return result;
}

int main(int argc, char **argv)
{
  uint32_t descriptors;

  if (argc != 1 || argv == NULL || argv[0] == NULL || argv[1] != NULL ||
      strcmp(argv[0], AOS_MANAGER_QUERY_PROGRAM) != 0 || environ == NULL ||
      environ[0] != NULL)
    return 254;
  if (aos_query_capture_fd_table(&descriptors) != 0)
    return 254;
  /* The extra retained worker pidfd places the executable at FD 7. Each mode
   * then validates its own complete descriptor and capability contract. */
  if (descriptors == 0xffU)
    return aos_query_run_worker_mode(argc, argv);
  return run_query() == 0 ? 0 : 254;
}
