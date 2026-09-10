/* SPDX-License-Identifier: Apache-2.0 */
#include "helper.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define AOS_SYSTEMD_V259_PROPERTY(id, object, interface, property, signature,  \
                                  binding, shape)                              \
  {id, #object, #interface, property, signature, #binding, #shape},
const struct aos_query_property aos_query_properties[] = {
#include "systemd_v259_properties.def"
};
#undef AOS_SYSTEMD_V259_PROPERTY

_Static_assert(sizeof(aos_query_properties) / sizeof(aos_query_properties[0]) ==
                   AOS_QUERY_PROPERTY_COUNT,
               "systemd 259 property manifest count changed");

const uint8_t aos_query_contract_digest[32] = {
    116, 242, 223, 173, 18, 235, 224, 170, 160, 88, 155, 79, 88, 28, 110, 116,
    19,  12,  27,  31,  143, 150, 14,  25,  153, 188, 92, 134, 151, 138, 20, 154,
};

struct query_reply {
  sd_bus_message *message;
  int callback_result;
  bool complete;
};

struct snapshot_observation {
  char control_group[AOS_QUERY_MAX_CGROUP + 1U];
  uint64_t control_group_id;
  uint32_t main_pid;
  uint8_t correlations;
};

struct property_decode {
  const struct aos_query_property *property;
  struct aos_query_buffer *output;
  struct snapshot_observation *observation;
};

enum snapshot_correlation {
  CORRELATED_UNIT_ID = 1U << 0,
  CORRELATED_INVOCATION_ID = 1U << 1,
  CORRELATED_CONTROL_GROUP = 1U << 2,
  CORRELATED_CONTROL_GROUP_ID = 1U << 3,
  CORRELATED_MAIN_PID = 1U << 4,
  CORRELATED_ALL = (1U << 5) - 1U,
};

typedef int (*reply_decoder)(struct aos_query_context *context,
                             sd_bus_message *message, void *userdata);

static int query_callback(sd_bus_message *message, void *userdata,
                          sd_bus_error *error)
{
  struct query_reply *reply = userdata;

  (void)error;
  reply->message = sd_bus_message_ref(message);
  reply->callback_result = sd_bus_message_is_method_error(message, NULL) ? -1 : 0;
  reply->complete = true;
  return 1;
}

static int wait_bus(const struct aos_query_context *context, short events)
{
  struct pollfd descriptor = {
      .fd = AOS_QUERY_MANAGER_FD,
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
  return (descriptor.revents & (events | POLLERR | POLLHUP)) != 0 ? 0 : -1;
}

static int process_until_ready(struct aos_query_context *context)
{
  while (sd_bus_is_ready(context->bus) == 0) {
    int processed = sd_bus_process(context->bus, NULL);

    if (processed < 0)
      return -1;
    if (aos_query_remaining_usec(context, &(uint64_t){0}) != 0)
      return -1;
    if (processed == 0) {
      int events = sd_bus_get_events(context->bus);

      if (events < 0 || wait_bus(context, (short)events) != 0)
        return -1;
    }
  }
  return 0;
}

static int append_text(struct aos_query_buffer *output, const char *value)
{
  size_t length;

  if (value == NULL)
    return -1;
  length = strnlen(value, AOS_QUERY_MAX_TEXT + 1U);
  if (length > AOS_QUERY_MAX_TEXT || length > UINT16_MAX ||
      aos_query_buffer_u16le(output, (uint16_t)length) != 0)
    return -1;
  return aos_query_buffer_append(output, value, length);
}

static int append_raw_text(struct aos_query_buffer *output, const char *value)
{
  size_t length;

  if (value == NULL)
    return -1;
  length = strnlen(value, AOS_QUERY_MAX_TEXT + 1U);
  if (length > AOS_QUERY_MAX_TEXT)
    return -1;
  return aos_query_buffer_append(output, value, length);
}

static int append_blob(struct aos_query_buffer *output, const void *bytes,
                       size_t length)
{
  if (length > AOS_QUERY_MAX_ELEMENT || length > UINT32_MAX ||
      aos_query_buffer_u32le(output, (uint32_t)length) != 0)
    return -1;
  return aos_query_buffer_append(output, bytes, length);
}

static int compare_strings(const void *left, const void *right)
{
  const char *const *left_string = left;
  const char *const *right_string = right;

  return strcmp(*left_string, *right_string);
}

static int read_string_values(sd_bus_message *message,
                              const char *values[AOS_QUERY_MAX_ELEMENTS],
                              unsigned int *count, bool unordered)
{
  unsigned int used = 0;
  int result;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "s") <= 0)
    return -1;
  for (;;) {
    const char *value = NULL;

    result = sd_bus_message_read(message, "s", &value);
    if (result < 0)
      return -1;
    if (result == 0)
      break;
    if (used >= AOS_QUERY_MAX_ELEMENTS || value == NULL ||
        strnlen(value, AOS_QUERY_MAX_TEXT + 1U) > AOS_QUERY_MAX_TEXT)
      return -1;
    values[used++] = value;
  }
  if (sd_bus_message_exit_container(message) < 0)
    return -1;
  if (unordered)
    qsort(values, used, sizeof(values[0]), compare_strings);
  for (unsigned int index = 1; unordered && index < used; index++) {
    if (strcmp(values[index - 1], values[index]) == 0)
      return -1;
  }

  *count = used;
  return 0;
}

static bool valid_environment_name(const char *value, size_t length)
{
  if (length == 0 ||
      !((value[0] >= 'a' && value[0] <= 'z') ||
        (value[0] >= 'A' && value[0] <= 'Z') || value[0] == '_'))
    return false;
  for (size_t index = 1; index < length; index++) {
    if (!((value[index] >= 'a' && value[index] <= 'z') ||
          (value[index] >= 'A' && value[index] <= 'Z') ||
          (value[index] >= '0' && value[index] <= '9') ||
          value[index] == '_'))
      return false;
  }
  return true;
}

static int validate_environment(const char *values[AOS_QUERY_MAX_ELEMENTS],
                                unsigned int count)
{
  const char *previous = NULL;
  size_t previous_length = 0;

  for (unsigned int index = 0; index < count; index++) {
    const char *separator = strchr(values[index], '=');
    size_t name_length;

    if (separator == NULL)
      return -1;
    name_length = (size_t)(separator - values[index]);
    if (!valid_environment_name(values[index], name_length) ||
        (previous != NULL && previous_length == name_length &&
         memcmp(previous, values[index], name_length) == 0))
      return -1;
    previous = values[index];
    previous_length = name_length;
  }
  return 0;
}

static int read_string_array(sd_bus_message *message,
                             struct aos_query_buffer *output, bool unordered,
                             bool environment)
{
  const char *values[AOS_QUERY_MAX_ELEMENTS];
  unsigned int count;

  if (read_string_values(message, values, &count, unordered) != 0 ||
      (environment && validate_environment(values, count) != 0) ||
      aos_query_buffer_u16le(output, (uint16_t)count) != 0)
    return -1;
  for (unsigned int index = 0; index < count; index++) {
    size_t length = strlen(values[index]);

    if (append_blob(output, values[index], length) != 0)
      return -1;
  }
  return 0;
}

static int read_nested_string_array(sd_bus_message *message,
                                    struct aos_query_buffer *output,
                                    bool unordered)
{
  const char *values[AOS_QUERY_MAX_ELEMENTS];
  unsigned int count;

  if (read_string_values(message, values, &count, unordered) != 0 ||
      aos_query_buffer_u16le(output, (uint16_t)count) != 0)
    return -1;
  for (unsigned int index = 0; index < count; index++) {
    if (append_text(output, values[index]) != 0)
      return -1;
  }
  return 0;
}

static int read_byte_array(sd_bus_message *message,
                           struct aos_query_buffer *output)
{
  const void *bytes = NULL;
  size_t length = 0;

  if (sd_bus_message_read_array(message, SD_BUS_TYPE_BYTE, &bytes, &length) <= 0 ||
      length > AOS_QUERY_MAX_ELEMENT ||
      aos_query_buffer_append(output, bytes, length) != 0)
    return -1;
  return 0;
}

static int read_string_bool_array(sd_bus_message *message,
                                  struct aos_query_buffer *output)
{
  struct aos_query_buffer values = {0};
  unsigned int count = 0;
  int result;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "(sb)") <= 0)
    return -1;
  for (;;) {
    struct aos_query_buffer element = {0};
    const char *value = NULL;
    int boolean;

    result = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "sb");
    if (result < 0)
      return -1;
    if (result == 0)
      break;
    if (count >= AOS_QUERY_MAX_ELEMENTS ||
        sd_bus_message_read(message, "sb", &value, &boolean) <= 0 ||
        append_text(&element, value) != 0 ||
        aos_query_buffer_u8(&element, boolean != 0) != 0 ||
        append_blob(&values, element.bytes, element.length) != 0 ||
        sd_bus_message_exit_container(message) < 0)
      return -1;
    count++;
  }
  if (sd_bus_message_exit_container(message) < 0 ||
      aos_query_buffer_u16le(output, (uint16_t)count) != 0 ||
      aos_query_buffer_append(output, values.bytes, values.length) != 0)
    return -1;
  return 0;
}

static int read_string_pair_array(sd_bus_message *message,
                                  struct aos_query_buffer *output)
{
  struct aos_query_buffer values = {0};
  unsigned int count = 0;
  int result;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, "(ss)") <= 0)
    return -1;
  for (;;) {
    struct aos_query_buffer element = {0};
    const char *first = NULL;
    const char *second = NULL;

    result = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "ss");
    if (result < 0)
      return -1;
    if (result == 0)
      break;
    if (count >= AOS_QUERY_MAX_ELEMENTS ||
        sd_bus_message_read(message, "ss", &first, &second) <= 0 ||
        append_text(&element, first) != 0 || append_text(&element, second) != 0 ||
        append_blob(&values, element.bytes, element.length) != 0 ||
        sd_bus_message_exit_container(message) < 0)
      return -1;
    count++;
  }
  if (sd_bus_message_exit_container(message) < 0 ||
      aos_query_buffer_u16le(output, (uint16_t)count) != 0 ||
      aos_query_buffer_append(output, values.bytes, values.length) != 0)
    return -1;
  return 0;
}

static int read_exec_array(sd_bus_message *message,
                           struct aos_query_buffer *output, bool extended)
{
  const char *contents = extended ? "(sasasttttuii)" : "(sasbttttuii)";
  const char *fields = extended ? "sasasttttuii" : "sasbttttuii";
  struct aos_query_buffer values = {0};
  unsigned int count = 0;
  int result;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_ARRAY, contents) <= 0)
    return -1;
  for (;;) {
    struct aos_query_buffer element = {0};
    const char *path = NULL;
    uint64_t timestamps[4];
    uint32_t pid;
    int32_t code;
    int32_t status;

    result = sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, fields);
    if (result < 0)
      return -1;
    if (result == 0)
      break;
    if (count >= AOS_QUERY_MAX_ELEMENTS ||
        sd_bus_message_read(message, "s", &path) <= 0 ||
        append_text(&element, path) != 0 ||
        read_nested_string_array(message, &element, false) != 0)
      return -1;
    if (extended) {
      if (read_nested_string_array(message, &element, true) != 0)
        return -1;
    } else {
      int ignore_errors;

      if (sd_bus_message_read(message, "b", &ignore_errors) <= 0 ||
          aos_query_buffer_u8(&element, ignore_errors != 0) != 0)
        return -1;
    }
    if (sd_bus_message_read(message, "ttttuii", &timestamps[0], &timestamps[1],
                            &timestamps[2], &timestamps[3], &pid, &code,
                            &status) <= 0 ||
        aos_query_buffer_u64le(&element, timestamps[0]) != 0 ||
        aos_query_buffer_u64le(&element, timestamps[1]) != 0 ||
        aos_query_buffer_u64le(&element, timestamps[2]) != 0 ||
        aos_query_buffer_u64le(&element, timestamps[3]) != 0 ||
        aos_query_buffer_u32le(&element, pid) != 0 ||
        aos_query_buffer_u32le(&element, (uint32_t)code) != 0 ||
        aos_query_buffer_u32le(&element, (uint32_t)status) != 0 ||
        append_blob(&values, element.bytes, element.length) != 0 ||
        sd_bus_message_exit_container(message) < 0)
      return -1;
    count++;
  }
  if (sd_bus_message_exit_container(message) < 0 ||
      aos_query_buffer_u16le(output, (uint16_t)count) != 0 ||
      aos_query_buffer_append(output, values.bytes, values.length) != 0)
    return -1;
  return 0;
}

static int decode_variant_value(sd_bus_message *message,
                                const struct aos_query_property *property,
                                struct aos_query_buffer *output)
{
  const char *signature = property->signature;

  if (strcmp(signature, "s") == 0) {
    const char *value = NULL;

    return sd_bus_message_read(message, "s", &value) > 0
               ? append_raw_text(output, value)
               : -1;
  }
  if (strcmp(signature, "b") == 0) {
    int value;

    return sd_bus_message_read(message, "b", &value) > 0
               ? aos_query_buffer_u8(output, value != 0)
               : -1;
  }
  if (strcmp(signature, "u") == 0) {
    uint32_t value;

    return sd_bus_message_read(message, "u", &value) > 0
               ? aos_query_buffer_u32le(output, value)
               : -1;
  }
  if (strcmp(signature, "i") == 0) {
    int32_t value;

    return sd_bus_message_read(message, "i", &value) > 0
               ? aos_query_buffer_u32le(output, (uint32_t)value)
               : -1;
  }
  if (strcmp(signature, "t") == 0) {
    uint64_t value;

    return sd_bus_message_read(message, "t", &value) > 0
               ? aos_query_buffer_u64le(output, value)
               : -1;
  }
  if (strcmp(signature, "ay") == 0)
    return read_byte_array(message, output);
  if (strcmp(signature, "as") == 0)
    return read_string_array(message, output,
                             strcmp(property->shape, "UNORDERED_SET") == 0,
                             property->id == 0);
  if (strcmp(signature, "a(sb)") == 0)
    return read_string_bool_array(message, output);
  if (strcmp(signature, "a(ss)") == 0)
    return read_string_pair_array(message, output);
  if (strcmp(signature, "a(sasbttttuii)") == 0)
    return read_exec_array(message, output, false);
  if (strcmp(signature, "a(sasasttttuii)") == 0)
    return read_exec_array(message, output, true);
  if (strcmp(signature, "(uo)") == 0) {
    uint32_t number;
    const char *path = NULL;

    if (sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "uo") <= 0 ||
        sd_bus_message_read(message, "uo", &number, &path) <= 0 ||
        aos_query_buffer_u32le(output, number) != 0 ||
        append_text(output, path) != 0 ||
        sd_bus_message_exit_container(message) < 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "(bs)") == 0) {
    int boolean;
    const char *text = NULL;

    if (sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "bs") <= 0 ||
        sd_bus_message_read(message, "bs", &boolean, &text) <= 0 ||
        aos_query_buffer_u8(output, boolean != 0) != 0 ||
        append_text(output, text) != 0 ||
        sd_bus_message_exit_container(message) < 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "(bas)") == 0) {
    int boolean;

    if (sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "bas") <= 0 ||
        sd_bus_message_read(message, "b", &boolean) <= 0 ||
        aos_query_buffer_u8(output, boolean != 0) != 0 ||
        read_nested_string_array(message, output, true) != 0 ||
        sd_bus_message_exit_container(message) < 0)
      return -1;
    return 0;
  }
  if (strcmp(signature, "(ss)") == 0) {
    const char *first = NULL;
    const char *second = NULL;

    if (sd_bus_message_enter_container(message, SD_BUS_TYPE_STRUCT, "ss") <= 0 ||
        sd_bus_message_read(message, "ss", &first, &second) <= 0 ||
        append_text(output, first) != 0 || append_text(output, second) != 0 ||
        sd_bus_message_exit_container(message) < 0)
      return -1;
    return 0;
  }
  return -1;
}

static uint32_t load_u32le(const uint8_t bytes[4])
{
  return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8U |
         (uint32_t)bytes[2] << 16U | (uint32_t)bytes[3] << 24U;
}

static uint64_t load_u64le(const uint8_t bytes[8])
{
  uint64_t value = 0;

  for (size_t index = 0; index < 8; index++)
    value |= (uint64_t)bytes[index] << (8U * index);
  return value;
}

static int correlate_property(struct aos_query_context *context,
                              struct snapshot_observation *observation,
                              const struct aos_query_property *property,
                              const struct aos_query_buffer *value)
{
  size_t expected_length;

  if (strcmp(property->name, "InvocationID") == 0) {
    bool nonzero = false;

    if (value->length != sizeof(context->invocation_id))
      return -1;
    for (size_t index = 0; index < value->length; index++)
      nonzero |= value->bytes[index] != 0;
    if (!nonzero)
      return -1;
  }
  switch (property->id) {
  case 1:
    expected_length = strlen(context->unit_name);
    if (value->length != expected_length ||
        memcmp(value->bytes, context->unit_name, expected_length) != 0)
      return -1;
    observation->correlations |= CORRELATED_UNIT_ID;
    break;
  case 14:
    if (value->length != sizeof(context->invocation_id) ||
        memcmp(value->bytes, context->invocation_id,
               sizeof(context->invocation_id)) != 0)
      return -1;
    observation->correlations |= CORRELATED_INVOCATION_ID;
    break;
  case 17:
    if (value->length == 0 || value->length > AOS_QUERY_MAX_CGROUP)
      return -1;
    memcpy(observation->control_group, value->bytes, value->length);
    observation->control_group[value->length] = '\0';
    observation->correlations |= CORRELATED_CONTROL_GROUP;
    break;
  case 18:
    if (value->length != sizeof(uint64_t) ||
        (observation->control_group_id = load_u64le(value->bytes)) == 0)
      return -1;
    observation->correlations |= CORRELATED_CONTROL_GROUP_ID;
    break;
  case 24:
    if (value->length != sizeof(uint32_t) ||
        (observation->main_pid = load_u32le(value->bytes)) == 0)
      return -1;
    observation->correlations |= CORRELATED_MAIN_PID;
    break;
  default:
    break;
  }
  return 0;
}

static int property_shape_code(const struct aos_query_property *property,
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

static int decode_property(struct aos_query_context *context,
                           sd_bus_message *message, void *userdata)
{
  const struct property_decode *decode = userdata;
  const struct aos_query_property *property = decode->property;
  struct aos_query_buffer value = {0};
  uint8_t shape;

  if (sd_bus_message_enter_container(message, SD_BUS_TYPE_VARIANT,
                                     property->signature) <= 0 ||
      decode_variant_value(message, property, &value) != 0 ||
      sd_bus_message_exit_container(message) < 0 ||
      sd_bus_message_at_end(message, true) <= 0 ||
      property_shape_code(property, &shape) != 0 ||
      correlate_property(context, decode->observation, property, &value) != 0 ||
      aos_query_buffer_u16le(decode->output, property->id) != 0 ||
      aos_query_buffer_u8(decode->output, shape) != 0)
    return -1;
  if (shape == 1)
    return append_blob(decode->output, value.bytes, value.length);
  return aos_query_buffer_append(decode->output, value.bytes, value.length);
}

static int encode_unit_path(const char *name, char *path, size_t path_size)
{
  static const char hexadecimal[] = "0123456789abcdef";
  size_t offset;
  int written;

  written = snprintf(path, path_size, "/org/freedesktop/systemd1/unit/");
  if (written < 0 || (size_t)written >= path_size)
    return -1;
  offset = (size_t)written;
  for (size_t index = 0; name[index] != '\0'; index++) {
    unsigned char byte = (unsigned char)name[index];

    if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
        (byte >= '0' && byte <= '9')) {
      if (offset + 1 >= path_size)
        return -1;
      path[offset++] = (char)byte;
    } else {
      if (offset + 3 >= path_size)
        return -1;
      path[offset++] = '_';
      path[offset++] = hexadecimal[byte >> 4U];
      path[offset++] = hexadecimal[byte & 0x0fU];
    }
  }
  path[offset] = '\0';
  return 0;
}

static int prepare_unit_identity(struct aos_query_context *context)
{
  static const char service_prefix[] =
      "aos-sandbox-network-namespace-inspector@";
  static const char service_suffix[] = ".service";
  static const char socket_name[] =
      "aos-sandbox-network-namespace-inspector.socket";
  int written;

  if (context->start.cookie == 0 || context->start.subject_pid == 0 ||
      context->start.subject_pidfd_inode == 0)
    return -1;
  written = snprintf(context->service_instance,
                     sizeof(context->service_instance),
                     "%" PRIu64 "-%" PRIu64 "-%" PRIu32 "_%" PRIu64 "-%" PRIu32,
                     context->start.ordinal, context->start.cookie,
                     context->start.subject_pid,
                     context->start.subject_pidfd_inode,
                     context->start.subject_uid);
  if (written <= 0 || (size_t)written >= sizeof(context->service_instance))
    return -1;
  written = snprintf(context->unit_name, sizeof(context->unit_name), "%s%s%s",
                     service_prefix, context->service_instance, service_suffix);
  if (written <= 0 || (size_t)written >= sizeof(context->unit_name) ||
      encode_unit_path(context->unit_name, context->unit_path_storage,
                       sizeof(context->unit_path_storage)) != 0 ||
      encode_unit_path(socket_name, context->socket_path,
                       sizeof(context->socket_path)) != 0)
    return -1;
  context->unit_path = context->unit_path_storage;
  return 0;
}

static int decode_unit(struct aos_query_context *context, sd_bus_message *message,
                       void *userdata)
{
  const char *path = NULL;
  const char *name = NULL;
  const void *invocation = NULL;
  size_t invocation_size = 0;
  bool nonzero = false;

  (void)userdata;
  if (sd_bus_message_read(message, "os", &path, &name) <= 0 ||
      sd_bus_message_read_array(message, SD_BUS_TYPE_BYTE, &invocation,
                                &invocation_size) <= 0 ||
      invocation_size != sizeof(context->invocation_id) ||
      sd_bus_message_at_end(message, true) <= 0 ||
      strcmp(name, context->unit_name) != 0 ||
      strcmp(path, context->unit_path) != 0)
    return -1;
  for (size_t index = 0; index < invocation_size; index++)
    nonzero |= ((const uint8_t *)invocation)[index] != 0;
  if (!nonzero)
    return -1;
  memcpy(context->invocation_id, invocation, sizeof(context->invocation_id));
  return 0;
}

static int run_call(struct aos_query_context *context, sd_bus_message *request,
                    reply_decoder decoder, void *userdata)
{
  struct query_reply reply = {0};
  int fillers[AOS_QUERY_FD_LIMIT];
  size_t filler_count = 0;
  uint32_t prefill_mask = 0;
  sd_bus_slot *slot = NULL;
  uint64_t remaining;
  int result = -1;
  bool filled = false;

  if (aos_query_remaining_usec(context, &remaining) != 0)
    goto out;
  if (remaining > 100000U)
    remaining = 100000U;

  /* sd_bus_call_async only seals, queues, and writes while the bus is running. */
  if (sd_bus_call_async(context->bus, &slot, request, query_callback, &reply,
                        remaining) < 0)
    goto out;

  /* No receive-capable call is permitted between submission and this fill. */
  if (aos_query_fill_fd_table(fillers, &filler_count, &prefill_mask) != 0)
    goto fatal;
  filled = true;
  if (aos_query_remaining_usec(context, &remaining) != 0)
    goto fatal;

  while (!reply.complete) {
    int processed = sd_bus_process(context->bus, NULL);

    if (processed < 0)
      goto fatal;
    if (aos_query_remaining_usec(context, &remaining) != 0)
      goto fatal;
    if (processed == 0) {
      int events = sd_bus_get_events(context->bus);

      if (events < 0 || wait_bus(context, (short)events) != 0)
        goto fatal;
    }
  }
  if (reply.callback_result != 0 || reply.message == NULL ||
      decoder(context, reply.message, userdata) != 0)
    goto fatal;

  if (aos_query_release_fd_table(fillers, filler_count, prefill_mask) != 0)
    goto fatal_without_fillers;
  filled = false;
  result = 0;
  goto out;

fatal:
  /* Once a guarded receive fails, close the bus before exposing a free slot. */
  aos_query_close_bus(context);
  if (filled)
    (void)aos_query_release_fd_table(fillers, filler_count, prefill_mask);
  filled = false;
  goto out;

fatal_without_fillers:
  filled = false;
  aos_query_close_bus(context);

out:
  if (filled)
    (void)aos_query_release_fd_table(fillers, filler_count, prefill_mask);
  sd_bus_message_unref(reply.message);
  sd_bus_slot_unref(slot);
  sd_bus_message_unref(request);
  if (result == 0) {
    uint32_t final_mask;

    if (aos_query_capture_fd_table(&final_mask) != 0 ||
        final_mask != context->runtime_fd_mask) {
      aos_query_close_bus(context);
      result = -1;
    }
  }
  return result;
}

static int get_unit(struct aos_query_context *context)
{
  sd_bus_message *request = NULL;

  if (sd_bus_message_new_method_call(
          context->bus, &request, NULL, "/org/freedesktop/systemd1",
          "org.freedesktop.systemd1.Manager", "GetUnitByPIDFD") < 0 ||
      sd_bus_message_append(request, "h", AOS_QUERY_PARENT_PIDFD) < 0) {
    sd_bus_message_unref(request);
    return -1;
  }
  return run_call(context, request, decode_unit, NULL);
}

static int get_property(struct aos_query_context *context,
                        const struct aos_query_property *property,
                        struct snapshot_observation *observation,
                        struct aos_query_buffer *output)
{
  static const char manager_path[] = "/org/freedesktop/systemd1";
  const char *path;
  const char *interface;
  sd_bus_message *request = NULL;
  struct property_decode decode = {
      .property = property,
      .output = output,
      .observation = observation,
  };

  if (strcmp(property->object, "MANAGER") == 0)
    path = manager_path;
  else if (strcmp(property->object, "INSPECTOR_SERVICE") == 0)
    path = context->unit_path;
  else if (strcmp(property->object, "INSPECTOR_SOCKET") == 0)
    path = context->socket_path;
  else
    return -1;

  if (strcmp(property->interface, "MANAGER") == 0)
    interface = "org.freedesktop.systemd1.Manager";
  else if (strcmp(property->interface, "UNIT") == 0)
    interface = "org.freedesktop.systemd1.Unit";
  else if (strcmp(property->interface, "SERVICE") == 0)
    interface = "org.freedesktop.systemd1.Service";
  else if (strcmp(property->interface, "SOCKET") == 0)
    interface = "org.freedesktop.systemd1.Socket";
  else
    return -1;

  if (sd_bus_message_new_method_call(context->bus, &request, NULL, path,
                                     "org.freedesktop.DBus.Properties", "Get") < 0 ||
      sd_bus_message_append(request, "ss", interface, property->name) < 0) {
    sd_bus_message_unref(request);
    return -1;
  }

  return run_call(context, request, decode_property, &decode);
}

int aos_query_connect_bus(struct aos_query_context *context)
{
  if (prepare_unit_identity(context) != 0 || sd_bus_new(&context->bus) < 0 ||
      sd_bus_set_fd(context->bus, AOS_QUERY_MANAGER_FD, AOS_QUERY_MANAGER_FD) < 0 ||
      sd_bus_set_bus_client(context->bus, 0) < 0 ||
      sd_bus_set_anonymous(context->bus, 0) < 0 ||
      sd_bus_negotiate_fds(context->bus, 1) < 0 || sd_bus_start(context->bus) < 0 ||
      process_until_ready(context) != 0 ||
      aos_query_capture_fd_table(&context->runtime_fd_mask) != 0)
    goto fail;
  return 0;

fail:
  aos_query_close_bus(context);
  return -1;
}

int aos_query_snapshot(struct aos_query_context *context,
                       struct aos_query_buffer *snapshot)
{
  struct snapshot_observation observation = {0};
  struct aos_query_buffer properties = {0};

  if (snapshot->length != 0 ||
      aos_query_remaining_usec(context, &(uint64_t){0}) != 0 ||
      get_unit(context) != 0 ||
      aos_query_buffer_u16le(&properties, AOS_QUERY_PROPERTY_COUNT) != 0)
    return -1;

  for (size_t index = 0; index < AOS_QUERY_PROPERTY_COUNT; index++) {
    if (aos_query_properties[index].id != index ||
        get_property(context, &aos_query_properties[index], &observation,
                     &properties) != 0)
      return -1;
  }
  if (observation.correlations != CORRELATED_ALL ||
      aos_query_buffer_append(snapshot, AOS_QUERY_PROTOCOL_MAGIC, 8) != 0 ||
      aos_query_buffer_u16le(snapshot, AOS_QUERY_PROTOCOL_VERSION) != 0 ||
      aos_query_buffer_u8(snapshot, AOS_QUERY_SNAPSHOT_KIND) != 0 ||
      aos_query_buffer_u8(snapshot, 0) != 0 ||
      aos_query_buffer_u32le(snapshot, 0) != 0 ||
      aos_query_buffer_append(snapshot, aos_query_contract_digest,
                              sizeof(aos_query_contract_digest)) != 0 ||
      aos_query_buffer_text_le(snapshot, context->unit_name) != 0 ||
      aos_query_buffer_text_le(snapshot, context->service_instance) != 0 ||
      aos_query_buffer_append(snapshot, context->invocation_id,
                              sizeof(context->invocation_id)) != 0 ||
      aos_query_buffer_u32le(snapshot, observation.main_pid) != 0 ||
      aos_query_buffer_text_le(snapshot, observation.control_group) != 0 ||
      aos_query_buffer_u64le(snapshot, observation.control_group_id) != 0 ||
      aos_query_buffer_u64le(snapshot, context->start.ordinal) != 0 ||
      aos_query_buffer_u64le(snapshot, context->start.cookie) != 0 ||
      aos_query_buffer_u32le(snapshot, context->start.subject_pid) != 0 ||
      aos_query_buffer_u64le(snapshot, context->start.subject_pidfd_inode) != 0 ||
      aos_query_buffer_u32le(snapshot, context->start.subject_uid) != 0 ||
      aos_query_buffer_append(snapshot, properties.bytes, properties.length) != 0)
    return -1;

  /* The outer control record is larger, but AOSNIMS1 accepts 128 KiB exactly. */
  if (snapshot->length > AOS_QUERY_MAX_SNAPSHOT)
    return -1;

  snapshot->bytes[12] = (uint8_t)snapshot->length;
  snapshot->bytes[13] = (uint8_t)(snapshot->length >> 8U);
  snapshot->bytes[14] = (uint8_t)(snapshot->length >> 16U);
  snapshot->bytes[15] = (uint8_t)(snapshot->length >> 24U);
  return aos_query_remaining_usec(context, &(uint64_t){0});
}

void aos_query_close_bus(struct aos_query_context *context)
{
  if (context->bus != NULL) {
    sd_bus_close(context->bus);
    context->bus = sd_bus_unref(context->bus);
  }
}
