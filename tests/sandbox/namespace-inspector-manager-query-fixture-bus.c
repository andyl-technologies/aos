/* SPDX-License-Identifier: Apache-2.0 */
#include "namespace-inspector-manager-query-fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define PIDFD_GET_INFO 0xc048ff0b
#define PIDFD_INFO_PID (1ULL << 0)

struct fixture_pidfd_info {
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

#define AOS_SYSTEMD_V259_PROPERTY(id, object, interface, property, signature,  \
                                  binding, shape)                              \
  {id, #object, #interface, property, signature, #binding, #shape},
static const struct aos_query_property fixture_properties[] = {
#include "systemd_v259_properties.def"
};
#undef AOS_SYSTEMD_V259_PROPERTY

_Static_assert(sizeof(fixture_properties) / sizeof(fixture_properties[0]) ==
                   AOS_QUERY_PROPERTY_COUNT,
               "fixture manifest count changed");

static void set_u32le(uint8_t *bytes, uint32_t value)
{
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
  bytes[2] = (uint8_t)(value >> 16U);
  bytes[3] = (uint8_t)(value >> 24U);
}

int aos_fixture_wire_append(struct aos_fixture_wire *wire, const void *data,
                            size_t length)
{
  if (wire->length > sizeof(wire->bytes) ||
      length > sizeof(wire->bytes) - wire->length)
    return -1;
  memcpy(wire->bytes + wire->length, data, length);
  wire->length += length;
  return 0;
}

int aos_fixture_wire_u8(struct aos_fixture_wire *wire, uint8_t value)
{
  return aos_fixture_wire_append(wire, &value, sizeof(value));
}

int aos_fixture_wire_u16le(struct aos_fixture_wire *wire, uint16_t value)
{
  uint8_t bytes[2];

  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
  return aos_fixture_wire_append(wire, bytes, sizeof(bytes));
}

int aos_fixture_wire_u32le(struct aos_fixture_wire *wire, uint32_t value)
{
  uint8_t bytes[4];

  set_u32le(bytes, value);
  return aos_fixture_wire_append(wire, bytes, sizeof(bytes));
}

int aos_fixture_wire_u64le(struct aos_fixture_wire *wire, uint64_t value)
{
  uint8_t bytes[8];

  for (size_t index = 0; index < sizeof(bytes); index++) {
    bytes[index] = (uint8_t)value;
    value >>= 8U;
  }
  return aos_fixture_wire_append(wire, bytes, sizeof(bytes));
}

int aos_fixture_wire_align(struct aos_fixture_wire *wire, size_t alignment)
{
  while (wire->length % alignment != 0) {
    if (aos_fixture_wire_u8(wire, 0) != 0)
      return -1;
  }
  return 0;
}

static int encode_unit_path(const char *name, char *path, size_t path_size)
{
  static const char hexadecimal[] = "0123456789abcdef";
  size_t offset = strlen("/org/freedesktop/systemd1/unit/");
  int written;

  written = snprintf(path, path_size, "/org/freedesktop/systemd1/unit/");
  if (written < 0 || (size_t)written >= path_size)
    return -1;
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

int aos_fixture_prepare_identity(struct aos_fixture_identity *identity)
{
  static const char service_prefix[] =
      "aos-sandbox-network-namespace-inspector@";
  static const char service_suffix[] = ".service";
  static const char socket_name[] =
      "aos-sandbox-network-namespace-inspector.socket";
  int written;

  written = snprintf(identity->service_instance,
                     sizeof(identity->service_instance),
                     "%" PRIu64 "-%" PRIu64 "-%" PRIu32 "_%" PRIu64 "-%" PRIu32,
                     identity->start.ordinal, identity->start.cookie,
                     identity->start.subject_pid,
                     identity->start.subject_pidfd_inode,
                     identity->start.subject_uid);
  if (written <= 0 || (size_t)written >= sizeof(identity->service_instance))
    return -1;
  written = snprintf(identity->service_name, sizeof(identity->service_name),
                     "%s%s%s", service_prefix, identity->service_instance,
                     service_suffix);
  if (written <= 0 || (size_t)written >= sizeof(identity->service_name) ||
      encode_unit_path(identity->service_name, identity->service_path,
                       sizeof(identity->service_path)) != 0 ||
      encode_unit_path(socket_name, identity->socket_path,
                       sizeof(identity->socket_path)) != 0)
    return -1;
  return 0;
}

static const char *property_interface(const struct aos_query_property *property)
{
  if (strcmp(property->interface, "MANAGER") == 0)
    return "org.freedesktop.systemd1.Manager";
  if (strcmp(property->interface, "UNIT") == 0)
    return "org.freedesktop.systemd1.Unit";
  if (strcmp(property->interface, "SERVICE") == 0)
    return "org.freedesktop.systemd1.Service";
  if (strcmp(property->interface, "SOCKET") == 0)
    return "org.freedesktop.systemd1.Socket";
  return NULL;
}

static int property_path(const struct aos_query_property *property,
                         const struct aos_fixture_identity *identity, char *path,
                         size_t path_size)
{
  const char *source;

  if (strcmp(property->object, "MANAGER") == 0)
    return snprintf(path, path_size, "/org/freedesktop/systemd1") < 0 ? -1 : 0;
  if (strcmp(property->object, "INSPECTOR_SERVICE") == 0)
    source = identity->service_path;
  else if (strcmp(property->object, "INSPECTOR_SOCKET") == 0)
    source = identity->socket_path;
  else
    return -1;
  return snprintf(path, path_size, "%s", source) < 0 ? -1 : 0;
}

static int append_strings(sd_bus_message *reply, const char *first,
                          const char *second)
{
  if (sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "s") < 0 ||
      sd_bus_message_append(reply, "ss", first, second) < 0 ||
      sd_bus_message_close_container(reply) < 0)
    return -1;
  return 0;
}

static int append_boundary_strings(sd_bus_message *reply, bool oversized)
{
  char value[AOS_QUERY_MAX_TEXT + 1U];
  int result;

  result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "s");
  for (size_t index = 0;
       result >= 0 && index < AOS_FIXTURE_BOUNDARY_ELEMENT_COUNT; index++) {
    size_t length = index + 1U == AOS_FIXTURE_BOUNDARY_ELEMENT_COUNT
                        ? AOS_FIXTURE_BOUNDARY_FINAL_LENGTH + oversized
                        : AOS_FIXTURE_BOUNDARY_ELEMENT_LENGTH;

    memset(value, 'x', length);
    value[length] = '\0';
    result = sd_bus_message_append(reply, "s", value);
  }
  if (result >= 0)
    result = sd_bus_message_close_container(reply);
  return result;
}

static int append_property_value(sd_bus_message *reply,
                                 const struct aos_query_property *property,
                                 const struct aos_fixture_identity *identity,
                                 enum aos_fixture_fault fault,
                                 unsigned int call_index)
{
  const char *signature = property->signature;
  char value[64];
  bool second_round = call_index >= AOS_QUERY_PROPERTY_COUNT + 1U;
  int result = -1;

  if (snprintf(value, sizeof(value), "value-%u", property->id) < 0 ||
      sd_bus_message_open_container(reply, SD_BUS_TYPE_VARIANT, signature) < 0)
    return -1;

  if ((fault == AOS_FIXTURE_MAXIMUM_SNAPSHOT ||
       fault == AOS_FIXTURE_OVERSIZE_SNAPSHOT) &&
      property->id == AOS_FIXTURE_BOUNDARY_PROPERTY_ID &&
      strcmp(signature, "as") == 0) {
    result = append_boundary_strings(
        reply, fault == AOS_FIXTURE_OVERSIZE_SNAPSHOT);
  } else if (fault == AOS_FIXTURE_OVERSIZE_TEXT &&
             strcmp(signature, "s") == 0) {
    char oversized[AOS_QUERY_MAX_TEXT + 2U];

    memset(oversized, 'x', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    result = sd_bus_message_append(reply, "s", oversized);
  } else if (fault == AOS_FIXTURE_OVERSIZE_ARRAY &&
             strcmp(signature, "as") == 0) {
    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "s");
    for (size_t index = 0; result >= 0 && index <= AOS_QUERY_MAX_ELEMENTS;
         index++)
      result = sd_bus_message_append(reply, "s", "item");
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  } else if (strcmp(signature, "s") == 0) {
    const char *text = value;

    if (property->id == 1)
      text = fault == AOS_FIXTURE_PROPERTY_UNIT_ID_MISMATCH
                 ? "wrong.service"
                 : identity->service_name;
    else if (property->id == 17 &&
             fault == AOS_FIXTURE_PROPERTY_EMPTY_CONTROL_GROUP)
      text = "";
    result = sd_bus_message_append(reply, "s", text);
  }
  else if (strcmp(signature, "b") == 0)
    result = sd_bus_message_append(reply, "b", 1);
  else if (strcmp(signature, "u") == 0) {
    uint32_t number = (uint32_t)property->id + 1U;

    if (property->id == 24 && fault == AOS_FIXTURE_PROPERTY_ZERO_MAIN_PID)
      number = 0;
    result = sd_bus_message_append(reply, "u", number);
  }
  else if (strcmp(signature, "i") == 0)
    result = sd_bus_message_append(reply, "i", -(int32_t)property->id - 1);
  else if (strcmp(signature, "t") == 0) {
    uint64_t number = UINT64_C(0x100000000) + property->id;

    if (property->id == 18 &&
        fault == AOS_FIXTURE_PROPERTY_ZERO_CONTROL_GROUP_ID)
      number = 0;
    result = sd_bus_message_append(reply, "t", number);
  }
  else if (strcmp(signature, "ay") == 0) {
    uint8_t invocation[sizeof(identity->invocation_id)];

    memcpy(invocation, identity->invocation_id, sizeof(invocation));
    if (property->id == 14 &&
        fault == AOS_FIXTURE_PROPERTY_INVOCATION_MISMATCH)
      invocation[0] ^= 0x80U;
    if (property->id == 106 &&
        fault == AOS_FIXTURE_PROPERTY_SOCKET_INVOCATION_ZERO)
      memset(invocation, 0, sizeof(invocation));
    result = sd_bus_message_append_array(reply, SD_BUS_TYPE_BYTE, invocation,
                                         sizeof(invocation));
  }
  else if (strcmp(signature, "as") == 0) {
    const char *first = "alpha";
    const char *second = value;

    if (property->id == 0) {
      first = "LANG=C";
      second = "PATH=/bin";
      if (fault == AOS_FIXTURE_INVALID_MANAGER_ENVIRONMENT)
        first = "1INVALID=value";
      else if (fault == AOS_FIXTURE_DUPLICATE_MANAGER_ENVIRONMENT_NAME)
        second = "LANG=en_US";
    }
    if (fault == AOS_FIXTURE_DUPLICATE_UNORDERED_SET)
      second = first;
    if (second_round && strcmp(property->shape, "UNORDERED_SET") == 0)
      result = append_strings(reply, second, first);
    else
      result = append_strings(reply, first, second);
  }
  else if (strcmp(signature, "(uo)") == 0) {
    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "uo");
    if (result >= 0)
      result = sd_bus_message_append(reply, "uo", (uint32_t)property->id,
                                     "/org/freedesktop/systemd1/job/1");
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  } else if (strcmp(signature, "(bs)") == 0) {
    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "bs");
    if (result >= 0)
      result = sd_bus_message_append(reply, "bs", 1, value);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  } else if (strcmp(signature, "(bas)") == 0) {
    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "bas");
    if (result >= 0)
      result = sd_bus_message_append(reply, "b", 1);
    if (result >= 0)
      result = append_strings(reply, second_round ? value : "alpha",
                              second_round ? "alpha" : value);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  } else if (strcmp(signature, "(ss)") == 0) {
    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "ss");
    if (result >= 0)
      result = sd_bus_message_append(reply, "ss", "first", value);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  } else if (strcmp(signature, "a(sb)") == 0) {
    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "(sb)");
    if (result >= 0)
      result = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "sb");
    if (result >= 0)
      result = sd_bus_message_append(reply, "sb", value, 1);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  } else if (strcmp(signature, "a(ss)") == 0) {
    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, "(ss)");
    if (result >= 0)
      result = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, "ss");
    if (result >= 0)
      result = sd_bus_message_append(reply, "ss", "first", value);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  } else if (strcmp(signature, "a(sasbttttuii)") == 0 ||
             strcmp(signature, "a(sasasttttuii)") == 0) {
    bool extended = signature[5] == 'a';
    const char *contents = extended ? "(sasasttttuii)" : "(sasbttttuii)";
    const char *fields = extended ? "sasasttttuii" : "sasbttttuii";

    result = sd_bus_message_open_container(reply, SD_BUS_TYPE_ARRAY, contents);
    if (result >= 0)
      result = sd_bus_message_open_container(reply, SD_BUS_TYPE_STRUCT, fields);
    if (result >= 0)
      result = sd_bus_message_append(reply, "s", "/bin/true");
    if (result >= 0)
      result = append_strings(reply, "/bin/true", "argument");
    if (result >= 0 && extended)
      result = append_strings(reply, second_round ? "ambient" : "ignore-failure",
                              second_round ? "ignore-failure" : "ambient");
    if (result >= 0 && !extended)
      result = sd_bus_message_append(reply, "b", 0);
    if (result >= 0)
      result = sd_bus_message_append(reply, "ttttuii", UINT64_C(1), UINT64_C(2),
                                     UINT64_C(3), UINT64_C(4), (uint32_t)5,
                                     (int32_t)6, (int32_t)7);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
    if (result >= 0)
      result = sd_bus_message_close_container(reply);
  }

  if (result < 0 || sd_bus_message_close_container(reply) < 0)
    return -1;
  if (fault == AOS_FIXTURE_TRAILING_VARIANT &&
      (sd_bus_message_open_container(reply, SD_BUS_TYPE_VARIANT, "s") < 0 ||
       sd_bus_message_append(reply, "s", "trailing") < 0 ||
       sd_bus_message_close_container(reply) < 0))
    return -1;
  return 0;
}

static int wire_string(struct aos_fixture_wire *wire, const char *value)
{
  size_t length = strlen(value);

  if (length > UINT32_MAX || aos_fixture_wire_align(wire, 4) != 0 ||
      aos_fixture_wire_u32le(wire, (uint32_t)length) != 0 ||
      aos_fixture_wire_append(wire, value, length + 1) != 0)
    return -1;
  return 0;
}

static int wire_header_field_u32(struct aos_fixture_wire *wire, uint8_t field,
                                 uint32_t value)
{
  static const uint8_t variant[] = {1, 'u', 0};

  if (aos_fixture_wire_align(wire, 8) != 0 || aos_fixture_wire_u8(wire, field) != 0 ||
      aos_fixture_wire_append(wire, variant, sizeof(variant)) != 0 ||
      aos_fixture_wire_align(wire, 4) != 0 || aos_fixture_wire_u32le(wire, value) != 0)
    return -1;
  return 0;
}

static int wire_header_signature(struct aos_fixture_wire *wire,
                                 const char *signature)
{
  static const uint8_t variant[] = {1, 'g', 0};
  size_t length = strlen(signature);

  if (length > UINT8_MAX || aos_fixture_wire_align(wire, 8) != 0 ||
      aos_fixture_wire_u8(wire, 8) != 0 ||
      aos_fixture_wire_append(wire, variant, sizeof(variant)) != 0 ||
      aos_fixture_wire_u8(wire, (uint8_t)length) != 0 ||
      aos_fixture_wire_append(wire, signature, length + 1) != 0)
    return -1;
  return 0;
}

static int raw_fd_reply(int raw_bus_fd, sd_bus_message *request,
                        const struct aos_query_property *property,
                        const struct aos_fixture_identity *identity,
                        unsigned int serial,
                        uint32_t declared_fds, bool attach_rights)
{
  struct aos_fixture_wire wire = {0};
  uint8_t fixed[16] = {'l', 2, 0, 1};
  uint64_t cookie;
  const char *signature = property == NULL ? "osay" : "v";
  size_t fields_end;
  size_t body_start;
  union {
    struct cmsghdr alignment;
    uint8_t bytes[CMSG_SPACE(sizeof(int))];
  } control;
  struct iovec iovec;
  struct msghdr message = {0};
  struct cmsghdr *header;
  int sent_fd = -1;
  int result = -1;

  if (sd_bus_message_get_cookie(request, &cookie) < 0 || cookie > UINT32_MAX ||
      aos_fixture_wire_append(&wire, fixed, sizeof(fixed)) != 0 ||
      wire_header_field_u32(&wire, 5, (uint32_t)cookie) != 0 ||
      wire_header_signature(&wire, signature) != 0)
    goto out;
  if (declared_fds > 0 && wire_header_field_u32(&wire, 9, declared_fds) != 0)
    goto out;
  fields_end = wire.length;
  if (aos_fixture_wire_align(&wire, 8) != 0)
    goto out;
  body_start = wire.length;

  if (property == NULL) {
    if (wire_string(&wire, identity->service_path) != 0 ||
        wire_string(&wire, identity->service_name) != 0 ||
        aos_fixture_wire_align(&wire, 4) != 0 ||
        aos_fixture_wire_u32le(&wire, sizeof(identity->invocation_id)) != 0 ||
        aos_fixture_wire_append(&wire, identity->invocation_id,
                                sizeof(identity->invocation_id)) != 0)
      goto out;
  } else if (strcmp(property->signature, "b") == 0) {
    static const uint8_t variant[] = {1, 'b', 0};

    if (aos_fixture_wire_append(&wire, variant, sizeof(variant)) != 0 ||
        aos_fixture_wire_align(&wire, 4) != 0 ||
        aos_fixture_wire_u32le(&wire, 1) != 0)
      goto out;
  } else if (strcmp(property->signature, "(ss)") == 0) {
    static const uint8_t variant[] = {4, '(', 's', 's', ')', 0};

    if (aos_fixture_wire_append(&wire, variant, sizeof(variant)) != 0 ||
        aos_fixture_wire_align(&wire, 8) != 0 || wire_string(&wire, "first") != 0 ||
        wire_string(&wire, "value-125") != 0)
      goto out;
  } else {
    goto out;
  }

  set_u32le(wire.bytes + 4, (uint32_t)(wire.length - body_start));
  set_u32le(wire.bytes + 8, serial);
  set_u32le(wire.bytes + 12, (uint32_t)(fields_end - 16));

  iovec.iov_base = wire.bytes;
  iovec.iov_len = wire.length;
  message.msg_iov = &iovec;
  message.msg_iovlen = 1;
  if (attach_rights) {
    sent_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (sent_fd < 0)
      goto out;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(sent_fd));
    memcpy(CMSG_DATA(header), &sent_fd, sizeof(sent_fd));
  }
  if (sendmsg(raw_bus_fd, &message, MSG_NOSIGNAL) != (ssize_t)wire.length)
    goto out;
  result = 0;

out:
  if (sent_fd >= 0)
    close(sent_fd);
  return result;
}

static int validate_call(sd_bus_message *request,
                         const struct aos_query_property *property,
                         const struct aos_fixture_identity *identity)
{
  const char *path = sd_bus_message_get_path(request);
  const char *interface = sd_bus_message_get_interface(request);
  const char *member = sd_bus_message_get_member(request);
  const char *requested_interface = NULL;
  const char *requested_property = NULL;
  const char *expected_interface = property_interface(property);
  char expected_path[512];

  if (path == NULL || interface == NULL || member == NULL || expected_interface == NULL ||
      property_path(property, identity, expected_path, sizeof(expected_path)) != 0 ||
      strcmp(path, expected_path) != 0 ||
      strcmp(interface, "org.freedesktop.DBus.Properties") != 0 ||
      strcmp(member, "Get") != 0 ||
      sd_bus_message_read(request, "ss", &requested_interface,
                          &requested_property) <= 0 ||
      strcmp(requested_interface, expected_interface) != 0 ||
      strcmp(requested_property, property->name) != 0 ||
      sd_bus_message_at_end(request, true) <= 0)
    return -1;
  return 0;
}

static int reply_unit(sd_bus *bus, sd_bus_message *request,
                      const struct aos_fixture_identity *identity,
                      enum aos_fixture_fault fault)
{
  sd_bus_message *reply = NULL;
  uint8_t invocation[32];
  const char *name = identity->service_name;
  const char *path = identity->service_path;
  size_t invocation_size = sizeof(identity->invocation_id);
  int received_fd;
  struct fixture_pidfd_info info = {.mask = PIDFD_INFO_PID};
  int result = -1;

  if (sd_bus_message_get_path(request) == NULL ||
      sd_bus_message_get_interface(request) == NULL ||
      sd_bus_message_get_member(request) == NULL ||
      strcmp(sd_bus_message_get_path(request), "/org/freedesktop/systemd1") != 0 ||
      strcmp(sd_bus_message_get_interface(request),
             "org.freedesktop.systemd1.Manager") != 0 ||
      strcmp(sd_bus_message_get_member(request), "GetUnitByPIDFD") != 0 ||
      sd_bus_message_read(request, "h", &received_fd) <= 0 ||
      ioctl(received_fd, PIDFD_GET_INFO, &info) != 0 ||
      (info.mask & PIDFD_INFO_PID) == 0 || info.pid != (uint32_t)getpid() ||
      info.euid != 0 ||
      sd_bus_message_at_end(request, true) <= 0)
    goto invalid;
  memcpy(invocation, identity->invocation_id, sizeof(identity->invocation_id));
  if (fault == AOS_FIXTURE_WRONG_UNIT_IDENTITY)
    name = "wrong.service";
  else if (fault == AOS_FIXTURE_WRONG_UNIT_PATH)
    path = "/org/freedesktop/systemd1/unit/wrong_2eservice";
  else if (fault == AOS_FIXTURE_UNIT_INVOCATION_WRONG_LENGTH)
    invocation_size = sizeof(identity->invocation_id) - 1U;
  else if (fault == AOS_FIXTURE_UNIT_INVOCATION_ZERO)
    memset(invocation, 0, sizeof(identity->invocation_id));
  if (sd_bus_message_new_method_return(request, &reply) < 0 ||
      sd_bus_message_append(reply, "os", path, name) < 0 ||
      sd_bus_message_append_array(reply, SD_BUS_TYPE_BYTE, invocation,
                                  invocation_size) < 0 ||
      sd_bus_send(bus, reply, NULL) < 0)
    goto invalid;
  result = 0;
  goto out;

invalid:
  (void)sd_bus_message_dump(request, stderr, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

out:
  sd_bus_message_unref(reply);
  return result;
}

int aos_fixture_serve_call(sd_bus *bus, int raw_bus_fd,
                           sd_bus_message *request,
                           const struct aos_fixture_case *test_case,
                           const struct aos_fixture_identity *identity,
                           unsigned int call_index)
{
  bool unit_call = call_index % (AOS_QUERY_PROPERTY_COUNT + 1U) == 0;
  unsigned int property_index =
      (call_index % (AOS_QUERY_PROPERTY_COUNT + 1U)) - 1U;
  const struct aos_query_property *property =
      unit_call ? NULL : &fixture_properties[property_index];
  const struct aos_query_property *reply_property = property;
  sd_bus_message *reply = NULL;
  bool boundary_call =
      !unit_call &&
      (test_case->fault == AOS_FIXTURE_MAXIMUM_SNAPSHOT ||
       test_case->fault == AOS_FIXTURE_OVERSIZE_SNAPSHOT) &&
      property->id == AOS_FIXTURE_BOUNDARY_PROPERTY_ID;
  enum aos_fixture_fault active_fault =
      call_index == test_case->fault_call || boundary_call
          ? test_case->fault
          : AOS_FIXTURE_SUCCESS;
  int result = -1;

  if (call_index >= AOS_QUERY_CALL_COUNT)
    return -1;
  if (test_case->fault == AOS_FIXTURE_STALLED_REPLY &&
      call_index == test_case->fault_call)
    return 0;
  if (test_case->fault >= AOS_FIXTURE_RIGHTS_FIRST_UNIT &&
      test_case->fault <= AOS_FIXTURE_RIGHTS_LAST_PROPERTY &&
      call_index == test_case->fault_call)
    return raw_fd_reply(raw_bus_fd, request, property, identity,
                        7000U + call_index, 1, true);
  if (active_fault == AOS_FIXTURE_RAW_UNIT_NO_FD ||
      active_fault == AOS_FIXTURE_RAW_PROPERTY_NO_FD)
    return raw_fd_reply(raw_bus_fd, request, property, identity,
                        7000U + call_index, 0, false);
  if (active_fault == AOS_FIXTURE_DECLARED_FD_MISSING)
    return raw_fd_reply(raw_bus_fd, request, property, identity,
                        7000U + call_index, 1, false);

  if (unit_call)
    return reply_unit(bus, request, identity, active_fault);
  if (test_case->fault == AOS_FIXTURE_WRONG_PROPERTY &&
      call_index == test_case->fault_call) {
    if (property_index + 1U >= AOS_QUERY_PROPERTY_COUNT)
      return -1;
    reply_property = &fixture_properties[property_index + 1U];
  }
  if (validate_call(request, property, identity) != 0 ||
      sd_bus_message_new_method_return(request, &reply) < 0 ||
      append_property_value(reply, reply_property, identity, active_fault,
                            call_index) != 0 ||
      sd_bus_send(bus, reply, NULL) < 0)
    goto out;
  result = 0;

out:
  sd_bus_message_unref(reply);
  return result;
}
