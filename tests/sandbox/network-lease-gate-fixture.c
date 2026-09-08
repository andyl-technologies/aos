// SPDX-License-Identifier: Apache-2.0
/* Test-only loader and state fault injector for the fixed production gate. */

#define _GNU_SOURCE

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <aos/sandbox-network-lease-gate.h>

#ifndef AOS_NETWORK_LEASE_GATE_OBJECT
#error "AOS_NETWORK_LEASE_GATE_OBJECT must name the production BPF object"
#endif

#ifndef AOS_NETWORK_LEASE_GATE_DENY_OBJECT
#error "AOS_NETWORK_LEASE_GATE_DENY_OBJECT must name the test deny BPF object"
#endif

#define DEFAULT_PIN_ROOT "/sys/fs/bpf/aos/network-lease-gate-proof"
#define OBSERVER_PIN_PREFIX "/sys/fs/bpf/aos/sandbox-network/"

static char pin_root[PATH_MAX] = DEFAULT_PIN_ROOT;
static char binding_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/binding";
static char state_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/lease_state";
static char ingress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/ingress_link";
static char egress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/egress_link";
static char deny_ingress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/deny_ingress_link";
static char deny_egress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/deny_egress_link";
static char allow_ingress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/allow_ingress_link";
static char allow_egress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/allow_egress_link";
static char observe_ingress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/observe_ingress_link";
static char observe_egress_pin[PATH_MAX] = DEFAULT_PIN_ROOT "/observe_egress_link";
static char ingress_observation_pin[PATH_MAX] =
    DEFAULT_PIN_ROOT "/ingress_observation";
static char egress_observation_pin[PATH_MAX] =
    DEFAULT_PIN_ROOT "/egress_observation";

#define PIN_ROOT pin_root
#define BINDING_PIN binding_pin
#define STATE_PIN state_pin
#define INGRESS_PIN ingress_pin
#define EGRESS_PIN egress_pin
#define DENY_INGRESS_PIN deny_ingress_pin
#define DENY_EGRESS_PIN deny_egress_pin
#define ALLOW_INGRESS_PIN allow_ingress_pin
#define ALLOW_EGRESS_PIN allow_egress_pin
#define OBSERVE_INGRESS_PIN observe_ingress_pin
#define OBSERVE_EGRESS_PIN observe_egress_pin
#define INGRESS_OBSERVATION_PIN ingress_observation_pin
#define EGRESS_OBSERVATION_PIN egress_observation_pin
#define INSTALL_READY "/run/aos-network-lease-gate-install.ready"
#define UPDATE_READY "/run/aos-network-lease-gate-update.ready"

enum direction {
  DIRECTION_INGRESS,
  DIRECTION_EGRESS,
};

struct link_identity {
  __u32 ifindex;
  __u32 peer_ifindex;
  struct aos_network_mac_address_v1 mac;
  bool up;
  bool veth;
};

struct gate_context_observation {
  __u32 ifindex;
  __u32 ingress_ifindex;
  __u64 boottime_nanoseconds;
};

static void usage(FILE *out)
{
  fprintf(out,
          "usage: network-lease-gate-fixture install-hold HOST_IF PEER_IF "
          "PEER_NETNS EPOCH ALLOCATION HANDLE_HEX ASSIGNMENT_HEX\n"
          "       network-lease-gate-fixture install-observer-hold HOST_IF PEER_IF "
          "PEER_NETNS EPOCH ALLOCATION HANDLE_HEX ASSIGNMENT_HEX GATE_HEX\n"
          "       network-lease-gate-fixture install-invalid-hold HOST_IF "
          "PEER_IF PEER_NETNS EPOCH ALLOCATION HANDLE_HEX ASSIGNMENT_HEX "
          "zero-assignment-digest|reserved-binding|old-format DEADLINE_NS LEASE_HEX\n"
          "       network-lease-gate-fixture update[-hold] "
          "arm|renew EPOCH GENERATION DEADLINE_NS LEASE_HEX\n"
          "       network-lease-gate-fixture update disarm\n"
          "       network-lease-gate-fixture inject ingress|egress "
          "stale-epoch|stale-digest|restore-peer\n"
          "       network-lease-gate-fixture delete-state\n"
          "       network-lease-gate-fixture attach-deny ingress|egress\n"
          "       network-lease-gate-fixture detach-deny ingress|egress\n"
          "       network-lease-gate-fixture attach-allow ingress|egress\n"
          "       network-lease-gate-fixture detach-allow ingress|egress\n"
          "       network-lease-gate-fixture attach-observers\n"
          "       network-lease-gate-fixture detach-observers\n"
          "       network-lease-gate-fixture observer-status\n"
          "       network-lease-gate-fixture status\n"
          "       network-lease-gate-fixture clocks\n"
          "       network-lease-gate-fixture receive PORT RESULT READY\n"
          "       network-lease-gate-fixture teardown HOST_IF\n"
          "       network-lease-gate-fixture force-observer-teardown HANDLE_HEX\n"
          "       network-lease-gate-fixture force-teardown\n");
}

static int parse_digest(const char *text, const char *field,
                        struct aos_network_digest_v1 *digest);
static bool digest_present(const struct aos_network_digest_v1 *digest);

static int set_pin_path(char *destination, size_t capacity, const char *root,
                        const char *leaf)
{
  int length = snprintf(destination, capacity, "%s/%s", root, leaf);

  if (length < 0 || (size_t)length >= capacity) {
    fprintf(stderr, "network-lease-gate-fixture: BPF pin path is too long\n");
    return -1;
  }
  return 0;
}

static int select_observer_pin_root(const char *handle)
{
  struct aos_network_digest_v1 parsed;
  int length;

  if (parse_digest(handle, "network handle", &parsed) != 0 ||
      !digest_present(&parsed))
    return -1;
  length = snprintf(PIN_ROOT, sizeof(pin_root), "%s%s", OBSERVER_PIN_PREFIX,
                    handle);
  if (length < 0 || (size_t)length >= sizeof(pin_root)) {
    fprintf(stderr, "network-lease-gate-fixture: BPF pin root is too long\n");
    return -1;
  }
  if (set_pin_path(BINDING_PIN, sizeof(binding_pin), PIN_ROOT, "binding") != 0 ||
      set_pin_path(STATE_PIN, sizeof(state_pin), PIN_ROOT, "lease_state") != 0 ||
      set_pin_path(INGRESS_PIN, sizeof(ingress_pin), PIN_ROOT, "ingress_link") !=
          0 ||
      set_pin_path(EGRESS_PIN, sizeof(egress_pin), PIN_ROOT, "egress_link") !=
          0)
    return -1;
  return 0;
}

static int parse_u64(const char *text, const char *field, __u64 *value)
{
  char *end = NULL;
  unsigned long long parsed;

  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || parsed == 0) {
    fprintf(stderr, "network-lease-gate-fixture: invalid %s\n", field);
    return -1;
  }

  *value = (__u64)parsed;
  return 0;
}

static int parse_digest(const char *text, const char *field,
                        struct aos_network_digest_v1 *digest)
{
  __u8 *bytes = (__u8 *)digest;

  if (strlen(text) != 64) {
    fprintf(stderr, "network-lease-gate-fixture: invalid %s length\n", field);
    return -1;
  }

  memset(digest, 0, sizeof(*digest));
  for (size_t i = 0; i < sizeof(*digest); i++) {
    unsigned int byte;

    if (sscanf(text + (i * 2), "%2x", &byte) != 1) {
      fprintf(stderr, "network-lease-gate-fixture: invalid %s hex\n", field);
      return -1;
    }
    bytes[i] = (__u8)byte;
  }

  return 0;
}

static bool digest_present(const struct aos_network_digest_v1 *digest)
{
  return digest->words[0] != 0 || digest->words[1] != 0 ||
         digest->words[2] != 0 || digest->words[3] != 0;
}

static bool digest_equal(const struct aos_network_digest_v1 *left,
                         const struct aos_network_digest_v1 *right)
{
  return memcmp(left, right, sizeof(*left)) == 0;
}

static bool link_info_is_veth(const struct rtattr *link_info)
{
  int remaining = RTA_PAYLOAD(link_info);
  struct rtattr *nested = RTA_DATA(link_info);

  for (; RTA_OK(nested, remaining); nested = RTA_NEXT(nested, remaining)) {
    if (nested->rta_type == IFLA_INFO_KIND && RTA_PAYLOAD(nested) >= 5 &&
        memcmp(RTA_DATA(nested), "veth", 5) == 0)
      return true;
  }

  return false;
}

static int observe_link(const char *name, struct link_identity *identity)
{
  struct {
    struct nlmsghdr header;
    struct ifinfomsg link;
  } request;
  char response[8192];
  struct nlmsghdr *header;
  ssize_t response_size;
  int socket_fd;
  bool found_address = false;
  bool found_peer = false;

  if (strlen(name) >= IFNAMSIZ) {
    fprintf(stderr, "network-lease-gate-fixture: interface name is too long\n");
    return -1;
  }

  memset(identity, 0, sizeof(*identity));
  identity->ifindex = if_nametoindex(name);
  if (identity->ifindex == 0) {
    fprintf(stderr, "network-lease-gate-fixture: interface %s is absent\n",
            name);
    return -1;
  }

  socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (socket_fd < 0) {
    perror("network-lease-gate-fixture: netlink socket");
    return -1;
  }

  memset(&request, 0, sizeof(request));
  request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.link));
  request.header.nlmsg_type = RTM_GETLINK;
  request.header.nlmsg_flags = NLM_F_REQUEST;
  request.header.nlmsg_seq = 1;
  request.link.ifi_family = AF_UNSPEC;
  request.link.ifi_index = (int)identity->ifindex;
  if (send(socket_fd, &request, request.header.nlmsg_len, 0) < 0) {
    perror("network-lease-gate-fixture: RTM_GETLINK send");
    close(socket_fd);
    return -1;
  }
  response_size = recv(socket_fd, response, sizeof(response), 0);
  if (response_size < 0) {
    perror("network-lease-gate-fixture: RTM_GETLINK receive");
    close(socket_fd);
    return -1;
  }
  close(socket_fd);

  for (header = (struct nlmsghdr *)response;
       NLMSG_OK(header, response_size);
       header = NLMSG_NEXT(header, response_size)) {
    struct ifinfomsg *link;
    struct rtattr *attribute;
    int remaining;

    if (header->nlmsg_type == NLMSG_ERROR) {
      const struct nlmsgerr *error = NLMSG_DATA(header);

      fprintf(stderr, "network-lease-gate-fixture: RTM_GETLINK: %s\n",
              strerror(error->error == 0 ? EPROTO : -error->error));
      return -1;
    }
    if (header->nlmsg_type != RTM_NEWLINK)
      continue;

    link = NLMSG_DATA(header);
    identity->up = (link->ifi_flags & IFF_UP) != 0;
    remaining = IFLA_PAYLOAD(header);
    for (attribute = IFLA_RTA(link); RTA_OK(attribute, remaining);
         attribute = RTA_NEXT(attribute, remaining)) {
      if (attribute->rta_type == IFLA_ADDRESS &&
          RTA_PAYLOAD(attribute) == sizeof(identity->mac.octets)) {
        memcpy(identity->mac.octets, RTA_DATA(attribute),
               sizeof(identity->mac.octets));
        found_address = true;
      } else if (attribute->rta_type == IFLA_LINK &&
                 RTA_PAYLOAD(attribute) == sizeof(identity->peer_ifindex)) {
        memcpy(&identity->peer_ifindex, RTA_DATA(attribute),
               sizeof(identity->peer_ifindex));
        found_peer = true;
      } else if (attribute->rta_type == IFLA_LINKINFO) {
        identity->veth = link_info_is_veth(attribute);
      }
    }
  }

  if (!found_address || !found_peer || !identity->veth) {
    fprintf(stderr,
            "network-lease-gate-fixture: incomplete or non-veth link identity\n");
    return -1;
  }

  return 0;
}

static int parse_boot_id(struct aos_network_boot_id_v1 *boot_id)
{
  char text[64];
  char compact[33];
  __u8 *bytes = (__u8 *)boot_id;
  ssize_t length;
  size_t compact_length = 0;
  int fd;

  fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("network-lease-gate-fixture: open boot_id");
    return -1;
  }
  length = read(fd, text, sizeof(text) - 1);
  close(fd);
  if (length <= 0) {
    fprintf(stderr, "network-lease-gate-fixture: read boot_id failed\n");
    return -1;
  }
  text[length] = '\0';

  for (ssize_t i = 0; i < length && compact_length < 32; i++) {
    if (text[i] != '-')
      compact[compact_length++] = text[i];
  }
  if (compact_length != 32) {
    fprintf(stderr, "network-lease-gate-fixture: malformed boot_id\n");
    return -1;
  }
  compact[32] = '\0';

  memset(boot_id, 0, sizeof(*boot_id));
  for (size_t i = 0; i < sizeof(*boot_id); i++) {
    unsigned int byte;

    if (sscanf(compact + (i * 2), "%2x", &byte) != 1) {
      fprintf(stderr, "network-lease-gate-fixture: malformed boot_id hex\n");
      return -1;
    }
    bytes[i] = (__u8)byte;
  }

  return 0;
}

static __u64 clock_nanoseconds(clockid_t id)
{
  struct timespec now;

  if (clock_gettime(id, &now) != 0 || now.tv_sec < 0 || now.tv_nsec < 0)
    return 0;

  return ((__u64)now.tv_sec * 1000000000ULL) + (__u64)now.tv_nsec;
}

static int build_binding(const char *host_name, const char *peer_name,
                         const char *peer_netns, __u64 assignment_epoch,
                         __u64 allocation_generation,
                         const struct aos_network_digest_v1 *network_handle,
                         const struct aos_network_digest_v1 *assignment_digest,
                         struct aos_network_lease_binding_v1 *binding)
{
  struct link_identity host;
  struct link_identity peer;
  struct stat namespace_stat;
  int original_netns = -1;
  int peer_netns_fd = -1;
  int result = -1;

  memset(binding, 0, sizeof(*binding));
  if (observe_link(host_name, &host) != 0 || host.up) {
    fprintf(stderr,
            "network-lease-gate-fixture: host link must exist and be down\n");
    return -1;
  }

  original_netns = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
  peer_netns_fd = open(peer_netns, O_RDONLY | O_CLOEXEC);
  if (original_netns < 0 || peer_netns_fd < 0 ||
      fstat(peer_netns_fd, &namespace_stat) != 0) {
    perror("network-lease-gate-fixture: retain network namespace");
    goto out;
  }
  if (namespace_stat.st_dev == 0 || namespace_stat.st_ino == 0) {
    fprintf(stderr, "network-lease-gate-fixture: invalid namespace identity\n");
    goto out;
  }
  if (setns(peer_netns_fd, CLONE_NEWNET) != 0) {
    perror("network-lease-gate-fixture: setns peer");
    goto out;
  }
  if (observe_link(peer_name, &peer) != 0) {
    goto restore;
  }
  if (setns(original_netns, CLONE_NEWNET) != 0) {
    perror("network-lease-gate-fixture: restore network namespace");
    goto out;
  }

  if (!host.veth || !peer.veth || host.peer_ifindex != peer.ifindex ||
      peer.peer_ifindex != host.ifindex ||
      memcmp(&host.mac, &peer.mac, sizeof(host.mac)) == 0) {
    fprintf(stderr, "network-lease-gate-fixture: veth peer identity mismatch\n");
    goto out;
  }

  binding->assignment_epoch = assignment_epoch;
  binding->allocation_generation = allocation_generation;
  binding->namespace_device = (__u64)namespace_stat.st_dev;
  binding->namespace_inode = (__u64)namespace_stat.st_ino;
  binding->format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  binding->provenance_version = AOS_NETWORK_LEASE_GATE_PROVENANCE_VERSION;
  binding->host_ifindex = host.ifindex;
  binding->peer_ifindex = peer.ifindex;
  binding->network_handle = *network_handle;
  binding->assignment_digest = *assignment_digest;
  memset(&binding->gate_object_digest, 0xa5,
         sizeof(binding->gate_object_digest));
  binding->host_mac = host.mac;
  binding->peer_mac = peer.mac;
  if (parse_boot_id(&binding->kernel_boot_id) != 0)
    goto out;

  result = 0;
  goto out;

restore:
  if (setns(original_netns, CLONE_NEWNET) != 0)
    perror("network-lease-gate-fixture: restore after error");
out:
  if (peer_netns_fd >= 0)
    close(peer_netns_fd);
  if (original_netns >= 0)
    close(original_netns);
  return result;
}

static int validate_map_fd(int fd, enum bpf_map_type type, __u32 value_size,
                           __u32 map_flags, const char *name)
{
  struct bpf_map_info info;
  __u32 info_size = sizeof(info);

  memset(&info, 0, sizeof(info));
  if (bpf_obj_get_info_by_fd(fd, &info, &info_size) != 0) {
    perror("network-lease-gate-fixture: BPF map info");
    return -1;
  }
  if (info.type != (__u32)type || info.key_size != sizeof(__u32) ||
      info.value_size != value_size || info.max_entries != 1 ||
      info.map_flags != map_flags || strcmp(info.name, name) != 0) {
    fprintf(stderr, "network-lease-gate-fixture: incompatible %s map\n", name);
    return -1;
  }

  return 0;
}

static int validate_link_fd(int fd, __u32 ifindex,
                            enum bpf_attach_type attach_type)
{
  struct bpf_link_info info;
  __u32 info_size = sizeof(info);

  memset(&info, 0, sizeof(info));
  if (bpf_obj_get_info_by_fd(fd, &info, &info_size) != 0) {
    perror("network-lease-gate-fixture: BPF link info");
    return -1;
  }
  if (info.type != BPF_LINK_TYPE_TCX || info.prog_id == 0 ||
      info.tcx.ifindex != ifindex ||
      info.tcx.attach_type != (__u32)attach_type) {
    fprintf(stderr, "network-lease-gate-fixture: incompatible TCX link\n");
    return -1;
  }

  return 0;
}

static int program_id(struct bpf_object *object, const char *name, __u32 *id)
{
  struct bpf_program *program = bpf_object__find_program_by_name(object, name);
  struct bpf_prog_info info;
  __u32 info_size = sizeof(info);

  if (program == NULL || bpf_program__fd(program) < 0) {
    fprintf(stderr, "network-lease-gate-fixture: missing program %s\n", name);
    return -1;
  }
  memset(&info, 0, sizeof(info));
  if (bpf_obj_get_info_by_fd(bpf_program__fd(program), &info, &info_size) != 0 ||
      info.id == 0) {
    perror("network-lease-gate-fixture: BPF program info");
    return -1;
  }
  *id = info.id;
  return 0;
}

static int require_empty_chain(__u32 ifindex, enum bpf_attach_type attach_type)
{
  LIBBPF_OPTS(bpf_prog_query_opts, query);
  int error;

  error = bpf_prog_query_opts((int)ifindex, attach_type, &query);
  if (error != 0) {
    fprintf(stderr, "network-lease-gate-fixture: query TCX chain: %s\n",
            strerror(-error));
    return -1;
  }
  if (query.count != 0) {
    fprintf(stderr,
            "network-lease-gate-fixture: refusing nonempty TCX chain\n");
    return -1;
  }

  return 0;
}

static int pin_map(struct bpf_object *object, const char *name,
                   const char *path)
{
  struct bpf_map *map = bpf_object__find_map_by_name(object, name);
  int error;

  if (map == NULL) {
    fprintf(stderr, "network-lease-gate-fixture: object lacks map %s\n", name);
    return -1;
  }
  error = bpf_map__pin(map, path);
  if (error != 0) {
    fprintf(stderr, "network-lease-gate-fixture: pin map %s: %s\n", name,
            strerror(-error));
    return -1;
  }

  return 0;
}

static struct bpf_link *attach_program(struct bpf_object *object,
                                       const char *name, __u32 ifindex)
{
  LIBBPF_OPTS(bpf_tcx_opts, options);
  struct bpf_program *program = bpf_object__find_program_by_name(object, name);
  struct bpf_link *link;
  int error;

  if (program == NULL) {
    fprintf(stderr, "network-lease-gate-fixture: object lacks program %s\n",
            name);
    return NULL;
  }
  link = bpf_program__attach_tcx(program, (int)ifindex, &options);
  error = libbpf_get_error(link);
  if (error != 0) {
    fprintf(stderr, "network-lease-gate-fixture: attach %s: %s\n", name,
            strerror(-error));
    return NULL;
  }

  return link;
}

static void initialize_direction(
    struct aos_network_direction_lease_v1 *direction,
    const struct aos_network_lease_binding_v1 *binding)
{
  memset(direction, 0, sizeof(*direction));
  direction->assignment_epoch = binding->assignment_epoch;
  direction->format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  direction->assignment_digest = binding->assignment_digest;
}

static int write_ready(const char *path)
{
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

  if (fd < 0) {
    perror("network-lease-gate-fixture: create ready file");
    return -1;
  }
  if (write(fd, "ready\n", 6) != 6) {
    perror("network-lease-gate-fixture: write ready file");
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static void hold_forever(void)
{
  for (;;)
    pause();
}

static int receive_probe(__u64 port, const char *result_path,
                         const char *ready_path)
{
  const struct timespec readiness_poll = {
      .tv_sec = 0,
      .tv_nsec = 10000000,
  };
  struct sockaddr_in address;
  struct pollfd poll_fd;
  char payload[4096];
  char *temporary_path;
  ssize_t payload_size;
  size_t path_size;
  int result_fd = -1;
  int socket_fd = -1;
  int result = -1;

  if (port > UINT16_MAX) {
    fprintf(stderr, "network-lease-gate-fixture: invalid UDP port\n");
    return -1;
  }

  path_size = strlen(result_path) + sizeof(".tmp");
  temporary_path = malloc(path_size);
  if (temporary_path == NULL) {
    perror("network-lease-gate-fixture: allocate result path");
    return -1;
  }
  if (snprintf(temporary_path, path_size, "%s.tmp", result_path) < 0)
    goto out;

  socket_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    perror("network-lease-gate-fixture: create probe socket");
    goto out;
  }

  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons((uint16_t)port);
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(socket_fd, (const struct sockaddr *)&address, sizeof(address)) != 0) {
    perror("network-lease-gate-fixture: bind probe socket");
    goto out;
  }

  if (write_ready(ready_path) != 0)
    goto out;

  /*
   * The controller removes the ready file and sends in one shell command.
   * Starting the receive deadline after that acknowledgement prevents test
   * agent scheduling latency from consuming the one-second packet window.
   */
  for (unsigned int attempt = 0; attempt < 1000; attempt++) {
    if (access(ready_path, F_OK) != 0) {
      if (errno == ENOENT)
        break;
      perror("network-lease-gate-fixture: inspect probe readiness");
      goto out;
    }
    if (nanosleep(&readiness_poll, NULL) != 0 && errno != EINTR) {
      perror("network-lease-gate-fixture: await probe readiness");
      goto out;
    }
    if (attempt == 999) {
      fprintf(stderr,
              "network-lease-gate-fixture: readiness was not acknowledged\n");
      goto out;
    }
  }

  poll_fd.fd = socket_fd;
  poll_fd.events = POLLIN;
  poll_fd.revents = 0;
  if (poll(&poll_fd, 1, 1000) <= 0 || (poll_fd.revents & POLLIN) == 0)
    goto out;

  payload_size = recv(socket_fd, payload, sizeof(payload), 0);
  if (payload_size <= 0) {
    perror("network-lease-gate-fixture: receive probe");
    goto out;
  }

  result_fd = open(temporary_path,
                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (result_fd < 0 ||
      write(result_fd, payload, (size_t)payload_size) != payload_size) {
    perror("network-lease-gate-fixture: write probe result");
    goto out;
  }
  if (close(result_fd) != 0) {
    result_fd = -1;
    perror("network-lease-gate-fixture: close probe result");
    goto out;
  }
  result_fd = -1;
  if (rename(temporary_path, result_path) != 0) {
    perror("network-lease-gate-fixture: publish probe result");
    goto out;
  }

  result = 0;

out:
  if (result_fd >= 0)
    close(result_fd);
  if (socket_fd >= 0)
    close(socket_fd);
  if (result != 0)
    unlink(temporary_path);
  free(temporary_path);
  return result;
}

static void arm_direction(
    struct aos_network_direction_lease_v1 *direction,
    const struct aos_network_lease_binding_v1 *binding, __u64 generation,
    __u64 deadline, const struct aos_network_digest_v1 *lease_digest);

static int install_gate(struct aos_network_lease_binding_v1 *binding,
                        const struct aos_network_digest_v1 *initial_lease,
                        __u64 initial_deadline, bool hold)
{
  struct aos_network_lease_state_v1 state;
  struct bpf_object *object = NULL;
  struct bpf_link *ingress = NULL;
  struct bpf_link *egress = NULL;
  int binding_fd;
  int state_fd;
  int error;
  __u32 key = AOS_NETWORK_LEASE_GATE_BINDING_KEY;
  int result = -1;

  if (mkdir(PIN_ROOT, 0700) != 0) {
    fprintf(stderr,
            "network-lease-gate-fixture: refusing existing or unavailable pin root: %s\n",
            strerror(errno));
    return -1;
  }
  if (require_empty_chain(binding->host_ifindex, BPF_TCX_INGRESS) != 0 ||
      require_empty_chain(binding->host_ifindex, BPF_TCX_EGRESS) != 0)
    goto out;

  object = bpf_object__open_file(AOS_NETWORK_LEASE_GATE_OBJECT, NULL);
  error = libbpf_get_error(object);
  if (error != 0) {
    fprintf(stderr, "network-lease-gate-fixture: open BPF object: %s\n",
            strerror(-error));
    object = NULL;
    goto out;
  }
  error = bpf_object__load(object);
  if (error != 0) {
    fprintf(stderr, "network-lease-gate-fixture: load BPF object: %s\n",
            strerror(-error));
    goto out;
  }

  if (program_id(object, "aos_network_lease_ingress",
                 &binding->ingress_program_id) != 0 ||
      program_id(object, "aos_network_lease_egress",
                 &binding->egress_program_id) != 0 ||
      binding->ingress_program_id == binding->egress_program_id)
    goto out;

  binding_fd = bpf_object__find_map_fd_by_name(object, "binding");
  state_fd = bpf_object__find_map_fd_by_name(object, "lease_state");
  if (binding_fd < 0 || state_fd < 0 ||
      validate_map_fd(binding_fd, BPF_MAP_TYPE_ARRAY, sizeof(*binding),
                      BPF_F_RDONLY_PROG, "binding") != 0 ||
      validate_map_fd(state_fd, BPF_MAP_TYPE_HASH, sizeof(state),
                      BPF_F_RDONLY_PROG, "lease_state") != 0)
    goto out;

  memset(&state, 0, sizeof(state));
  state.format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  initialize_direction(&state.ingress, binding);
  initialize_direction(&state.egress, binding);
  if (initial_lease != NULL) {
    arm_direction(&state.ingress, binding, 1, initial_deadline,
                  initial_lease);
    arm_direction(&state.egress, binding, 1, initial_deadline, initial_lease);
  }
  if (bpf_map_update_elem(binding_fd, &key, binding, BPF_EXIST) != 0 ||
      bpf_map_update_elem(state_fd, &key, &state, BPF_NOEXIST) != 0) {
    perror("network-lease-gate-fixture: initialize maps");
    goto out;
  }
  if (bpf_map_freeze(binding_fd) != 0) {
    perror("network-lease-gate-fixture: freeze binding map");
    goto out;
  }
  if (bpf_map_update_elem(binding_fd, &key, binding, BPF_EXIST) == 0 ||
      errno != EPERM) {
    fprintf(stderr,
            "network-lease-gate-fixture: frozen binding accepted an update\n");
    goto out;
  }

  if (pin_map(object, "binding", BINDING_PIN) != 0 ||
      pin_map(object, "lease_state", STATE_PIN) != 0)
    goto out;

  ingress = attach_program(object, "aos_network_lease_ingress",
                           binding->host_ifindex);
  if (ingress == NULL || bpf_link__pin(ingress, INGRESS_PIN) != 0)
    goto out;
  egress = attach_program(object, "aos_network_lease_egress",
                          binding->host_ifindex);
  if (egress == NULL || bpf_link__pin(egress, EGRESS_PIN) != 0)
    goto out;

  if (validate_link_fd(bpf_link__fd(ingress), binding->host_ifindex,
                       BPF_TCX_INGRESS) != 0 ||
      validate_link_fd(bpf_link__fd(egress), binding->host_ifindex,
                       BPF_TCX_EGRESS) != 0)
    goto out;

  result = 0;
  if (hold) {
    if (write_ready(INSTALL_READY) != 0)
      result = -1;
    else
      hold_forever();
  }

out:
  if (egress != NULL)
    bpf_link__destroy(egress);
  if (ingress != NULL)
    bpf_link__destroy(ingress);
  if (object != NULL)
    bpf_object__close(object);
  if (result != 0) {
    unlink(EGRESS_PIN);
    unlink(INGRESS_PIN);
    unlink(STATE_PIN);
    unlink(BINDING_PIN);
    rmdir(PIN_ROOT);
  }
  return result;
}

static int open_gate(int *binding_fd, int *state_fd,
                     struct aos_network_lease_binding_v1 *binding,
                     struct aos_network_lease_state_v1 *state)
{
  int ingress_fd = -1;
  int egress_fd = -1;
  __u32 key = AOS_NETWORK_LEASE_GATE_BINDING_KEY;
  int result = -1;

  *binding_fd = bpf_obj_get(BINDING_PIN);
  *state_fd = bpf_obj_get(STATE_PIN);
  ingress_fd = bpf_obj_get(INGRESS_PIN);
  egress_fd = bpf_obj_get(EGRESS_PIN);
  if (*binding_fd < 0 || *state_fd < 0 || ingress_fd < 0 || egress_fd < 0) {
    fprintf(stderr, "network-lease-gate-fixture: incomplete pin set\n");
    goto out;
  }
  if (validate_map_fd(*binding_fd, BPF_MAP_TYPE_ARRAY, sizeof(*binding),
                      BPF_F_RDONLY_PROG, "binding") != 0 ||
      validate_map_fd(*state_fd, BPF_MAP_TYPE_HASH, sizeof(*state),
                      BPF_F_RDONLY_PROG, "lease_state") != 0)
    goto out;
  if (bpf_map_lookup_elem(*binding_fd, &key, binding) != 0 ||
      bpf_map_lookup_elem(*state_fd, &key, state) != 0) {
    fprintf(stderr, "network-lease-gate-fixture: missing binding or state\n");
    goto out;
  }
  if (validate_link_fd(ingress_fd, binding->host_ifindex,
                       BPF_TCX_INGRESS) != 0 ||
      validate_link_fd(egress_fd, binding->host_ifindex,
                       BPF_TCX_EGRESS) != 0)
    goto out;
  result = 0;

out:
  if (egress_fd >= 0)
    close(egress_fd);
  if (ingress_fd >= 0)
    close(ingress_fd);
  if (result != 0) {
    if (*state_fd >= 0)
      close(*state_fd);
    if (*binding_fd >= 0)
      close(*binding_fd);
    *state_fd = -1;
    *binding_fd = -1;
  }
  return result;
}

static bool direction_matches_binding(
    const struct aos_network_direction_lease_v1 *direction,
    const struct aos_network_lease_binding_v1 *binding)
{
  return direction->format_version == AOS_NETWORK_LEASE_GATE_FORMAT_VERSION &&
         direction->assignment_epoch == binding->assignment_epoch &&
         digest_equal(&direction->assignment_digest,
                      &binding->assignment_digest) &&
         (direction->armed == 0 || direction->armed == 1);
}

static void arm_direction(
    struct aos_network_direction_lease_v1 *direction,
    const struct aos_network_lease_binding_v1 *binding, __u64 generation,
    __u64 deadline, const struct aos_network_digest_v1 *lease_digest)
{
  direction->assignment_epoch = binding->assignment_epoch;
  direction->lease_generation = generation;
  direction->deadline_boottime_nanoseconds = deadline;
  direction->format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  direction->armed = 1;
  direction->assignment_digest = binding->assignment_digest;
  direction->lease_digest = *lease_digest;
}

static int update_gate(const char *operation, __u64 epoch, __u64 generation,
                       __u64 deadline,
                       const struct aos_network_digest_v1 *lease_digest,
                       bool hold)
{
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  __u32 key = AOS_NETWORK_LEASE_GATE_STATE_KEY;
  __u64 now = clock_nanoseconds(CLOCK_BOOTTIME);
  int binding_fd = -1;
  int state_fd = -1;
  int result = -1;

  if (open_gate(&binding_fd, &state_fd, &binding, &state) != 0)
    return -1;
  if (state.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      state.reserved != 0 ||
      !direction_matches_binding(&state.ingress, &binding) ||
      !direction_matches_binding(&state.egress, &binding)) {
    fprintf(stderr, "network-lease-gate-fixture: state identity is stale\n");
    goto out;
  }

  if (strcmp(operation, "disarm") == 0) {
    state.ingress.armed = 0;
    state.ingress.deadline_boottime_nanoseconds = 0;
    state.egress.armed = 0;
    state.egress.deadline_boottime_nanoseconds = 0;
  } else {
    bool arm = strcmp(operation, "arm") == 0;
    bool renew = strcmp(operation, "renew") == 0;

    if ((!arm && !renew) || epoch != binding.assignment_epoch || now == 0 ||
        deadline <= now || !digest_present(lease_digest)) {
      fprintf(stderr, "network-lease-gate-fixture: invalid lease update\n");
      goto out;
    }
    if ((arm && (state.ingress.armed != 0 || state.egress.armed != 0)) ||
        (renew && (state.ingress.armed != 1 || state.egress.armed != 1)) ||
        generation <= state.ingress.lease_generation ||
        generation <= state.egress.lease_generation ||
        (renew &&
         (deadline <= state.ingress.deadline_boottime_nanoseconds ||
          deadline <= state.egress.deadline_boottime_nanoseconds))) {
      fprintf(stderr,
              "network-lease-gate-fixture: lease generation or phase is stale\n");
      goto out;
    }

    arm_direction(&state.ingress, &binding, generation, deadline,
                  lease_digest);
    arm_direction(&state.egress, &binding, generation, deadline, lease_digest);
  }

  if (bpf_map_update_elem(state_fd, &key, &state, BPF_EXIST) != 0) {
    perror("network-lease-gate-fixture: update lease state");
    goto out;
  }
  result = 0;
  if (hold) {
    if (write_ready(UPDATE_READY) != 0)
      result = -1;
    else
      hold_forever();
  }

out:
  close(state_fd);
  close(binding_fd);
  return result;
}

static int parse_direction(const char *text, enum direction *direction)
{
  if (strcmp(text, "ingress") == 0)
    *direction = DIRECTION_INGRESS;
  else if (strcmp(text, "egress") == 0)
    *direction = DIRECTION_EGRESS;
  else {
    fprintf(stderr, "network-lease-gate-fixture: invalid direction\n");
    return -1;
  }
  return 0;
}

static int inject_state(enum direction selected, const char *fault)
{
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  struct aos_network_direction_lease_v1 *direction;
  const struct aos_network_direction_lease_v1 *peer;
  __u32 key = AOS_NETWORK_LEASE_GATE_STATE_KEY;
  int binding_fd = -1;
  int state_fd = -1;
  int result = -1;

  if (open_gate(&binding_fd, &state_fd, &binding, &state) != 0)
    return -1;
  direction = selected == DIRECTION_INGRESS ? &state.ingress : &state.egress;
  peer = selected == DIRECTION_INGRESS ? &state.egress : &state.ingress;

  if (strcmp(fault, "stale-epoch") == 0)
    direction->assignment_epoch ^= 1;
  else if (strcmp(fault, "stale-digest") == 0)
    direction->assignment_digest.words[0] ^= 1;
  else if (strcmp(fault, "restore-peer") == 0)
    *direction = *peer;
  else {
    fprintf(stderr, "network-lease-gate-fixture: unknown injection\n");
    goto out;
  }

  if (bpf_map_update_elem(state_fd, &key, &state, BPF_EXIST) != 0) {
    perror("network-lease-gate-fixture: inject lease state");
    goto out;
  }
  result = 0;

out:
  close(state_fd);
  close(binding_fd);
  return result;
}

static int delete_state(void)
{
  int state_fd = bpf_obj_get(STATE_PIN);
  __u32 key = AOS_NETWORK_LEASE_GATE_STATE_KEY;
  int result;

  if (state_fd < 0 ||
      validate_map_fd(state_fd, BPF_MAP_TYPE_HASH,
                      sizeof(struct aos_network_lease_state_v1),
                      BPF_F_RDONLY_PROG, "lease_state") != 0) {
    if (state_fd >= 0)
      close(state_fd);
    return -1;
  }
  result = bpf_map_delete_elem(state_fd, &key);
  if (result != 0)
    perror("network-lease-gate-fixture: delete state");
  close(state_fd);
  return result;
}

static const char *gate_link_pin(enum direction direction)
{
  return direction == DIRECTION_INGRESS ? INGRESS_PIN : EGRESS_PIN;
}

static const char *downstream_link_pin(enum direction direction, bool allow)
{
  if (allow)
    return direction == DIRECTION_INGRESS ? ALLOW_INGRESS_PIN
                                          : ALLOW_EGRESS_PIN;
  return direction == DIRECTION_INGRESS ? DENY_INGRESS_PIN
                                        : DENY_EGRESS_PIN;
}

static enum bpf_attach_type direction_attach_type(enum direction direction)
{
  return direction == DIRECTION_INGRESS ? BPF_TCX_INGRESS : BPF_TCX_EGRESS;
}

static const char *downstream_program_name(enum direction direction, bool allow)
{
  if (allow)
    return direction == DIRECTION_INGRESS ? "allow_ingress" : "allow_egress";
  return direction == DIRECTION_INGRESS ? "deny_ingress" : "deny_egress";
}

static int attach_downstream(enum direction direction, bool allow)
{
  LIBBPF_OPTS(bpf_tcx_opts, options);
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  struct bpf_object *object = NULL;
  struct bpf_program *program;
  struct bpf_link *link = NULL;
  struct bpf_link_info gate_info;
  __u32 info_size = sizeof(gate_info);
  int binding_fd = -1;
  int state_fd = -1;
  int gate_fd = -1;
  int error;
  int result = -1;

  if (open_gate(&binding_fd, &state_fd, &binding, &state) != 0)
    return -1;
  close(state_fd);
  close(binding_fd);

  gate_fd = bpf_obj_get(gate_link_pin(direction));
  memset(&gate_info, 0, sizeof(gate_info));
  if (gate_fd < 0 ||
      bpf_obj_get_info_by_fd(gate_fd, &gate_info, &info_size) != 0)
    goto out;

  object = bpf_object__open_file(AOS_NETWORK_LEASE_GATE_DENY_OBJECT, NULL);
  error = libbpf_get_error(object);
  if (error != 0) {
    object = NULL;
    goto out;
  }
  if (bpf_object__load(object) != 0)
    goto out;
  program = bpf_object__find_program_by_name(
      object, downstream_program_name(direction, allow));
  if (program == NULL)
    goto out;

  options.flags = BPF_F_AFTER | BPF_F_LINK;
  options.relative_fd = (__u32)gate_fd;
  link = bpf_program__attach_tcx(program, (int)binding.host_ifindex, &options);
  error = libbpf_get_error(link);
  if (error != 0) {
    link = NULL;
    goto out;
  }
  if (bpf_link__pin(link, downstream_link_pin(direction, allow)) != 0 ||
      validate_link_fd(bpf_link__fd(link), binding.host_ifindex,
                       direction_attach_type(direction)) != 0)
    goto out;
  result = 0;

out:
  if (link != NULL)
    bpf_link__destroy(link);
  if (object != NULL)
    bpf_object__close(object);
  if (gate_fd >= 0)
    close(gate_fd);
  if (result != 0)
    unlink(downstream_link_pin(direction, allow));
  return result;
}

static int detach_downstream(enum direction direction, bool allow)
{
  const char *pin = downstream_link_pin(direction, allow);
  int fd = bpf_obj_get(pin);

  if (fd < 0) {
    fprintf(stderr, "network-lease-gate-fixture: deny link is absent\n");
    return -1;
  }
  close(fd);
  if (unlink(pin) != 0) {
    perror("network-lease-gate-fixture: unlink downstream link");
    return -1;
  }
  return 0;
}

static int attach_observers(void)
{
  LIBBPF_OPTS(bpf_tcx_opts, ingress_options);
  LIBBPF_OPTS(bpf_tcx_opts, egress_options);
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  struct bpf_object *object = NULL;
  struct bpf_program *ingress_program;
  struct bpf_program *egress_program;
  struct bpf_link *ingress = NULL;
  struct bpf_link *egress = NULL;
  int binding_fd = -1;
  int state_fd = -1;
  int ingress_gate_fd = -1;
  int egress_gate_fd = -1;
  int error;
  int result = -1;

  if (open_gate(&binding_fd, &state_fd, &binding, &state) != 0)
    return -1;
  close(state_fd);
  close(binding_fd);

  ingress_gate_fd = bpf_obj_get(INGRESS_PIN);
  egress_gate_fd = bpf_obj_get(EGRESS_PIN);
  if (ingress_gate_fd < 0 || egress_gate_fd < 0)
    goto out;

  object = bpf_object__open_file(AOS_NETWORK_LEASE_GATE_DENY_OBJECT, NULL);
  error = libbpf_get_error(object);
  if (error != 0) {
    object = NULL;
    goto out;
  }
  if (bpf_object__load(object) != 0)
    goto out;

  ingress_program =
      bpf_object__find_program_by_name(object, "observe_ingress");
  egress_program = bpf_object__find_program_by_name(object, "observe_egress");
  if (ingress_program == NULL || egress_program == NULL ||
      pin_map(object, "ingress_context", INGRESS_OBSERVATION_PIN) != 0 ||
      pin_map(object, "egress_context", EGRESS_OBSERVATION_PIN) != 0)
    goto out;

  ingress_options.flags = BPF_F_BEFORE | BPF_F_LINK;
  ingress_options.relative_fd = (__u32)ingress_gate_fd;
  ingress = bpf_program__attach_tcx(ingress_program,
                                    (int)binding.host_ifindex,
                                    &ingress_options);
  error = libbpf_get_error(ingress);
  if (error != 0) {
    ingress = NULL;
    goto out;
  }

  egress_options.flags = BPF_F_BEFORE | BPF_F_LINK;
  egress_options.relative_fd = (__u32)egress_gate_fd;
  egress = bpf_program__attach_tcx(egress_program,
                                   (int)binding.host_ifindex,
                                   &egress_options);
  error = libbpf_get_error(egress);
  if (error != 0) {
    egress = NULL;
    goto out;
  }
  if (bpf_link__pin(ingress, OBSERVE_INGRESS_PIN) != 0 ||
      bpf_link__pin(egress, OBSERVE_EGRESS_PIN) != 0 ||
      validate_link_fd(bpf_link__fd(ingress), binding.host_ifindex,
                       BPF_TCX_INGRESS) != 0 ||
      validate_link_fd(bpf_link__fd(egress), binding.host_ifindex,
                       BPF_TCX_EGRESS) != 0)
    goto out;

  result = 0;

out:
  if (egress != NULL)
    bpf_link__destroy(egress);
  if (ingress != NULL)
    bpf_link__destroy(ingress);
  if (object != NULL)
    bpf_object__close(object);
  if (egress_gate_fd >= 0)
    close(egress_gate_fd);
  if (ingress_gate_fd >= 0)
    close(ingress_gate_fd);
  if (result != 0) {
    unlink(OBSERVE_EGRESS_PIN);
    unlink(OBSERVE_INGRESS_PIN);
    unlink(EGRESS_OBSERVATION_PIN);
    unlink(INGRESS_OBSERVATION_PIN);
  }
  return result;
}

static int print_observer_status(void)
{
  struct gate_context_observation ingress;
  struct gate_context_observation egress;
  __u32 key = 0;
  int ingress_fd = -1;
  int egress_fd = -1;
  int result = -1;

  ingress_fd = bpf_obj_get(INGRESS_OBSERVATION_PIN);
  egress_fd = bpf_obj_get(EGRESS_OBSERVATION_PIN);
  if (ingress_fd < 0 || egress_fd < 0 ||
      validate_map_fd(ingress_fd, BPF_MAP_TYPE_ARRAY, sizeof(ingress),
                      0, "ingress_context") != 0 ||
      validate_map_fd(egress_fd, BPF_MAP_TYPE_ARRAY, sizeof(egress),
                      0, "egress_context") != 0 ||
      bpf_map_lookup_elem(ingress_fd, &key, &ingress) != 0 ||
      bpf_map_lookup_elem(egress_fd, &key, &egress) != 0)
    goto out;

  printf("{\"ingress\":{\"ifindex\":%u,\"ingress_ifindex\":%u,"
         "\"boottime_nanoseconds\":%llu},"
         "\"egress\":{\"ifindex\":%u,\"ingress_ifindex\":%u,"
         "\"boottime_nanoseconds\":%llu}}\n",
         ingress.ifindex, ingress.ingress_ifindex,
         (unsigned long long)ingress.boottime_nanoseconds, egress.ifindex,
         egress.ingress_ifindex,
         (unsigned long long)egress.boottime_nanoseconds);
  result = 0;

out:
  if (egress_fd >= 0)
    close(egress_fd);
  if (ingress_fd >= 0)
    close(ingress_fd);
  return result;
}

static int detach_observers(void)
{
  const char *pins[] = {
      OBSERVE_EGRESS_PIN,
      OBSERVE_INGRESS_PIN,
      EGRESS_OBSERVATION_PIN,
      INGRESS_OBSERVATION_PIN,
  };

  for (size_t index = 0; index < sizeof(pins) / sizeof(pins[0]); index++) {
    int fd = bpf_obj_get(pins[index]);

    if (fd < 0) {
      fprintf(stderr, "network-lease-gate-fixture: observer pin is absent\n");
      return -1;
    }
    close(fd);
  }
  for (size_t index = 0; index < sizeof(pins) / sizeof(pins[0]); index++) {
    if (unlink(pins[index]) != 0) {
      perror("network-lease-gate-fixture: unlink observer pin");
      return -1;
    }
  }
  return 0;
}

static int print_status(void)
{
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  int binding_fd = -1;
  int state_fd = -1;

  if (open_gate(&binding_fd, &state_fd, &binding, &state) != 0)
    return -1;
  printf("{\"format_version\":%u,\"host_ifindex\":%u,"
         "\"peer_ifindex\":%u,\"assignment_epoch\":%llu,"
         "\"allocation_generation\":%llu,"
         "\"ingress\":{\"armed\":%u,\"generation\":%llu,"
         "\"deadline_boottime_nanoseconds\":%llu},"
         "\"egress\":{\"armed\":%u,\"generation\":%llu,"
         "\"deadline_boottime_nanoseconds\":%llu}}\n",
         binding.format_version, binding.host_ifindex, binding.peer_ifindex,
         (unsigned long long)binding.assignment_epoch,
         (unsigned long long)binding.allocation_generation,
         state.ingress.armed,
         (unsigned long long)state.ingress.lease_generation,
         (unsigned long long)state.ingress.deadline_boottime_nanoseconds,
         state.egress.armed,
         (unsigned long long)state.egress.lease_generation,
         (unsigned long long)state.egress.deadline_boottime_nanoseconds);
  close(state_fd);
  close(binding_fd);
  return 0;
}

static int teardown(const char *host_name)
{
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  struct link_identity host;
  int binding_fd = -1;
  int state_fd = -1;
  int result = -1;
  DIR *directory = NULL;
  struct dirent *entry;

  if (open_gate(&binding_fd, &state_fd, &binding, &state) != 0)
    return -1;
  if (observe_link(host_name, &host) != 0 || host.up ||
      host.ifindex != binding.host_ifindex || state.ingress.armed != 0 ||
      state.egress.armed != 0 || access(DENY_INGRESS_PIN, F_OK) == 0 ||
      access(DENY_EGRESS_PIN, F_OK) == 0 ||
      access(ALLOW_INGRESS_PIN, F_OK) == 0 ||
      access(ALLOW_EGRESS_PIN, F_OK) == 0 ||
      access(OBSERVE_INGRESS_PIN, F_OK) == 0 ||
      access(OBSERVE_EGRESS_PIN, F_OK) == 0) {
    fprintf(stderr,
            "network-lease-gate-fixture: teardown identity or state mismatch\n");
    goto out;
  }
  directory = opendir(PIN_ROOT);
  if (directory == NULL) {
    perror("network-lease-gate-fixture: open pin root");
    goto out;
  }
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0 &&
        strcmp(entry->d_name, "binding") != 0 &&
        strcmp(entry->d_name, "lease_state") != 0 &&
        strcmp(entry->d_name, "ingress_link") != 0 &&
        strcmp(entry->d_name, "egress_link") != 0) {
      fprintf(stderr, "network-lease-gate-fixture: unknown pin %s\n",
              entry->d_name);
      goto out;
    }
  }
  closedir(directory);
  directory = NULL;
  if (unlink(EGRESS_PIN) != 0 || unlink(INGRESS_PIN) != 0 ||
      unlink(STATE_PIN) != 0 || unlink(BINDING_PIN) != 0 ||
      rmdir(PIN_ROOT) != 0) {
    perror("network-lease-gate-fixture: teardown pins");
    goto out;
  }
  result = 0;

out:
  if (directory != NULL)
    closedir(directory);
  close(state_fd);
  close(binding_fd);
  return result;
}

static int force_teardown(void)
{
  const char *pins[] = {
      OBSERVE_EGRESS_PIN,     OBSERVE_INGRESS_PIN,
      EGRESS_OBSERVATION_PIN, INGRESS_OBSERVATION_PIN,
      ALLOW_EGRESS_PIN,       ALLOW_INGRESS_PIN,
      DENY_EGRESS_PIN,        DENY_INGRESS_PIN,
      EGRESS_PIN,             INGRESS_PIN,
      STATE_PIN,              BINDING_PIN,
  };

  for (size_t i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
    if (unlink(pins[i]) != 0 && errno != ENOENT) {
      perror("network-lease-gate-fixture: force unlink pin");
      return -1;
    }
  }
  if (rmdir(PIN_ROOT) != 0 && errno != ENOENT) {
    perror("network-lease-gate-fixture: force remove pin root");
    return -1;
  }
  return 0;
}

static int force_observer_teardown(void)
{
  const char *pins[] = {
      EGRESS_PIN,
      INGRESS_PIN,
      STATE_PIN,
      BINDING_PIN,
  };

  for (size_t i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
    if (unlink(pins[i]) != 0 && errno != ENOENT) {
      perror("network-lease-gate-fixture: force unlink observer pin");
      return -1;
    }
  }
  if (rmdir(PIN_ROOT) != 0 && errno != ENOENT) {
    perror("network-lease-gate-fixture: force remove observer pin root");
    return -1;
  }
  return 0;
}

int main(int argc, char **argv)
{
  if (argc < 2) {
    usage(stderr);
    return 2;
  }

  if (strcmp(argv[1], "install-hold") == 0) {
    struct aos_network_lease_binding_v1 binding;
    struct aos_network_digest_v1 handle;
    struct aos_network_digest_v1 assignment;
    __u64 epoch;
    __u64 allocation;

    if (argc != 9 || parse_u64(argv[5], "assignment epoch", &epoch) != 0 ||
        parse_u64(argv[6], "allocation generation", &allocation) != 0 ||
        parse_digest(argv[7], "network handle", &handle) != 0 ||
        parse_digest(argv[8], "assignment digest", &assignment) != 0 ||
        !digest_present(&handle) || !digest_present(&assignment) ||
        build_binding(argv[2], argv[3], argv[4], epoch, allocation, &handle,
                      &assignment, &binding) != 0)
      return 2;
    return install_gate(&binding, NULL, 0, true) == 0 ? 0 : 1;
  }

  if (strcmp(argv[1], "install-observer-hold") == 0) {
    struct aos_network_lease_binding_v1 binding;
    struct aos_network_digest_v1 gate_object;
    struct aos_network_digest_v1 handle;
    struct aos_network_digest_v1 assignment;
    __u64 epoch;
    __u64 allocation;

    if (argc != 10 || select_observer_pin_root(argv[7]) != 0 ||
        parse_u64(argv[5], "assignment epoch", &epoch) != 0 ||
        parse_u64(argv[6], "allocation generation", &allocation) != 0 ||
        parse_digest(argv[7], "network handle", &handle) != 0 ||
        parse_digest(argv[8], "assignment digest", &assignment) != 0 ||
        parse_digest(argv[9], "gate object digest", &gate_object) != 0 ||
        !digest_present(&handle) || !digest_present(&assignment) ||
        !digest_present(&gate_object) ||
        build_binding(argv[2], argv[3], argv[4], epoch, allocation, &handle,
                      &assignment, &binding) != 0)
      return 2;
    binding.gate_object_digest = gate_object;
    return install_gate(&binding, NULL, 0, true) == 0 ? 0 : 1;
  }

  if (strcmp(argv[1], "install-invalid-hold") == 0) {
    struct aos_network_lease_binding_v1 binding;
    struct aos_network_digest_v1 handle;
    struct aos_network_digest_v1 assignment;
    struct aos_network_digest_v1 lease;
    __u64 epoch;
    __u64 allocation;
    __u64 deadline;

    if (argc != 12 || parse_u64(argv[5], "assignment epoch", &epoch) != 0 ||
        parse_u64(argv[6], "allocation generation", &allocation) != 0 ||
        parse_digest(argv[7], "network handle", &handle) != 0 ||
        parse_digest(argv[8], "assignment digest", &assignment) != 0 ||
        parse_u64(argv[10], "deadline", &deadline) != 0 ||
        parse_digest(argv[11], "lease digest", &lease) != 0 ||
        !digest_present(&handle) || !digest_present(&assignment) ||
        !digest_present(&lease) || deadline <= clock_nanoseconds(CLOCK_BOOTTIME) ||
        build_binding(argv[2], argv[3], argv[4], epoch, allocation, &handle,
                      &assignment, &binding) != 0)
      return 2;
    if (strcmp(argv[9], "zero-assignment-digest") == 0)
      memset(&binding.assignment_digest, 0, sizeof(binding.assignment_digest));
    else if (strcmp(argv[9], "reserved-binding") == 0)
      binding.reserved_tail[0] = 1;
    else if (strcmp(argv[9], "old-format") == 0)
      binding.format_version = 1;
    else {
      fprintf(stderr, "network-lease-gate-fixture: invalid binding fault\n");
      return 2;
    }
    return install_gate(&binding, &lease, deadline, true) == 0 ? 0 : 1;
  }

  if (strcmp(argv[1], "update") == 0 ||
      strcmp(argv[1], "update-hold") == 0) {
    bool hold = strcmp(argv[1], "update-hold") == 0;

    if (argc == 3 && strcmp(argv[2], "disarm") == 0)
      return update_gate("disarm", 0, 0, 0, NULL, hold) == 0 ? 0 : 1;
    if (argc == 7) {
      struct aos_network_digest_v1 lease_digest;
      __u64 epoch;
      __u64 generation;
      __u64 deadline;

      if (parse_u64(argv[3], "assignment epoch", &epoch) != 0 ||
          parse_u64(argv[4], "lease generation", &generation) != 0 ||
          parse_u64(argv[5], "deadline", &deadline) != 0 ||
          parse_digest(argv[6], "lease digest", &lease_digest) != 0)
        return 2;
      return update_gate(argv[2], epoch, generation, deadline, &lease_digest,
                         hold) == 0
                 ? 0
                 : 1;
    }
    usage(stderr);
    return 2;
  }

  if (strcmp(argv[1], "inject") == 0 && argc == 4) {
    enum direction direction;

    if (parse_direction(argv[2], &direction) != 0)
      return 2;
    return inject_state(direction, argv[3]) == 0 ? 0 : 1;
  }
  if (strcmp(argv[1], "delete-state") == 0 && argc == 2)
    return delete_state() == 0 ? 0 : 1;
  if ((strcmp(argv[1], "attach-deny") == 0 ||
       strcmp(argv[1], "detach-deny") == 0 ||
       strcmp(argv[1], "attach-allow") == 0 ||
       strcmp(argv[1], "detach-allow") == 0) &&
      argc == 3) {
    enum direction direction;
    bool allow = strstr(argv[1], "allow") != NULL;

    if (parse_direction(argv[2], &direction) != 0)
      return 2;
    if (strncmp(argv[1], "attach-", 7) == 0)
      return attach_downstream(direction, allow) == 0 ? 0 : 1;
    return detach_downstream(direction, allow) == 0 ? 0 : 1;
  }
  if (strcmp(argv[1], "attach-observers") == 0 && argc == 2)
    return attach_observers() == 0 ? 0 : 1;
  if (strcmp(argv[1], "detach-observers") == 0 && argc == 2)
    return detach_observers() == 0 ? 0 : 1;
  if (strcmp(argv[1], "observer-status") == 0 && argc == 2)
    return print_observer_status() == 0 ? 0 : 1;
  if (strcmp(argv[1], "status") == 0 && argc == 2)
    return print_status() == 0 ? 0 : 1;
  if (strcmp(argv[1], "clocks") == 0 && argc == 2) {
    __u64 monotonic = clock_nanoseconds(CLOCK_MONOTONIC);
    __u64 boottime = clock_nanoseconds(CLOCK_BOOTTIME);

    if (monotonic == 0 || boottime == 0)
      return 1;
    printf("{\"monotonic_nanoseconds\":%llu,"
           "\"boottime_nanoseconds\":%llu}\n",
           (unsigned long long)monotonic, (unsigned long long)boottime);
    return 0;
  }
  if (strcmp(argv[1], "receive") == 0 && argc == 5) {
    __u64 port;

    if (parse_u64(argv[2], "UDP port", &port) != 0)
      return 2;
    return receive_probe(port, argv[3], argv[4]) == 0 ? 0 : 1;
  }
  if (strcmp(argv[1], "teardown") == 0 && argc == 3)
    return teardown(argv[2]) == 0 ? 0 : 1;
  if (strcmp(argv[1], "force-observer-teardown") == 0 && argc == 3) {
    if (select_observer_pin_root(argv[2]) != 0)
      return 2;
    return force_observer_teardown() == 0 ? 0 : 1;
  }
  if (strcmp(argv[1], "force-teardown") == 0 && argc == 2)
    return force_teardown() == 0 ? 0 : 1;

  usage(stderr);
  return 2;
}
