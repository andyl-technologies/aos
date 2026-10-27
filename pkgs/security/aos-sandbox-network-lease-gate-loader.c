// SPDX-License-Identifier: Apache-2.0
/* Installs and updates one exact sandbox Network ownership-lease gate. */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/magic.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <aos/sandbox-network-lease-gate.h>

#ifndef AOS_NETWORK_LEASE_GATE_OBJECT
#error "AOS_NETWORK_LEASE_GATE_OBJECT must name the fixed BPF object"
#endif

#define PIN_PARENT "/sys/fs/bpf/aos/sandbox-network"
#define PEER_NAMESPACE_FD 3
#define EXPECTED_PIN_COUNT 4U
#define PIN_BINDING (1U << 0)
#define PIN_STATE (1U << 1)
#define PIN_INGRESS (1U << 2)
#define PIN_EGRESS (1U << 3)
#define PIN_GRAPH_COMPLETE (PIN_BINDING | PIN_STATE | PIN_INGRESS | PIN_EGRESS)

struct link_identity {
  __u32 ifindex;
  __u32 peer_ifindex;
  struct aos_network_mac_address_v1 mac;
  bool up;
  bool veth;
};

struct installation {
  char root[PATH_MAX];
  char binding_pin[PATH_MAX];
  char state_pin[PATH_MAX];
  char ingress_pin[PATH_MAX];
  char egress_pin[PATH_MAX];
  bool root_created;
};

union netlink_response_buffer {
  struct nlmsghdr alignment;
  unsigned char bytes[8192];
};

static int verify_pin_inventory(const char *root);

static void usage(void)
{
  fprintf(stderr,
          "usage: aos-sandbox-network-lease-gate-loader install-disarmed "
          "HOST_IF PEER_IF /proc/self/fd/3 EPOCH ALLOCATION HANDLE_HEX "
          "ASSIGNMENT_HEX GATE_OBJECT_HEX GATE_OBJECT\n"
          "       aos-sandbox-network-lease-gate-loader set-lease "
          "HANDLE_HEX EPOCH ASSIGNMENT_HEX GENERATION DEADLINE LEASE_HEX\n"
          "       aos-sandbox-network-lease-gate-loader set-default-drop "
          "HANDLE_HEX EPOCH ASSIGNMENT_HEX\n"
          "       aos-sandbox-network-lease-gate-loader remove "
          "HANDLE_HEX EPOCH ASSIGNMENT_HEX\n");
}

static int hexadecimal_nibble(char value)
{
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  return -1;
}

static int parse_digest(const char *text, const char *field,
                        struct aos_network_digest_v1 *digest)
{
  __u8 *bytes = (__u8 *)digest;

  if (strlen(text) != sizeof(*digest) * 2) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: invalid %s length\n",
            field);
    return -1;
  }
  memset(digest, 0, sizeof(*digest));
  for (size_t index = 0; index < sizeof(*digest); index++) {
    int high = hexadecimal_nibble(text[index * 2]);
    int low = hexadecimal_nibble(text[(index * 2) + 1]);

    if (high < 0 || low < 0) {
      fprintf(stderr,
              "aos-sandbox-network-lease-gate-loader: invalid %s hex\n",
              field);
      return -1;
    }
    bytes[index] = (__u8)((high << 4) | low);
  }
  return 0;
}

static bool digest_present(const struct aos_network_digest_v1 *digest)
{
  return digest->words[0] != 0 || digest->words[1] != 0 ||
         digest->words[2] != 0 || digest->words[3] != 0;
}

static int parse_u64(const char *text, const char *field, __u64 *value)
{
  char canonical[32];
  char *end = NULL;
  unsigned long long parsed;
  int length;

  if (text[0] < '1' || text[0] > '9') {
    fprintf(stderr, "aos-sandbox-network-lease-gate-loader: invalid %s\n",
            field);
    return -1;
  }
  for (const char *cursor = text; *cursor != '\0'; cursor++) {
    if (*cursor < '0' || *cursor > '9') {
      fprintf(stderr, "aos-sandbox-network-lease-gate-loader: invalid %s\n",
              field);
      return -1;
    }
  }
  errno = 0;
  parsed = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || parsed == 0) {
    fprintf(stderr, "aos-sandbox-network-lease-gate-loader: invalid %s\n",
            field);
    return -1;
  }
  length = snprintf(canonical, sizeof(canonical), "%llu", parsed);
  if (length < 0 || (size_t)length >= sizeof(canonical) ||
      strcmp(text, canonical) != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: noncanonical %s\n",
            field);
    return -1;
  }
  *value = (__u64)parsed;
  return 0;
}

static int parse_boot_id(struct aos_network_boot_id_v1 *boot_id)
{
  static const size_t hyphens[] = {8, 13, 18, 23};
  char text[38];
  __u8 *bytes = (__u8 *)boot_id;
  size_t input = 0;
  size_t output = 0;
  ssize_t length;
  int fd;

  fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    perror("aos-sandbox-network-lease-gate-loader: open boot ID");
    return -1;
  }
  length = read(fd, text, sizeof(text));
  close(fd);
  if (length != 37 || text[36] != '\n') {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: malformed boot ID\n");
    return -1;
  }
  for (size_t index = 0; index < sizeof(hyphens) / sizeof(hyphens[0]);
       index++) {
    if (text[hyphens[index]] != '-') {
      fprintf(stderr,
              "aos-sandbox-network-lease-gate-loader: malformed boot ID\n");
      return -1;
    }
  }
  memset(boot_id, 0, sizeof(*boot_id));
  while (input < 36) {
    int high;
    int low;

    if (text[input] == '-') {
      input++;
      continue;
    }
    high = hexadecimal_nibble(text[input++]);
    low = hexadecimal_nibble(text[input++]);
    if (high < 0 || low < 0 || output >= sizeof(*boot_id)) {
      fprintf(stderr,
              "aos-sandbox-network-lease-gate-loader: malformed boot ID\n");
      return -1;
    }
    bytes[output++] = (__u8)((high << 4) | low);
  }
  if (output != sizeof(*boot_id)) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: malformed boot ID\n");
    return -1;
  }
  return 0;
}

static bool link_info_is_veth(const struct rtattr *link_info)
{
  int remaining = RTA_PAYLOAD(link_info);
  struct rtattr *nested = RTA_DATA(link_info);
  bool found_kind = false;
  bool is_veth = false;

  for (; RTA_OK(nested, remaining); nested = RTA_NEXT(nested, remaining)) {
    if (nested->rta_type == IFLA_INFO_KIND) {
      if (found_kind)
        return false;
      found_kind = true;
      is_veth = RTA_PAYLOAD(nested) == 5 &&
                memcmp(RTA_DATA(nested), "veth", 5) == 0;
    }
  }
  return remaining == 0 && found_kind && is_veth;
}

static int parse_link_response(union netlink_response_buffer *response,
                               size_t length, __u32 port_id,
                               struct link_identity *identity)
{
  struct nlmsghdr *header;
  bool found = false;
  bool found_address = false;
  bool found_link_info = false;
  bool found_peer = false;
  int remaining_messages;

  if (length == 0 || length > sizeof(response->bytes))
    return -1;
  remaining_messages = (int)length;
  for (header = (struct nlmsghdr *)response->bytes;
       NLMSG_OK(header, remaining_messages);
       header = NLMSG_NEXT(header, remaining_messages)) {
    struct ifinfomsg *link;
    struct rtattr *attribute;
    int remaining_attributes;

    if (header->nlmsg_seq != 1 || header->nlmsg_pid != port_id) {
      fprintf(stderr,
              "aos-sandbox-network-lease-gate-loader: unrelated netlink reply\n");
      return -1;
    }
    if (header->nlmsg_type == NLMSG_ERROR) {
      struct nlmsgerr error;
      int diagnostic_error;

      if (NLMSG_PAYLOAD(header, 0) < sizeof(error)) {
        fprintf(stderr,
                "aos-sandbox-network-lease-gate-loader: truncated netlink error\n");
        return -1;
      }
      memcpy(&error, NLMSG_DATA(header), sizeof(error));
      diagnostic_error = error.error >= 0 || error.error == INT_MIN
                             ? EPROTO
                             : -error.error;
      fprintf(stderr,
              "aos-sandbox-network-lease-gate-loader: RTM_GETLINK: %s\n",
              strerror(diagnostic_error));
      return -1;
    }
    if (header->nlmsg_type != RTM_NEWLINK ||
        NLMSG_PAYLOAD(header, 0) < sizeof(struct ifinfomsg))
      return -1;
    link = NLMSG_DATA(header);
    if (link->ifi_index != (int)identity->ifindex || found) {
      fprintf(stderr,
              "aos-sandbox-network-lease-gate-loader: ambiguous link reply\n");
      return -1;
    }
    found = true;
    identity->up = (link->ifi_flags & IFF_UP) != 0;
    remaining_attributes = IFLA_PAYLOAD(header);
    for (attribute = IFLA_RTA(link);
         RTA_OK(attribute, remaining_attributes);
         attribute = RTA_NEXT(attribute, remaining_attributes)) {
      if (attribute->rta_type == IFLA_ADDRESS &&
          RTA_PAYLOAD(attribute) == sizeof(identity->mac.octets)) {
        if (found_address)
          return -1;
        memcpy(identity->mac.octets, RTA_DATA(attribute),
               sizeof(identity->mac.octets));
        found_address = true;
      } else if (attribute->rta_type == IFLA_LINK &&
                 RTA_PAYLOAD(attribute) == sizeof(identity->peer_ifindex)) {
        if (found_peer)
          return -1;
        memcpy(&identity->peer_ifindex, RTA_DATA(attribute),
               sizeof(identity->peer_ifindex));
        found_peer = true;
      } else if (attribute->rta_type == IFLA_LINKINFO) {
        if (found_link_info)
          return -1;
        found_link_info = true;
        identity->veth = link_info_is_veth(attribute);
      }
    }
    if (remaining_attributes != 0)
      return -1;
  }
  if (remaining_messages != 0 || !found || !found_address) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: incomplete link identity\n");
    return -1;
  }
  return 0;
}

static int read_link(const char *name, struct link_identity *identity)
{
  struct {
    struct nlmsghdr header;
    struct ifinfomsg link;
  } request;
  union netlink_response_buffer response;
  struct sockaddr_nl local;
  struct sockaddr_nl kernel;
  struct sockaddr_nl sender;
  struct iovec iov;
  struct msghdr message;
  socklen_t local_length;
  ssize_t received;
  int socket_fd;

  if (name[0] == '\0' || strlen(name) >= IFNAMSIZ) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: invalid interface name\n");
    return -1;
  }
  memset(identity, 0, sizeof(*identity));
  identity->ifindex = if_nametoindex(name);
  if (identity->ifindex == 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: interface is absent\n");
    return -1;
  }
  socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (socket_fd < 0) {
    perror("aos-sandbox-network-lease-gate-loader: netlink socket");
    return -1;
  }
  memset(&local, 0, sizeof(local));
  local.nl_family = AF_NETLINK;
  if (bind(socket_fd, (const struct sockaddr *)&local, sizeof(local)) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: bind netlink socket");
    close(socket_fd);
    return -1;
  }
  local_length = sizeof(local);
  if (getsockname(socket_fd, (struct sockaddr *)&local, &local_length) != 0 ||
      local_length != sizeof(local) || local.nl_family != AF_NETLINK ||
      local.nl_pid == 0 || local.nl_groups != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: invalid local netlink identity\n");
    close(socket_fd);
    return -1;
  }
  memset(&request, 0, sizeof(request));
  request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.link));
  request.header.nlmsg_type = RTM_GETLINK;
  request.header.nlmsg_flags = NLM_F_REQUEST;
  request.header.nlmsg_seq = 1;
  request.header.nlmsg_pid = local.nl_pid;
  request.link.ifi_family = AF_UNSPEC;
  request.link.ifi_index = (int)identity->ifindex;
  memset(&kernel, 0, sizeof(kernel));
  kernel.nl_family = AF_NETLINK;
  if (sendto(socket_fd, &request, request.header.nlmsg_len, 0,
             (const struct sockaddr *)&kernel, sizeof(kernel)) !=
      (ssize_t)request.header.nlmsg_len) {
    perror("aos-sandbox-network-lease-gate-loader: send RTM_GETLINK");
    close(socket_fd);
    return -1;
  }
  memset(&sender, 0, sizeof(sender));
  memset(&message, 0, sizeof(message));
  iov.iov_base = response.bytes;
  iov.iov_len = sizeof(response.bytes);
  message.msg_name = &sender;
  message.msg_namelen = sizeof(sender);
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  received = recvmsg(socket_fd, &message, 0);
  close(socket_fd);
  if (received <= 0) {
    perror("aos-sandbox-network-lease-gate-loader: receive RTM_GETLINK");
    return -1;
  }
  if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
      message.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK ||
      sender.nl_pid != 0 || sender.nl_groups != 0 ||
      received > (ssize_t)sizeof(response.bytes)) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: untrusted netlink reply\n");
    return -1;
  }
  return parse_link_response(&response, (size_t)received, local.nl_pid,
                             identity);
}

static int observe_veth(const char *name, struct link_identity *identity)
{
  if (read_link(name, identity) != 0 || !identity->veth ||
      identity->peer_ifindex == 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: incomplete veth identity\n");
    return -1;
  }
  return 0;
}

static int build_binding(
    const char *host_name, const char *peer_name, __u64 assignment_epoch,
    __u64 allocation_generation,
    const struct aos_network_digest_v1 *network_handle,
    const struct aos_network_digest_v1 *assignment_digest,
    const struct aos_network_digest_v1 *gate_object_digest,
    struct aos_network_lease_binding_v1 *binding)
{
  struct link_identity host;
  struct link_identity peer;
  struct stat namespace_stat;
  struct statfs namespace_filesystem;
  int initial_namespace = -1;
  int result = -1;

  memset(binding, 0, sizeof(*binding));
  if (fstat(PEER_NAMESPACE_FD, &namespace_stat) != 0 ||
      fstatfs(PEER_NAMESPACE_FD, &namespace_filesystem) != 0 ||
      namespace_filesystem.f_type != NSFS_MAGIC || namespace_stat.st_dev == 0 ||
      namespace_stat.st_ino == 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: invalid peer namespace FD\n");
    return -1;
  }
  if (observe_veth(host_name, &host) != 0 || host.up)
    return -1;

  initial_namespace = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
  if (initial_namespace < 0 || setns(PEER_NAMESPACE_FD, CLONE_NEWNET) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: enter peer namespace");
    goto out;
  }
  if (observe_veth(peer_name, &peer) != 0 || peer.up)
    goto restore;
  if (setns(initial_namespace, CLONE_NEWNET) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: restore host namespace");
    _exit(125);
  }
  if (!host.veth || !peer.veth || host.peer_ifindex != peer.ifindex ||
      peer.peer_ifindex != host.ifindex ||
      memcmp(&host.mac, &peer.mac, sizeof(host.mac)) == 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: reciprocal veth mismatch\n");
    goto out;
  }

  binding->assignment_epoch = assignment_epoch;
  binding->allocation_generation = allocation_generation;
  binding->namespace_device = (__u64)namespace_stat.st_dev;
  binding->namespace_inode = (__u64)namespace_stat.st_ino;
  binding->format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  binding->host_ifindex = host.ifindex;
  binding->peer_ifindex = peer.ifindex;
  binding->provenance_version = AOS_NETWORK_LEASE_GATE_PROVENANCE_VERSION;
  binding->network_handle = *network_handle;
  binding->assignment_digest = *assignment_digest;
  binding->gate_object_digest = *gate_object_digest;
  binding->host_mac = host.mac;
  binding->peer_mac = peer.mac;
  if (parse_boot_id(&binding->kernel_boot_id) != 0)
    goto out;
  result = 0;
  goto out;

restore:
  if (setns(initial_namespace, CLONE_NEWNET) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: restore after error");
    _exit(125);
  }
out:
  if (initial_namespace >= 0)
    close(initial_namespace);
  return result;
}

static int prepare_pin_root(const char *handle, struct installation *install)
{
  struct stat parent;
  struct statfs filesystem;
  DIR *directory = NULL;
  struct dirent *entry;
  unsigned int entries = 0;
  int length;

  memset(install, 0, sizeof(*install));
  if (lstat(PIN_PARENT, &parent) != 0 || !S_ISDIR(parent.st_mode) ||
      parent.st_uid != 0 || parent.st_gid != 0 ||
      (parent.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
      statfs(PIN_PARENT, &filesystem) != 0 || filesystem.f_type != BPF_FS_MAGIC) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: unsafe BPF pin parent\n");
    return -1;
  }
  length = snprintf(install->root, sizeof(install->root), "%s/%s", PIN_PARENT,
                    handle);
  if (length < 0 || (size_t)length >= sizeof(install->root))
    return -1;
  if (mkdir(install->root, 0700) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: create exclusive pin root");
    return -1;
  }
  install->root_created = true;
  if (snprintf(install->binding_pin, sizeof(install->binding_pin), "%s/binding",
               install->root) < 0 ||
      snprintf(install->state_pin, sizeof(install->state_pin), "%s/lease_state",
               install->root) < 0 ||
      snprintf(install->ingress_pin, sizeof(install->ingress_pin),
               "%s/ingress_link", install->root) < 0 ||
      snprintf(install->egress_pin, sizeof(install->egress_pin),
               "%s/egress_link", install->root) < 0)
    return -1;

  directory = opendir(install->root);
  if (directory == NULL)
    return -1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
      entries++;
  }
  if (errno != 0 || closedir(directory) != 0 || entries != 0)
    return -1;
  return 0;
}

static int open_pin_root(const char *handle, struct installation *install)
{
  struct stat parent;
  struct stat root;
  struct statfs filesystem;
  int binding_length;
  int state_length;
  int ingress_length;
  int egress_length;
  int length;

  memset(install, 0, sizeof(*install));
  if (lstat(PIN_PARENT, &parent) != 0 || !S_ISDIR(parent.st_mode) ||
      parent.st_uid != 0 || parent.st_gid != 0 ||
      (parent.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
      statfs(PIN_PARENT, &filesystem) != 0 || filesystem.f_type != BPF_FS_MAGIC)
    return -1;
  length = snprintf(install->root, sizeof(install->root), "%s/%s", PIN_PARENT,
                    handle);
  if (length < 0 || (size_t)length >= sizeof(install->root) ||
      lstat(install->root, &root) != 0 || !S_ISDIR(root.st_mode) ||
      root.st_uid != 0 || root.st_gid != 0 ||
      (root.st_mode & 0777) != 0700 || root.st_dev != parent.st_dev) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: unsafe existing pin graph\n");
    return -1;
  }
  binding_length = snprintf(install->binding_pin, sizeof(install->binding_pin),
                            "%s/binding", install->root);
  state_length = snprintf(install->state_pin, sizeof(install->state_pin),
                          "%s/lease_state", install->root);
  ingress_length = snprintf(install->ingress_pin, sizeof(install->ingress_pin),
                            "%s/ingress_link", install->root);
  egress_length = snprintf(install->egress_pin, sizeof(install->egress_pin),
                           "%s/egress_link", install->root);
  if (binding_length < 0 ||
      (size_t)binding_length >= sizeof(install->binding_pin) ||
      state_length < 0 || (size_t)state_length >= sizeof(install->state_pin) ||
      ingress_length < 0 ||
      (size_t)ingress_length >= sizeof(install->ingress_pin) ||
      egress_length < 0 ||
      (size_t)egress_length >= sizeof(install->egress_pin) ||
      verify_pin_inventory(install->root) != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: invalid existing pin graph\n");
    return -1;
  }
  return 0;
}

static int open_pin_root_for_removal(const char *handle,
                                     struct installation *install,
                                     unsigned int *inventory,
                                     bool *root_absent)
{
  struct stat parent;
  struct stat root;
  struct statfs filesystem;
  DIR *directory = NULL;
  struct dirent *entry;
  int binding_length;
  int state_length;
  int ingress_length;
  int egress_length;
  int length;

  memset(install, 0, sizeof(*install));
  *inventory = 0;
  *root_absent = false;
  if (lstat(PIN_PARENT, &parent) != 0 || !S_ISDIR(parent.st_mode) ||
      parent.st_uid != 0 || parent.st_gid != 0 ||
      (parent.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
      statfs(PIN_PARENT, &filesystem) != 0 || filesystem.f_type != BPF_FS_MAGIC)
    return -1;
  length = snprintf(install->root, sizeof(install->root), "%s/%s", PIN_PARENT,
                    handle);
  if (length < 0 || (size_t)length >= sizeof(install->root))
    return -1;
  if (lstat(install->root, &root) != 0) {
    if (errno == ENOENT) {
      *root_absent = true;
      return 0;
    }
    return -1;
  }
  if (!S_ISDIR(root.st_mode) || root.st_uid != 0 || root.st_gid != 0 ||
      (root.st_mode & 0777) != 0700 || root.st_dev != parent.st_dev)
    return -1;

  binding_length = snprintf(install->binding_pin, sizeof(install->binding_pin),
                            "%s/binding", install->root);
  state_length = snprintf(install->state_pin, sizeof(install->state_pin),
                          "%s/lease_state", install->root);
  ingress_length = snprintf(install->ingress_pin, sizeof(install->ingress_pin),
                            "%s/ingress_link", install->root);
  egress_length = snprintf(install->egress_pin, sizeof(install->egress_pin),
                           "%s/egress_link", install->root);
  if (binding_length < 0 ||
      (size_t)binding_length >= sizeof(install->binding_pin) ||
      state_length < 0 || (size_t)state_length >= sizeof(install->state_pin) ||
      ingress_length < 0 ||
      (size_t)ingress_length >= sizeof(install->ingress_pin) ||
      egress_length < 0 ||
      (size_t)egress_length >= sizeof(install->egress_pin))
    return -1;

  directory = opendir(install->root);
  if (directory == NULL)
    return -1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    unsigned int pin = 0;

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (strcmp(entry->d_name, "binding") == 0)
      pin = PIN_BINDING;
    else if (strcmp(entry->d_name, "lease_state") == 0)
      pin = PIN_STATE;
    else if (strcmp(entry->d_name, "ingress_link") == 0)
      pin = PIN_INGRESS;
    else if (strcmp(entry->d_name, "egress_link") == 0)
      pin = PIN_EGRESS;
    else
      goto invalid;
    if ((*inventory & pin) != 0)
      goto invalid;
    *inventory |= pin;
  }
  if (errno != 0 || closedir(directory) != 0)
    return -1;
  directory = NULL;

  if (*inventory != PIN_GRAPH_COMPLETE &&
      *inventory != (PIN_BINDING | PIN_STATE | PIN_INGRESS) &&
      *inventory != (PIN_BINDING | PIN_STATE) &&
      *inventory != PIN_BINDING && *inventory != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: invalid removal prefix\n");
    return -1;
  }
  return 0;

invalid:
  closedir(directory);
  fprintf(stderr,
          "aos-sandbox-network-lease-gate-loader: invalid removal inventory\n");
  return -1;
}

static int validate_map(int fd, enum bpf_map_type type, __u32 value_size,
                        const char *name)
{
  struct bpf_map_info info;
  __u32 size = sizeof(info);

  memset(&info, 0, sizeof(info));
  if (bpf_obj_get_info_by_fd(fd, &info, &size) != 0 ||
      info.type != (__u32)type || info.key_size != sizeof(__u32) ||
      info.value_size != value_size || info.max_entries != 1 ||
      info.map_flags != BPF_F_RDONLY_PROG || strcmp(info.name, name) != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: incompatible BPF map\n");
    return -1;
  }
  return 0;
}

static int program_id(struct bpf_object *object, const char *name, __u32 *id)
{
  struct bpf_program *program = bpf_object__find_program_by_name(object, name);
  struct bpf_prog_info info;
  __u32 size = sizeof(info);

  if (program == NULL || bpf_program__fd(program) < 0)
    return -1;
  memset(&info, 0, sizeof(info));
  if (bpf_obj_get_info_by_fd(bpf_program__fd(program), &info, &size) != 0 ||
      info.id == 0)
    return -1;
  *id = info.id;
  return 0;
}

static int require_empty_chain(__u32 ifindex, enum bpf_attach_type type)
{
  LIBBPF_OPTS(bpf_prog_query_opts, query);

  if (bpf_prog_query_opts((int)ifindex, type, &query) != 0 || query.count != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: TCX chain is not empty\n");
    return -1;
  }
  return 0;
}

static int require_empty_chain_or_absent(__u32 ifindex,
                                         enum bpf_attach_type type)
{
  LIBBPF_OPTS(bpf_prog_query_opts, query);

  if (bpf_prog_query_opts((int)ifindex, type, &query) != 0) {
    if (errno == ENODEV)
      return 0;
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: query TCX chain: %s\n",
            strerror(errno));
    return -1;
  }
  if (query.count != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: TCX chain is not empty\n");
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

  if (program == NULL)
    return NULL;
  link = bpf_program__attach_tcx(program, (int)ifindex, &options);
  error = libbpf_get_error(link);
  if (error != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: attach TCX program: %s\n",
            strerror(-error));
    return NULL;
  }
  return link;
}

static int validate_attachment(struct bpf_link *link, __u32 ifindex,
                               enum bpf_attach_type type, __u32 program_id)
{
  LIBBPF_OPTS(bpf_prog_query_opts, query);
  struct bpf_link_info info;
  __u32 programs[2] = {0};
  __u32 links[2] = {0};
  __u32 size = sizeof(info);

  memset(&info, 0, sizeof(info));
  if (bpf_obj_get_info_by_fd(bpf_link__fd(link), &info, &size) != 0 ||
      info.id == 0 || info.type != BPF_LINK_TYPE_TCX ||
      info.prog_id != program_id || info.tcx.ifindex != ifindex ||
      info.tcx.attach_type != (__u32)type)
    return -1;
  query.count = 2;
  query.prog_ids = programs;
  query.link_ids = links;
  if (bpf_prog_query_opts((int)ifindex, type, &query) != 0 ||
      query.count != 1 || programs[0] != program_id || links[0] != info.id)
    return -1;
  return 0;
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

static int verify_pin_inventory(const char *root)
{
  static const char *expected[] = {
      "binding", "lease_state", "ingress_link", "egress_link"};
  bool found[EXPECTED_PIN_COUNT] = {false};
  DIR *directory = opendir(root);
  struct dirent *entry;
  unsigned int count = 0;

  if (directory == NULL)
    return -1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    bool matched = false;

    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    for (size_t index = 0; index < EXPECTED_PIN_COUNT; index++) {
      if (strcmp(entry->d_name, expected[index]) == 0 && !found[index]) {
        found[index] = true;
        matched = true;
        break;
      }
    }
    if (!matched) {
      closedir(directory);
      return -1;
    }
    count++;
  }
  if (errno != 0 || closedir(directory) != 0 || count != EXPECTED_PIN_COUNT)
    return -1;
  return 0;
}

struct opened_gate {
  struct installation paths;
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  int binding_fd;
  int state_fd;
  int ingress_fd;
  int egress_fd;
};

static void close_opened_gate(struct opened_gate *gate)
{
  if (gate->egress_fd >= 0)
    close(gate->egress_fd);
  if (gate->ingress_fd >= 0)
    close(gate->ingress_fd);
  if (gate->state_fd >= 0)
    close(gate->state_fd);
  if (gate->binding_fd >= 0)
    close(gate->binding_fd);
  gate->binding_fd = -1;
  gate->state_fd = -1;
  gate->ingress_fd = -1;
  gate->egress_fd = -1;
}

static bool direction_equal(
    const struct aos_network_direction_lease_v1 *left,
    const struct aos_network_direction_lease_v1 *right)
{
  return left->assignment_epoch == right->assignment_epoch &&
         left->lease_generation == right->lease_generation &&
         left->deadline_boottime_nanoseconds ==
             right->deadline_boottime_nanoseconds &&
         left->format_version == right->format_version &&
         left->armed == right->armed &&
         memcmp(&left->assignment_digest, &right->assignment_digest,
                sizeof(left->assignment_digest)) == 0 &&
         memcmp(&left->lease_digest, &right->lease_digest,
                sizeof(left->lease_digest)) == 0;
}

static bool direction_valid(
    const struct aos_network_direction_lease_v1 *direction,
    const struct aos_network_lease_binding_v1 *binding)
{
  bool lease_present = direction->lease_generation != 0 &&
                       direction->deadline_boottime_nanoseconds != 0 &&
                       digest_present(&direction->lease_digest);
  bool lease_absent = direction->lease_generation == 0 &&
                      direction->deadline_boottime_nanoseconds == 0 &&
                      !digest_present(&direction->lease_digest);

  return direction->format_version == AOS_NETWORK_LEASE_GATE_FORMAT_VERSION &&
         direction->armed <= 1 &&
         direction->assignment_epoch == binding->assignment_epoch &&
         memcmp(&direction->assignment_digest, &binding->assignment_digest,
                sizeof(direction->assignment_digest)) == 0 &&
         ((direction->armed == 1 && lease_present) ||
          (direction->armed == 0 && (lease_present || lease_absent)));
}

static int validate_pinned_attachment(int fd, __u32 ifindex,
                                      enum bpf_attach_type type,
                                      __u32 program_id)
{
  LIBBPF_OPTS(bpf_prog_query_opts, query);
  struct bpf_link_info info;
  __u32 programs[2] = {0};
  __u32 links[2] = {0};
  __u32 size = sizeof(info);

  memset(&info, 0, sizeof(info));
  if (bpf_obj_get_info_by_fd(fd, &info, &size) != 0 || info.id == 0 ||
      info.type != BPF_LINK_TYPE_TCX || info.prog_id != program_id ||
      info.tcx.ifindex != ifindex || info.tcx.attach_type != (__u32)type)
    return -1;
  query.count = 2;
  query.prog_ids = programs;
  query.link_ids = links;
  if (bpf_prog_query_opts((int)ifindex, type, &query) != 0 ||
      query.count != 1 || programs[0] != program_id || links[0] != info.id)
    return -1;
  return 0;
}

static int open_existing_gate(
    const char *handle_text, __u64 assignment_epoch,
    const struct aos_network_digest_v1 *expected_handle,
    const struct aos_network_digest_v1 *expected_assignment,
    struct opened_gate *gate)
{
  struct aos_network_boot_id_v1 boot_id;
  __u32 key = AOS_NETWORK_LEASE_GATE_BINDING_KEY;

  memset(gate, 0, sizeof(*gate));
  gate->binding_fd = -1;
  gate->state_fd = -1;
  gate->ingress_fd = -1;
  gate->egress_fd = -1;
  if (open_pin_root(handle_text, &gate->paths) != 0)
    goto invalid;
  gate->binding_fd = bpf_obj_get(gate->paths.binding_pin);
  gate->state_fd = bpf_obj_get(gate->paths.state_pin);
  gate->ingress_fd = bpf_obj_get(gate->paths.ingress_pin);
  gate->egress_fd = bpf_obj_get(gate->paths.egress_pin);
  if (gate->binding_fd < 0 || gate->state_fd < 0 || gate->ingress_fd < 0 ||
      gate->egress_fd < 0 ||
      validate_map(gate->binding_fd, BPF_MAP_TYPE_ARRAY,
                   sizeof(gate->binding), "binding") != 0 ||
      validate_map(gate->state_fd, BPF_MAP_TYPE_HASH, sizeof(gate->state),
                   "lease_state") != 0 ||
      bpf_map_lookup_elem(gate->binding_fd, &key, &gate->binding) != 0 ||
      bpf_map_lookup_elem(gate->state_fd, &key, &gate->state) != 0 ||
      parse_boot_id(&boot_id) != 0)
    goto invalid;
  if (gate->binding.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      gate->binding.provenance_version !=
          AOS_NETWORK_LEASE_GATE_PROVENANCE_VERSION ||
      gate->binding.reserved != 0 || gate->binding.provenance_reserved != 0 ||
      gate->binding.assignment_epoch != assignment_epoch ||
      gate->binding.allocation_generation == 0 ||
      gate->binding.namespace_device == 0 || gate->binding.namespace_inode == 0 ||
      gate->binding.host_ifindex == 0 || gate->binding.peer_ifindex == 0 ||
      gate->binding.ingress_program_id == 0 ||
      gate->binding.egress_program_id == 0 ||
      gate->binding.ingress_program_id == gate->binding.egress_program_id ||
      memcmp(&gate->binding.network_handle, expected_handle,
             sizeof(*expected_handle)) != 0 ||
      memcmp(&gate->binding.assignment_digest, expected_assignment,
             sizeof(*expected_assignment)) != 0 ||
      !digest_present(&gate->binding.gate_object_digest) ||
      memcmp(&gate->binding.kernel_boot_id, &boot_id, sizeof(boot_id)) != 0 ||
      gate->state.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      gate->state.reserved != 0 ||
      !direction_equal(&gate->state.ingress, &gate->state.egress) ||
      !direction_valid(&gate->state.ingress, &gate->binding) ||
      validate_pinned_attachment(gate->ingress_fd,
                                 gate->binding.host_ifindex, BPF_TCX_INGRESS,
                                 gate->binding.ingress_program_id) != 0 ||
      validate_pinned_attachment(gate->egress_fd,
                                 gate->binding.host_ifindex, BPF_TCX_EGRESS,
                                 gate->binding.egress_program_id) != 0)
    goto invalid;
  return 0;

invalid:
  fprintf(stderr,
          "aos-sandbox-network-lease-gate-loader: existing gate mismatch\n");
  close_opened_gate(gate);
  return -1;
}

static int open_removable_gate(
    const char *handle_text, __u64 assignment_epoch,
    const struct aos_network_digest_v1 *expected_handle,
    const struct aos_network_digest_v1 *expected_assignment,
    struct opened_gate *gate, bool *root_absent)
{
  struct aos_network_boot_id_v1 boot_id;
  unsigned int inventory;
  __u32 key = AOS_NETWORK_LEASE_GATE_BINDING_KEY;

  memset(gate, 0, sizeof(*gate));
  gate->binding_fd = -1;
  gate->state_fd = -1;
  gate->ingress_fd = -1;
  gate->egress_fd = -1;
  if (open_pin_root_for_removal(handle_text, &gate->paths, &inventory,
                                root_absent) != 0)
    goto invalid;
  if (*root_absent || inventory == 0)
    return 0;

  gate->binding_fd = bpf_obj_get(gate->paths.binding_pin);
  if ((inventory & PIN_STATE) != 0)
    gate->state_fd = bpf_obj_get(gate->paths.state_pin);
  if ((inventory & PIN_INGRESS) != 0)
    gate->ingress_fd = bpf_obj_get(gate->paths.ingress_pin);
  if ((inventory & PIN_EGRESS) != 0)
    gate->egress_fd = bpf_obj_get(gate->paths.egress_pin);
  if (gate->binding_fd < 0 ||
      ((inventory & PIN_STATE) != 0 && gate->state_fd < 0) ||
      ((inventory & PIN_INGRESS) != 0 && gate->ingress_fd < 0) ||
      ((inventory & PIN_EGRESS) != 0 && gate->egress_fd < 0) ||
      validate_map(gate->binding_fd, BPF_MAP_TYPE_ARRAY,
                   sizeof(gate->binding), "binding") != 0 ||
      bpf_map_lookup_elem(gate->binding_fd, &key, &gate->binding) != 0 ||
      parse_boot_id(&boot_id) != 0)
    goto invalid;
  if (gate->binding.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      gate->binding.provenance_version !=
          AOS_NETWORK_LEASE_GATE_PROVENANCE_VERSION ||
      gate->binding.reserved != 0 || gate->binding.provenance_reserved != 0 ||
      gate->binding.assignment_epoch != assignment_epoch ||
      gate->binding.allocation_generation == 0 ||
      gate->binding.namespace_device == 0 || gate->binding.namespace_inode == 0 ||
      gate->binding.host_ifindex == 0 || gate->binding.peer_ifindex == 0 ||
      gate->binding.ingress_program_id == 0 ||
      gate->binding.egress_program_id == 0 ||
      gate->binding.ingress_program_id == gate->binding.egress_program_id ||
      memcmp(&gate->binding.network_handle, expected_handle,
             sizeof(*expected_handle)) != 0 ||
      memcmp(&gate->binding.assignment_digest, expected_assignment,
             sizeof(*expected_assignment)) != 0 ||
      !digest_present(&gate->binding.gate_object_digest) ||
      memcmp(&gate->binding.kernel_boot_id, &boot_id, sizeof(boot_id)) != 0)
    goto invalid;
  if (gate->state_fd >= 0 &&
      (validate_map(gate->state_fd, BPF_MAP_TYPE_HASH, sizeof(gate->state),
                    "lease_state") != 0 ||
       bpf_map_lookup_elem(gate->state_fd, &key, &gate->state) != 0 ||
       gate->state.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
       gate->state.reserved != 0 ||
       !direction_equal(&gate->state.ingress, &gate->state.egress) ||
       !direction_valid(&gate->state.ingress, &gate->binding)))
    goto invalid;
  if ((gate->ingress_fd >= 0 &&
       validate_pinned_attachment(gate->ingress_fd,
                                  gate->binding.host_ifindex,
                                  BPF_TCX_INGRESS,
                                  gate->binding.ingress_program_id) != 0) ||
      (gate->ingress_fd < 0 &&
       require_empty_chain_or_absent(gate->binding.host_ifindex,
                                     BPF_TCX_INGRESS) != 0) ||
      (gate->egress_fd >= 0 &&
       validate_pinned_attachment(gate->egress_fd,
                                  gate->binding.host_ifindex,
                                  BPF_TCX_EGRESS,
                                  gate->binding.egress_program_id) != 0) ||
      (gate->egress_fd < 0 &&
       require_empty_chain_or_absent(gate->binding.host_ifindex,
                                     BPF_TCX_EGRESS) != 0))
    goto invalid;
  return 0;

invalid:
  fprintf(stderr,
          "aos-sandbox-network-lease-gate-loader: removable gate mismatch\n");
  close_opened_gate(gate);
  return -1;
}

static int replace_gate_state(
    struct opened_gate *gate,
    const struct aos_network_lease_state_v1 *replacement)
{
  struct aos_network_lease_state_v1 observed;
  __u32 key = AOS_NETWORK_LEASE_GATE_STATE_KEY;

  if (bpf_map_update_elem(gate->state_fd, &key, replacement, BPF_EXIST) != 0 ||
      bpf_map_lookup_elem(gate->state_fd, &key, &observed) != 0 ||
      memcmp(&observed, replacement, sizeof(observed)) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: replace lease state");
    return -1;
  }
  return 0;
}

static int set_gate_lease(struct opened_gate *gate, __u64 generation,
                          __u64 deadline,
                          const struct aos_network_digest_v1 *lease_digest)
{
  struct aos_network_lease_state_v1 replacement;

  if (deadline == 0 || !digest_present(lease_digest))
    return -1;
  memset(&replacement, 0, sizeof(replacement));
  replacement.format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  initialize_direction(&replacement.ingress, &gate->binding);
  replacement.ingress.armed = 1;
  replacement.ingress.lease_generation = generation;
  replacement.ingress.deadline_boottime_nanoseconds = deadline;
  replacement.ingress.lease_digest = *lease_digest;
  replacement.egress = replacement.ingress;
  if (direction_equal(&gate->state.ingress, &replacement.ingress))
    return 0;
  if (generation <= gate->state.ingress.lease_generation)
    return -1;
  return replace_gate_state(gate, &replacement);
}

static int set_gate_default_drop(struct opened_gate *gate)
{
  struct aos_network_lease_state_v1 replacement;

  memset(&replacement, 0, sizeof(replacement));
  replacement.format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  initialize_direction(&replacement.ingress, &gate->binding);
  replacement.egress = replacement.ingress;
  return replace_gate_state(gate, &replacement);
}

static int remove_gate(struct opened_gate *gate)
{
  __u32 host_ifindex = gate->binding.host_ifindex;

  if (gate->binding_fd < 0 && gate->state_fd < 0 && gate->ingress_fd < 0 &&
      gate->egress_fd < 0)
    return rmdir(gate->paths.root);

  if (gate->egress_fd >= 0) {
    if (unlink(gate->paths.egress_pin) != 0)
      return -1;
    close(gate->egress_fd);
    gate->egress_fd = -1;
  }
  if (require_empty_chain_or_absent(host_ifindex, BPF_TCX_EGRESS) != 0)
    return -1;
  if (gate->ingress_fd >= 0) {
    if (unlink(gate->paths.ingress_pin) != 0)
      return -1;
    close(gate->ingress_fd);
    gate->ingress_fd = -1;
  }
  if (require_empty_chain_or_absent(host_ifindex, BPF_TCX_INGRESS) != 0)
    return -1;
  if (gate->state_fd >= 0) {
    if (unlink(gate->paths.state_pin) != 0)
      return -1;
    close(gate->state_fd);
    gate->state_fd = -1;
  }
  if (gate->binding_fd >= 0) {
    if (unlink(gate->paths.binding_pin) != 0)
      return -1;
    close(gate->binding_fd);
    gate->binding_fd = -1;
  }
  if (rmdir(gate->paths.root) != 0)
    return -1;
  return 0;
}

static void cleanup_installation(const struct installation *install)
{
  if (!install->root_created)
    return;
  unlink(install->egress_pin);
  unlink(install->ingress_pin);
  unlink(install->state_pin);
  unlink(install->binding_pin);
  rmdir(install->root);
}

static int install_gate(struct aos_network_lease_binding_v1 *binding,
                        struct installation *install)
{
  struct aos_network_lease_state_v1 state;
  struct bpf_object *object = NULL;
  struct bpf_link *ingress = NULL;
  struct bpf_link *egress = NULL;
  __u32 key = AOS_NETWORK_LEASE_GATE_BINDING_KEY;
  int binding_fd = -1;
  int state_fd = -1;
  int result = -1;
  int error;

  if (require_empty_chain(binding->host_ifindex, BPF_TCX_INGRESS) != 0 ||
      require_empty_chain(binding->host_ifindex, BPF_TCX_EGRESS) != 0)
    goto out;
  object = bpf_object__open_file(AOS_NETWORK_LEASE_GATE_OBJECT, NULL);
  error = libbpf_get_error(object);
  if (error != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: open BPF object: %s\n",
            strerror(-error));
    object = NULL;
    goto out;
  }
  error = bpf_object__load(object);
  if (error != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: load BPF object: %s\n",
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
      validate_map(binding_fd, BPF_MAP_TYPE_ARRAY, sizeof(*binding),
                   "binding") != 0 ||
      validate_map(state_fd, BPF_MAP_TYPE_HASH, sizeof(state), "lease_state") !=
          0)
    goto out;

  memset(&state, 0, sizeof(state));
  state.format_version = AOS_NETWORK_LEASE_GATE_FORMAT_VERSION;
  initialize_direction(&state.ingress, binding);
  initialize_direction(&state.egress, binding);
  if (bpf_map_update_elem(binding_fd, &key, binding, BPF_EXIST) != 0 ||
      bpf_map_update_elem(state_fd, &key, &state, BPF_NOEXIST) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: initialize maps");
    goto out;
  }
  if (bpf_map_freeze(binding_fd) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: freeze binding map");
    goto out;
  }
  if (bpf_map_update_elem(binding_fd, &key, binding, BPF_EXIST) == 0 ||
      errno != EPERM) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: binding map is mutable\n");
    goto out;
  }
  if (bpf_obj_pin(binding_fd, install->binding_pin) != 0 ||
      bpf_obj_pin(state_fd, install->state_pin) != 0) {
    perror("aos-sandbox-network-lease-gate-loader: pin BPF map");
    goto out;
  }

  ingress = attach_program(object, "aos_network_lease_ingress",
                           binding->host_ifindex);
  if (ingress == NULL || bpf_link__pin(ingress, install->ingress_pin) != 0)
    goto out;
  egress = attach_program(object, "aos_network_lease_egress",
                          binding->host_ifindex);
  if (egress == NULL || bpf_link__pin(egress, install->egress_pin) != 0)
    goto out;
  if (validate_attachment(ingress, binding->host_ifindex, BPF_TCX_INGRESS,
                          binding->ingress_program_id) != 0 ||
      validate_attachment(egress, binding->host_ifindex, BPF_TCX_EGRESS,
                          binding->egress_program_id) != 0 ||
      verify_pin_inventory(install->root) != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: installed graph mismatch\n");
    goto out;
  }
  result = 0;

out:
  if (egress != NULL)
    bpf_link__destroy(egress);
  if (ingress != NULL)
    bpf_link__destroy(ingress);
  if (object != NULL)
    bpf_object__close(object);
  if (result != 0)
    cleanup_installation(install);
  return result;
}

int main(int argc, char **argv)
{
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_digest_v1 handle;
  struct aos_network_digest_v1 assignment;
  struct aos_network_digest_v1 gate_object;
  struct aos_network_digest_v1 lease_digest = {{0}};
  struct installation install;
  struct opened_gate gate;
  __u64 epoch;
  __u64 allocation;
  __u64 generation = 0;
  __u64 deadline = 0;
  bool root_absent = false;
  int result;

  if (getuid() != 0 || geteuid() != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: root identity required\n");
    return 1;
  }
  if ((argc == 5 &&
       (strcmp(argv[1], "set-default-drop") == 0 ||
        strcmp(argv[1], "remove") == 0)) ||
      (argc == 8 && strcmp(argv[1], "set-lease") == 0)) {
    if (parse_digest(argv[2], "network handle", &handle) != 0 ||
        parse_u64(argv[3], "assignment epoch", &epoch) != 0 ||
        parse_digest(argv[4], "assignment digest", &assignment) != 0 ||
        !digest_present(&handle) || !digest_present(&assignment))
      return 2;
    if (argc == 8 &&
        (parse_u64(argv[5], "lease generation", &generation) != 0 ||
         parse_u64(argv[6], "lease deadline", &deadline) != 0 ||
         parse_digest(argv[7], "lease digest", &lease_digest) != 0 ||
         !digest_present(&lease_digest)))
      return 2;
    if (strcmp(argv[1], "remove") == 0) {
      if (open_removable_gate(argv[2], epoch, &handle, &assignment, &gate,
                              &root_absent) != 0)
        return 1;
      if (root_absent)
        return 0;
      result = remove_gate(&gate);
    } else if (open_existing_gate(argv[2], epoch, &handle, &assignment,
                                  &gate) != 0) {
      return 1;
    } else if (strcmp(argv[1], "set-lease") == 0) {
      result = set_gate_lease(&gate, generation, deadline, &lease_digest);
    } else {
      result = set_gate_default_drop(&gate);
    }
    close_opened_gate(&gate);
    return result == 0 ? 0 : 1;
  }
  if (argc != 11 || strcmp(argv[1], "install-disarmed") != 0 ||
      strcmp(argv[4], "/proc/self/fd/3") != 0 ||
      strcmp(argv[10], AOS_NETWORK_LEASE_GATE_OBJECT) != 0) {
    usage();
    return 2;
  }
  if (parse_u64(argv[5], "assignment epoch", &epoch) != 0 ||
      parse_u64(argv[6], "allocation generation", &allocation) != 0 ||
      parse_digest(argv[7], "network handle", &handle) != 0 ||
      parse_digest(argv[8], "assignment digest", &assignment) != 0 ||
      parse_digest(argv[9], "gate object digest", &gate_object) != 0 ||
      !digest_present(&handle) || !digest_present(&assignment) ||
      !digest_present(&gate_object))
    return 2;
  if (fcntl(PEER_NAMESPACE_FD, F_GETFD) != 0) {
    fprintf(stderr,
            "aos-sandbox-network-lease-gate-loader: FD 3 must be the sole "
            "non-CLOEXEC namespace role\n");
    return 2;
  }
  if (build_binding(argv[2], argv[3], epoch, allocation, &handle, &assignment,
                    &gate_object, &binding) != 0)
    return 1;
  if (prepare_pin_root(argv[7], &install) != 0) {
    cleanup_installation(&install);
    return 1;
  }
  return install_gate(&binding, &install) == 0 ? 0 : 1;
}
