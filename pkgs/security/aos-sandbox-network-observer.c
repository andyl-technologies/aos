// SPDX-License-Identifier: Apache-2.0
/* Reads the fixed Network lease-gate BPF object graph without mutation. */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <linux/openat2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <aos/sandbox-network-lease-gate.h>

#define PIN_PREFIX "/sys/fs/bpf/aos/sandbox-network/"
#define EXPECTED_PIN_COUNT 4U

struct attachment_observation {
  __u32 link_id;
  __u32 program_id;
  __u8 program_tag[BPF_TAG_SIZE];
  __u32 ifindex;
  __u32 attach_type;
  __u32 map_ids[2];
};

struct root_identity {
  dev_t device;
  ino_t inode;
  mode_t mode;
  uid_t owner;
};

static bool valid_pin_root(const char *path)
{
  const char *suffix;

  if (strncmp(path, PIN_PREFIX, sizeof(PIN_PREFIX) - 1) != 0)
    return false;
  suffix = path + sizeof(PIN_PREFIX) - 1;
  if (strlen(suffix) != 64)
    return false;
  for (size_t index = 0; index < 64; index++) {
    char byte = suffix[index];

    if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f')))
      return false;
  }
  return true;
}

static bool expected_pin_name(const char *name)
{
  return strcmp(name, "binding") == 0 || strcmp(name, "lease_state") == 0 ||
         strcmp(name, "ingress_link") == 0 ||
         strcmp(name, "egress_link") == 0;
}

static int inspect_directory(int directory_fd, bool private,
                             struct root_identity *identity)
{
  struct statfs filesystem;
  struct stat status;

  if (fstat(directory_fd, &status) != 0 || !S_ISDIR(status.st_mode) ||
      status.st_uid != 0 || (status.st_mode & (private ? 077 : 022)) != 0) {
    fprintf(stderr,
            "aos-sandbox-network-observer: unsafe BPF directory\n");
    return -1;
  }
  if (private &&
      (fstatfs(directory_fd, &filesystem) != 0 ||
       filesystem.f_type != BPF_FS_MAGIC)) {
    fprintf(stderr,
            "aos-sandbox-network-observer: pin root is not bpffs\n");
    return -1;
  }
  identity->device = status.st_dev;
  identity->inode = status.st_ino;
  identity->mode = status.st_mode;
  identity->owner = status.st_uid;
  return 0;
}

static int open_directory_beneath(int parent_fd, const char *name)
{
  struct open_how how = {
      .flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
      .resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS |
                 RESOLVE_NO_SYMLINKS,
  };

  return syscall(SYS_openat2, parent_fd, name, &how, sizeof(how));
}

static int open_pin_root(const char *root, struct root_identity *identity)
{
  static const char *const fixed_segments[] = {
      "sys", "fs", "bpf", "aos", "sandbox-network",
  };
  const char *handle = root + sizeof(PIN_PREFIX) - 1;
  struct root_identity ignored;
  int directory_fd = -1;

  if (!valid_pin_root(root))
    return -1;
  directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory_fd < 0 || inspect_directory(directory_fd, false, &ignored) != 0)
    goto fail;
  for (size_t index = 0;
       index < sizeof(fixed_segments) / sizeof(fixed_segments[0]); index++) {
    int next_fd = open_directory_beneath(directory_fd, fixed_segments[index]);

    close(directory_fd);
    directory_fd = next_fd;
    if (directory_fd < 0 ||
        inspect_directory(directory_fd, false, &ignored) != 0)
      goto fail;
  }
  {
    int next_fd = open_directory_beneath(directory_fd, handle);

    close(directory_fd);
    directory_fd = next_fd;
  }
  if (directory_fd < 0 || inspect_directory(directory_fd, true, identity) != 0)
    goto fail;
  return directory_fd;

fail:
  if (directory_fd >= 0)
    close(directory_fd);
  perror("aos-sandbox-network-observer: open protected pin root");
  return -1;
}

static bool same_root(const struct root_identity *left,
                      const struct root_identity *right)
{
  return left->device == right->device && left->inode == right->inode &&
         left->mode == right->mode && left->owner == right->owner;
}

static int validate_complete_pin_set(int root_fd,
                                     const struct root_identity *identity)
{
  struct dirent *entry;
  unsigned int count = 0;
  int inventory_fd = openat(root_fd, ".",
                            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  DIR *directory;

  if (inventory_fd < 0) {
    perror("aos-sandbox-network-observer: open pin root");
    return -1;
  }
  directory = fdopendir(inventory_fd);
  if (directory == NULL) {
    close(inventory_fd);
    perror("aos-sandbox-network-observer: read pin root");
    return -1;
  }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (!expected_pin_name(entry->d_name)) {
      fprintf(stderr, "aos-sandbox-network-observer: unexpected BPF pin\n");
      closedir(directory);
      return -1;
    }
    struct stat status;

    if (fstatat(root_fd, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISREG(status.st_mode) || status.st_uid != 0 ||
        status.st_dev != identity->device || (status.st_mode & 077) != 0) {
      fprintf(stderr, "aos-sandbox-network-observer: unsafe BPF pin\n");
      closedir(directory);
      return -1;
    }
    count++;
  }
  if (errno != 0) {
    perror("aos-sandbox-network-observer: read pin root");
    closedir(directory);
    return -1;
  }
  if (closedir(directory) != 0 || count != EXPECTED_PIN_COUNT) {
    fprintf(stderr, "aos-sandbox-network-observer: incomplete BPF pin set\n");
    return -1;
  }
  return 0;
}

static int open_pinned_object(int root_fd, const char *pin)
{
  LIBBPF_OPTS(bpf_obj_get_opts, options, .file_flags = BPF_F_PATH_FD,
              .path_fd = root_fd);
  int fd = bpf_obj_get_opts(pin, &options);

  if (fd < 0)
    perror("aos-sandbox-network-observer: open object relative to pin root");
  return fd;
}

static int open_map(int root_fd, const char *pin, const char *name,
                    enum bpf_map_type type, __u32 value_size,
                    struct bpf_map_info *info)
{
  __u32 info_size = sizeof(*info);
  int fd;

  fd = open_pinned_object(root_fd, pin);
  if (fd < 0) {
    return -1;
  }
  memset(info, 0, sizeof(*info));
  if (bpf_obj_get_info_by_fd(fd, info, &info_size) != 0) {
    perror("aos-sandbox-network-observer: inspect map");
    close(fd);
    return -1;
  }
  if (info->id == 0 || info->type != (__u32)type ||
      info->key_size != sizeof(__u32) || info->value_size != value_size ||
      info->max_entries != 1 || info->map_flags != BPF_F_RDONLY_PROG ||
      strcmp((const char *)info->name, name) != 0) {
    fprintf(stderr, "aos-sandbox-network-observer: map schema mismatch\n");
    close(fd);
    return -1;
  }
  return fd;
}

static int inspect_attachment(int root_fd, const char *pin,
                              enum bpf_attach_type expected_type,
                              struct attachment_observation *observation)
{
  LIBBPF_OPTS(bpf_prog_query_opts, query);
  struct bpf_link_info link;
  struct bpf_prog_info program;
  __u32 query_programs[2] = {0};
  __u32 query_links[2] = {0};
  __u32 link_size = sizeof(link);
  __u32 program_size = sizeof(program);
  __u32 map_ids[3] = {0};
  int program_fd = -1;
  int link_fd = -1;
  int result = -1;

  link_fd = open_pinned_object(root_fd, pin);
  if (link_fd < 0) {
    goto out;
  }
  memset(&link, 0, sizeof(link));
  if (bpf_obj_get_info_by_fd(link_fd, &link, &link_size) != 0) {
    perror("aos-sandbox-network-observer: inspect link");
    goto out;
  }
  if (link.id == 0 || link.type != BPF_LINK_TYPE_TCX || link.prog_id == 0 ||
      link.tcx.ifindex == 0 ||
      link.tcx.attach_type != (__u32)expected_type) {
    fprintf(stderr, "aos-sandbox-network-observer: TCX link mismatch\n");
    goto out;
  }

  query.count = 2;
  query.prog_ids = query_programs;
  query.link_ids = query_links;
  if (bpf_prog_query_opts((int)link.tcx.ifindex, expected_type, &query) != 0 ||
      query.count != 1 || query_programs[0] != link.prog_id ||
      query_links[0] != link.id) {
    fprintf(stderr,
            "aos-sandbox-network-observer: TCX chain is not exact\n");
    goto out;
  }

  program_fd = bpf_prog_get_fd_by_id(link.prog_id);
  if (program_fd < 0) {
    perror("aos-sandbox-network-observer: open attached program");
    goto out;
  }
  memset(&program, 0, sizeof(program));
  program.nr_map_ids = 3;
  program.map_ids = (__u64)(uintptr_t)map_ids;
  if (bpf_obj_get_info_by_fd(program_fd, &program, &program_size) != 0) {
    perror("aos-sandbox-network-observer: inspect attached program");
    goto out;
  }
  if (program.id != link.prog_id || program.nr_map_ids != 2 ||
      memcmp(program.tag, (const __u8[BPF_TAG_SIZE]){0}, BPF_TAG_SIZE) == 0) {
    fprintf(stderr,
            "aos-sandbox-network-observer: program identity mismatch\n");
    goto out;
  }
  if (map_ids[0] > map_ids[1]) {
    __u32 temporary = map_ids[0];

    map_ids[0] = map_ids[1];
    map_ids[1] = temporary;
  }
  observation->link_id = link.id;
  observation->program_id = program.id;
  memcpy(observation->program_tag, program.tag, BPF_TAG_SIZE);
  observation->ifindex = link.tcx.ifindex;
  observation->attach_type = link.tcx.attach_type;
  observation->map_ids[0] = map_ids[0];
  observation->map_ids[1] = map_ids[1];
  result = 0;

out:
  if (program_fd >= 0)
    close(program_fd);
  if (link_fd >= 0)
    close(link_fd);
  return result;
}

static void print_hex(const void *value, size_t size)
{
  const unsigned char *bytes = value;

  for (size_t index = 0; index < size; index++)
    printf("%02x", bytes[index]);
}

static void print_map(const struct bpf_map_info *map)
{
  printf("{\"id\":%u,\"type\":%u,\"name\":\"%s\","
         "\"key_size\":%u,\"value_size\":%u,\"max_entries\":%u,"
         "\"flags\":%u}",
         map->id, map->type, map->name, map->key_size, map->value_size,
         map->max_entries, map->map_flags);
}

static void print_direction(
    const struct aos_network_direction_lease_v1 *direction)
{
  printf("{\"format_version\":%u,\"armed\":%u,"
         "\"assignment_epoch\":%llu,\"assignment_digest\":\"",
         direction->format_version, direction->armed,
         (unsigned long long)direction->assignment_epoch);
  print_hex(&direction->assignment_digest,
            sizeof(direction->assignment_digest));
  printf("\",\"lease_generation\":%llu,\"lease_digest\":\"",
         (unsigned long long)direction->lease_generation);
  print_hex(&direction->lease_digest, sizeof(direction->lease_digest));
  printf("\",\"deadline_boottime_nanoseconds\":%llu}",
         (unsigned long long)direction->deadline_boottime_nanoseconds);
}

static void print_attachment(const struct attachment_observation *attachment)
{
  printf("{\"link_id\":%u,\"program_id\":%u,\"program_tag\":\"",
         attachment->link_id, attachment->program_id);
  print_hex(attachment->program_tag, sizeof(attachment->program_tag));
  printf("\",\"ifindex\":%u,\"attach_type\":%u,"
         "\"map_ids\":[%u,%u]}",
         attachment->ifindex, attachment->attach_type,
         attachment->map_ids[0], attachment->map_ids[1]);
}

static int observe(const char *root)
{
  struct aos_network_lease_binding_v1 binding;
  struct aos_network_lease_state_v1 state;
  struct attachment_observation ingress;
  struct attachment_observation egress;
  struct bpf_map_info binding_map;
  struct bpf_map_info state_map;
  struct root_identity initial_root;
  struct root_identity final_root;
  __u32 key = AOS_NETWORK_LEASE_GATE_BINDING_KEY;
  int binding_fd = -1;
  int state_fd = -1;
  int root_fd = -1;
  int result = -1;

  root_fd = open_pin_root(root, &initial_root);
  if (root_fd < 0 || validate_complete_pin_set(root_fd, &initial_root) != 0) {
    fprintf(stderr, "aos-sandbox-network-observer: invalid pin root\n");
    goto out;
  }
  binding_fd = open_map(root_fd, "binding", "binding", BPF_MAP_TYPE_ARRAY,
                        sizeof(binding), &binding_map);
  state_fd = open_map(root_fd, "lease_state", "lease_state", BPF_MAP_TYPE_HASH,
                      sizeof(state), &state_map);
  if (binding_fd < 0 || state_fd < 0)
    goto out;
  memset(&binding, 0, sizeof(binding));
  memset(&state, 0, sizeof(state));
  if (bpf_map_lookup_elem(binding_fd, &key, &binding) != 0 ||
      bpf_map_lookup_elem(state_fd, &key, &state) != 0) {
    fprintf(stderr, "aos-sandbox-network-observer: missing map entry\n");
    goto out;
  }
  if (binding.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      binding.provenance_version !=
          AOS_NETWORK_LEASE_GATE_PROVENANCE_VERSION ||
      binding.reserved != 0 || binding.provenance_reserved != 0 ||
      memcmp(binding.reserved_tail, (const __u8[4]){0}, 4) != 0 ||
      state.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      state.reserved != 0 ||
      state.ingress.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      state.egress.format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      state.ingress.armed > 1 || state.egress.armed > 1) {
    fprintf(stderr, "aos-sandbox-network-observer: map value ABI mismatch\n");
    goto out;
  }
  if (inspect_attachment(root_fd, "ingress_link", BPF_TCX_INGRESS, &ingress) !=
          0 ||
      inspect_attachment(root_fd, "egress_link", BPF_TCX_EGRESS, &egress) !=
          0 ||
      ingress.ifindex != binding.host_ifindex ||
      egress.ifindex != binding.host_ifindex ||
      ingress.program_id != binding.ingress_program_id ||
      egress.program_id != binding.egress_program_id ||
      ingress.map_ids[0] !=
          (binding_map.id < state_map.id ? binding_map.id : state_map.id) ||
      ingress.map_ids[1] !=
          (binding_map.id < state_map.id ? state_map.id : binding_map.id) ||
      memcmp(ingress.map_ids, egress.map_ids, sizeof(ingress.map_ids)) != 0) {
    fprintf(stderr, "aos-sandbox-network-observer: BPF graph mismatch\n");
    goto out;
  }

  if (inspect_directory(root_fd, true, &final_root) != 0 ||
      !same_root(&initial_root, &final_root) ||
      validate_complete_pin_set(root_fd, &final_root) != 0) {
    fprintf(stderr,
            "aos-sandbox-network-observer: observation changed during read\n");
    goto out;
  }

  printf("{\"binding_map\":");
  print_map(&binding_map);
  printf(",\"state_map\":");
  print_map(&state_map);
  printf(",\"binding\":{\"format_version\":%u,"
         "\"provenance_version\":%u,\"ingress_program_id\":%u,"
         "\"egress_program_id\":%u,\"network_handle\":\"",
         binding.format_version, binding.provenance_version,
         binding.ingress_program_id, binding.egress_program_id);
  print_hex(&binding.network_handle, sizeof(binding.network_handle));
  printf("\",\"assignment_digest\":\"");
  print_hex(&binding.assignment_digest, sizeof(binding.assignment_digest));
  printf("\",\"gate_object_digest\":\"");
  print_hex(&binding.gate_object_digest, sizeof(binding.gate_object_digest));
  printf("\",\"assignment_epoch\":%llu,\"allocation_generation\":%llu,"
         "\"namespace_device\":%llu,\"namespace_inode\":%llu,"
         "\"boot_id\":\"",
         (unsigned long long)binding.assignment_epoch,
         (unsigned long long)binding.allocation_generation,
         (unsigned long long)binding.namespace_device,
         (unsigned long long)binding.namespace_inode);
  print_hex(&binding.kernel_boot_id, sizeof(binding.kernel_boot_id));
  printf("\",\"host_ifindex\":%u,\"peer_ifindex\":%u,"
         "\"host_mac\":\"",
         binding.host_ifindex, binding.peer_ifindex);
  print_hex(&binding.host_mac, sizeof(binding.host_mac));
  printf("\",\"peer_mac\":\"");
  print_hex(&binding.peer_mac, sizeof(binding.peer_mac));
  printf("\"},\"state\":{\"format_version\":%u,\"ingress\":",
         state.format_version);
  print_direction(&state.ingress);
  printf(",\"egress\":");
  print_direction(&state.egress);
  printf("},\"ingress\":");
  print_attachment(&ingress);
  printf(",\"egress\":");
  print_attachment(&egress);
  printf("}\n");
  if (fflush(stdout) != 0 || ferror(stdout)) {
    fprintf(stderr, "aos-sandbox-network-observer: write observation failed\n");
    goto out;
  }
  result = 0;

out:
  if (state_fd >= 0)
    close(state_fd);
  if (binding_fd >= 0)
    close(binding_fd);
  if (root_fd >= 0)
    close(root_fd);
  return result;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "usage: aos-sandbox-network-observer PIN_ROOT\n");
    return 2;
  }
  return observe(argv[1]) == 0 ? 0 : 1;
}
