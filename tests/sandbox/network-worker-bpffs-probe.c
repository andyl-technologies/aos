#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif

static int bpf_command(enum bpf_cmd command, union bpf_attr *attributes)
{
  return (int)syscall(SYS_bpf, command, attributes, sizeof(*attributes));
}

static int create_pinned_map(const char *pin_path)
{
  union bpf_attr create = {
      .map_type = BPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(uint32_t),
      .value_size = sizeof(uint32_t),
      .max_entries = 1,
  };
  union bpf_attr pin = {0};
  int map_fd;

  memcpy(create.map_name, "aos_bpffs_vm", sizeof("aos_bpffs_vm"));
  map_fd = bpf_command(BPF_MAP_CREATE, &create);
  if (map_fd < 0) {
    perror("network-worker-bpffs-probe: create BPF map");
    return -1;
  }

  pin.pathname = (__u64)(uintptr_t)pin_path;
  pin.bpf_fd = (__u32)map_fd;
  if (bpf_command(BPF_OBJ_PIN, &pin) != 0) {
    perror("network-worker-bpffs-probe: pin BPF map");
    close(map_fd);
    return -1;
  }

  return close(map_fd);
}

static int inspect_pinned_map(const char *pin_path)
{
  union bpf_attr get = {0};
  struct bpf_map_info information = {0};
  union bpf_attr info = {0};
  __u32 information_size = sizeof(information);
  int map_fd;

  get.pathname = (__u64)(uintptr_t)pin_path;
  map_fd = bpf_command(BPF_OBJ_GET, &get);
  if (map_fd < 0) {
    perror("network-worker-bpffs-probe: open pinned BPF map");
    return -1;
  }

  info.info.bpf_fd = (__u32)map_fd;
  info.info.info_len = information_size;
  info.info.info = (__u64)(uintptr_t)&information;
  if (bpf_command(BPF_OBJ_GET_INFO_BY_FD, &info) != 0 ||
      information.type != BPF_MAP_TYPE_ARRAY ||
      information.key_size != sizeof(uint32_t) ||
      information.value_size != sizeof(uint32_t) ||
      information.max_entries != 1 ||
      strcmp((const char *)information.name, "aos_bpffs_vm") != 0) {
    fprintf(stderr,
            "network-worker-bpffs-probe: pinned object identity mismatch\n");
    close(map_fd);
    return -1;
  }

  return close(map_fd);
}

static int require_read_only_file(const char *path)
{
  int descriptor = open(path, O_WRONLY | O_CLOEXEC);

  if (descriptor >= 0) {
    close(descriptor);
    fprintf(stderr,
            "network-worker-bpffs-probe: protected sysfs file is writable\n");
    return -1;
  }
  if (errno != EACCES && errno != EROFS) {
    perror("network-worker-bpffs-probe: test protected sysfs file");
    return -1;
  }
  return 0;
}

static int require_read_only_parent(const char *path)
{
  if (mkdir(path, 0700) == 0) {
    rmdir(path);
    fprintf(stderr,
            "network-worker-bpffs-probe: bpffs parent is unexpectedly writable\n");
    return -1;
  }
  if (errno != EACCES && errno != EROFS) {
    perror("network-worker-bpffs-probe: test protected bpffs parent");
    return -1;
  }
  return 0;
}

static int require_mount_read_only(const char *path, int expected_read_only)
{
  struct statvfs filesystem;

  if (statvfs(path, &filesystem) != 0) {
    perror("network-worker-bpffs-probe: inspect mount flags");
    return -1;
  }
  if (!!(filesystem.f_flag & ST_RDONLY) != expected_read_only) {
    fprintf(stderr,
            "network-worker-bpffs-probe: mount read-only state mismatch\n");
    return -1;
  }
  return 0;
}

static int record_worker_identity(const char *output_path, const char *pin_path)
{
  static const char *const outside_pin_parent =
      "/sys/fs/bpf/aos/outside-worker";
  static const char *const pin_parent =
      "/sys/fs/bpf/aos/sandbox-network";
  struct statfs filesystem;
  struct stat directory;
  struct stat mount_namespace;
  char identity[256];
  int length;
  int output_fd;

  if (statfs(pin_parent, &filesystem) != 0 ||
      (unsigned long)filesystem.f_type != (unsigned long)BPF_FS_MAGIC) {
    fprintf(stderr,
            "network-worker-bpffs-probe: worker pin parent is not bpffs\n");
    return -1;
  }
  if (lstat(pin_parent, &directory) != 0 || !S_ISDIR(directory.st_mode) ||
      directory.st_uid != 0 || directory.st_gid != 0 ||
      (directory.st_mode & 0777) != 0700) {
    fprintf(stderr,
            "network-worker-bpffs-probe: worker pin parent is unprotected\n");
    return -1;
  }
  if (stat("/proc/self/ns/mnt", &mount_namespace) != 0) {
    perror("network-worker-bpffs-probe: inspect worker mount namespace");
    return -1;
  }
  if (require_mount_read_only("/sys", 1) != 0 ||
      require_mount_read_only("/sys/fs/bpf/aos", 1) != 0 ||
      require_mount_read_only(pin_parent, 0) != 0 ||
      require_read_only_file("/sys/kernel/uevent_seqnum") != 0 ||
      require_read_only_parent(outside_pin_parent) != 0)
    return -1;
  if (create_pinned_map(pin_path) != 0)
    return -1;

  length = snprintf(identity, sizeof(identity), "%ju %ju %ju %lx\n",
                    (uintmax_t)directory.st_dev,
                    (uintmax_t)directory.st_ino,
                    (uintmax_t)mount_namespace.st_ino,
                    (unsigned long)filesystem.f_type);
  if (length <= 0 || (size_t)length >= sizeof(identity))
    return -1;

  output_fd = open(output_path,
                   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                   0600);
  if (output_fd < 0) {
    perror("network-worker-bpffs-probe: create identity record");
    return -1;
  }
  if (write(output_fd, identity, (size_t)length) != length ||
      fsync(output_fd) != 0 || close(output_fd) != 0) {
    perror("network-worker-bpffs-probe: persist identity record");
    return -1;
  }
  return 0;
}

static int connect_worker_socket(const char *socket_path)
{
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  ssize_t received;
  char byte;
  int socket_fd;

  if (strlen(socket_path) >= sizeof(address.sun_path)) {
    fprintf(stderr, "network-worker-bpffs-probe: socket path is too long\n");
    return -1;
  }
  memcpy(address.sun_path, socket_path, strlen(socket_path) + 1);

  socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    perror("network-worker-bpffs-probe: create client socket");
    return -1;
  }
  if (connect(socket_fd, (const struct sockaddr *)&address,
              offsetof(struct sockaddr_un, sun_path) + strlen(socket_path) + 1) !=
      0) {
    perror("network-worker-bpffs-probe: connect worker socket");
    close(socket_fd);
    return -1;
  }

  do {
    received = recv(socket_fd, &byte, sizeof(byte), 0);
  } while (received < 0 && errno == EINTR);
  if (received > 0 || (received < 0 && errno != ECONNRESET)) {
    perror("network-worker-bpffs-probe: wait for worker close");
    close(socket_fd);
    return -1;
  }
  return close(socket_fd);
}

int main(int argc, char **argv)
{
  if (argc == 4 && strcmp(argv[1], "worker") == 0)
    return record_worker_identity(argv[2], argv[3]) == 0 ? EXIT_SUCCESS
                                                         : EXIT_FAILURE;
  if (argc == 3 && strcmp(argv[1], "inspect") == 0)
    return inspect_pinned_map(argv[2]) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
  if (argc == 3 && strcmp(argv[1], "connect") == 0)
    return connect_worker_socket(argv[2]) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

  fprintf(stderr,
          "usage: network-worker-bpffs-probe worker OUTPUT PIN\n"
          "       network-worker-bpffs-probe inspect PIN\n"
          "       network-worker-bpffs-probe connect SOCKET\n");
  return EXIT_FAILURE;
}
