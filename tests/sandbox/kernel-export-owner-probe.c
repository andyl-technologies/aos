// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <openssl/evp.h>

#ifndef AOS_KERNEL_EXPORT_OWNER_BIN
#error "AOS_KERNEL_EXPORT_OWNER_BIN must name the packaged owner"
#endif

static const char handoff[] = "/var/lib/aos/kernel-export-owner/handoff";
static const unsigned char signature_domain[] =
    "aos.sandbox.storage.live-export-lease.signature.v1";
static const unsigned char handoff_domain[] =
    "aos.sandbox.storage.kernel-export-deny-handoff.v1";
static const unsigned char lease_digest_domain[] =
    "aos.sandbox.storage.live-export-lease.digest.v1";
static const unsigned char stage_domain[] =
    "aos.sandbox.kernel-export-owner.prepared-map.v1";
static const unsigned char ack_domain[] =
    "aos.sandbox.storage.kernel-export-stage-ack.signature.v1";
static const unsigned char record_domain[] =
    "aos.sandbox.kernel-export-owner.lease-record.v1";
static const char record_path[] =
    "/var/lib/aos/kernel-export-owner/lease-record";

static void be64(unsigned char *bytes, uint64_t value)
{
  for (int i = 7; i >= 0; i--) {
    bytes[i] = (unsigned char)value;
    value >>= 8;
  }
}

static uint64_t read_be64(const unsigned char *bytes)
{
  uint64_t value = 0;

  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | bytes[i];
  return value;
}

static int owner(const char *command, int clone, int cgroup,
                 const char *lease, const char *ack, const char *ttl)
{
  char clone_text[24], cgroup_text[24];
  pid_t child;
  int status;

  snprintf(clone_text, sizeof(clone_text), "%d", clone);
  snprintf(cgroup_text, sizeof(cgroup_text), "%d", cgroup);
  child = fork();
  if (child == 0) {
    if (clone >= 0 &&
        (fcntl(clone, F_SETFD, 0) != 0 ||
         fcntl(cgroup, F_SETFD, 0) != 0)) {
      dprintf(STDERR_FILENO, "kernel-export-owner-probe: %s descriptor transfer failed: %s\n",
              command, strerror(errno));
      _exit(127);
    }
    if (ttl != NULL)
      execl(AOS_KERNEL_EXPORT_OWNER_BIN, AOS_KERNEL_EXPORT_OWNER_BIN,
            command, clone_text, cgroup_text, handoff, lease, ack,
            ttl, (char *)NULL);
    else if (lease != NULL)
      execl(AOS_KERNEL_EXPORT_OWNER_BIN, AOS_KERNEL_EXPORT_OWNER_BIN,
            command, clone_text, cgroup_text, handoff, lease, ack,
            (char *)NULL);
    else if (clone >= 0)
      execl(AOS_KERNEL_EXPORT_OWNER_BIN, AOS_KERNEL_EXPORT_OWNER_BIN,
            command, clone_text, cgroup_text, handoff, (char *)NULL);
    else
      execl(AOS_KERNEL_EXPORT_OWNER_BIN, AOS_KERNEL_EXPORT_OWNER_BIN,
            command, (char *)NULL);
    dprintf(STDERR_FILENO, "kernel-export-owner-probe: %s exec failed: %s\n",
            command, strerror(errno));
    _exit(127);
  }
  return child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int write_exact(const char *path, const void *data, size_t size)
{
  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  ssize_t written = fd < 0 ? -1 : write(fd, data, size);
  if (fd >= 0)
    close(fd);
  return written == (ssize_t)size ? 0 : -1;
}

static int read_exact_file(const char *path, void *data, size_t size)
{
  unsigned char *bytes = data;
  size_t offset = 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);

  if (fd < 0)
    return -1;
  while (offset < size) {
    ssize_t count = read(fd, bytes + offset, size - offset);
    if (count <= 0) {
      close(fd);
      return -1;
    }
    offset += (size_t)count;
  }
  unsigned char extra;
  int result = read(fd, &extra, 1) == 0 ? 0 : -1;
  close(fd);
  return result;
}

static int digest_parts(const unsigned char *domain, size_t domain_size,
                        const void *bytes, size_t size,
                        unsigned char digest[32])
{
  unsigned int digest_size = 0;
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  int result = -1;

  if (context != NULL &&
      EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
      EVP_DigestUpdate(context, domain, domain_size) == 1 &&
      EVP_DigestUpdate(context, bytes, size) == 1 &&
      EVP_DigestFinal_ex(context, digest, &digest_size) == 1 &&
      digest_size == 32)
    result = 0;
  EVP_MD_CTX_free(context);
  return result;
}

static int boot_bytes(unsigned char boot[16])
{
  char uuid[40] = {0};
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  ssize_t length = fd < 0 ? -1 : read(fd, uuid, sizeof(uuid) - 1);
  size_t output = 0;

  if (fd >= 0)
    close(fd);
  if (length < 36)
    return -1;
  for (size_t i = 0; i < 36;) {
    unsigned int value;
    if (uuid[i] == '-') {
      i++;
      continue;
    }
    if (output >= 16 || sscanf(uuid + i, "%2x", &value) != 1)
      return -1;
    boot[output++] = (unsigned char)value;
    i += 2;
  }
  return output == 16 ? 0 : -1;
}

static int unique_mount_id(int fd, uint64_t *mount_id)
{
  struct statx state = {0};

  if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE,
              &state) != 0 || (state.stx_mask & STATX_MNT_ID_UNIQUE) == 0)
    return -1;
  *mount_id = state.stx_mnt_id;
  return 0;
}

static int make_handoff(int clone_fd, int cgroup_fd)
{
  unsigned char frame[344], digest[32];
  struct stat root, cgroup;
  uint64_t mount_id;
  unsigned int size = 0;
  EVP_MD_CTX *context = NULL;
  int result = -1;

  memset(frame, 0x44, sizeof(frame));
  memcpy(frame, "AOSKGH01", 8);
  frame[8] = 0;
  frame[9] = 1;
  frame[10] = 1;
  memset(frame + 11, 0, 5);
  if (fstat(clone_fd, &root) != 0 || fstat(cgroup_fd, &cgroup) != 0 ||
      unique_mount_id(clone_fd, &mount_id) != 0 ||
      boot_bytes(frame + 224) != 0)
    goto out;
  be64(frame + 64, 1);
  be64(frame + 184, 1);
  be64(frame + 240, mount_id);
  be64(frame + 248, root.st_dev);
  be64(frame + 256, root.st_ino);
  be64(frame + 280, 1);
  be64(frame + 320, cgroup.st_ino);
  be64(frame + 328, 0);
  be64(frame + 336, (uint64_t)time(NULL) + 60);
  context = EVP_MD_CTX_new();
  if (context == NULL ||
      EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(context, handoff_domain,
                       sizeof(handoff_domain)) != 1 ||
      EVP_DigestUpdate(context, frame + 48, sizeof(frame) - 48) != 1 ||
      EVP_DigestFinal_ex(context, digest, &size) != 1 || size != 32)
    goto out;
  memcpy(frame + 16, digest, sizeof(digest));
  result = write_exact(handoff, frame, sizeof(frame));

out:
  EVP_MD_CTX_free(context);
  return result;
}

static int make_lease(int source_fd, int clone_fd)
{
  unsigned char lease[496], verifier[112], seed[32], message[sizeof(signature_domain) + 432];
  unsigned char frame[344];
  struct stat state;
  uint64_t origin_id, clone_id;
  size_t public_size = 32, signature_size = 64;
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  int result = -1;

  memset(lease, 0x22, sizeof(lease));
  memset(verifier, 0, sizeof(verifier));
  memset(seed, 0x33, sizeof(seed));
  memcpy(lease, "AOSSLE01", 8);
  lease[8] = 0;
  lease[9] = 1;
  memset(lease + 10, 0, 6);
  if (read_exact_file(handoff, frame, sizeof(frame)) != 0 ||
      fstat(source_fd, &state) != 0 ||
      unique_mount_id(source_fd, &origin_id) != 0 ||
      unique_mount_id(clone_fd, &clone_id) != 0 ||
      origin_id == clone_id || boot_bytes(lease + 200) != 0)
    goto out;
  be64(lease + 96, 1);
  be64(lease + 216, state.st_dev);
  be64(lease + 224, state.st_ino);
  be64(lease + 232, origin_id);
  memcpy(lease + 288, frame + 48, 16);
  be64(lease + 304, 1);
  be64(lease + 328, 1);
  be64(lease + 336, (uint64_t)time(NULL) - 1);
  be64(lease + 344, (uint64_t)time(NULL) + 30);
  be64(lease + 368, 1);
  be64(lease + 424, 1);
  memcpy(verifier, lease + 352, 80);

  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
  context = EVP_MD_CTX_new();
  if (key == NULL || context == NULL ||
      EVP_PKEY_get_raw_public_key(key, verifier + 80, &public_size) != 1 ||
      public_size != 32 ||
      EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1)
    goto out;
  memcpy(message, signature_domain, sizeof(signature_domain));
  memcpy(message + sizeof(signature_domain), lease, 432);
  if (EVP_DigestSign(context, lease + 432, &signature_size,
                     message, sizeof(message)) != 1 || signature_size != 64 ||
      write_exact("/var/lib/aos/kernel-export-owner/lease", lease,
                  sizeof(lease)) != 0 ||
      write_exact("/var/lib/aos/kernel-export-owner/storage-verifier", verifier,
                  sizeof(verifier)) != 0)
    goto out;
  result = 0;

out:
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

static int lease_names_origin(int source_fd, int clone_fd)
{
  unsigned char lease[496];
  struct stat origin, clone;
  uint64_t origin_id, clone_id;

  if (read_exact_file("/var/lib/aos/kernel-export-owner/lease",
                      lease, sizeof(lease)) != 0 ||
      fstat(source_fd, &origin) != 0 || fstat(clone_fd, &clone) != 0 ||
      unique_mount_id(source_fd, &origin_id) != 0 ||
      unique_mount_id(clone_fd, &clone_id) != 0 ||
      origin_id == clone_id ||
      read_be64(lease + 216) != origin.st_dev ||
      read_be64(lease + 224) != origin.st_ino ||
      read_be64(lease + 232) != origin_id ||
      read_be64(lease + 232) == clone_id ||
      origin.st_dev != clone.st_dev || origin.st_ino != clone.st_ino)
    return -1;
  return 0;
}

static int reject_signed_origin_device_mismatch(int clone_fd, int cgroup_fd,
                                                const char *lease,
                                                const char *ack)
{
  unsigned char original[496], changed[496], seed[32];
  unsigned char message[sizeof(signature_domain) + 432];
  unsigned char original_ack[576], changed_ack[576];
  unsigned char ack_message[sizeof(ack_domain) + 512];
  size_t signature_size = 64;
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  int fd = -1, ack_fd = -1, result = -1;

  if (read_exact_file(lease, original, sizeof(original)) != 0 ||
      read_exact_file(ack, original_ack, sizeof(original_ack)) != 0)
    return -1;
  memcpy(changed, original, sizeof(changed));
  memcpy(changed_ack, original_ack, sizeof(changed_ack));
  changed[216] ^= 1;
  memset(seed, 0x33, sizeof(seed));
  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
  context = EVP_MD_CTX_new();
  if (key == NULL || context == NULL ||
      EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1)
    goto out;
  memcpy(message, signature_domain, sizeof(signature_domain));
  memcpy(message + sizeof(signature_domain), changed, 432);
  if (EVP_DigestSign(context, changed + 432, &signature_size,
                     message, sizeof(message)) != 1 || signature_size != 64)
    goto out;
  if (digest_parts(lease_digest_domain, sizeof(lease_digest_domain),
                   changed, sizeof(changed), changed_ack + 360) != 0 ||
      EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1)
    goto out;
  memcpy(ack_message, ack_domain, sizeof(ack_domain));
  memcpy(ack_message + sizeof(ack_domain), changed_ack, 512);
  signature_size = 64;
  if (EVP_DigestSign(context, changed_ack + 512, &signature_size,
                     ack_message, sizeof(ack_message)) != 1 ||
      signature_size != 64)
    goto out;

  fd = open(lease, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  ack_fd = open(ack, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0 || ack_fd < 0 ||
      pwrite(fd, changed, sizeof(changed), 0) !=
          (ssize_t)sizeof(changed) ||
      pwrite(ack_fd, changed_ack, sizeof(changed_ack), 0) !=
          (ssize_t)sizeof(changed_ack))
    goto out;
  int rejected = owner("record", clone_fd, cgroup_fd, lease, ack, NULL) != 0;
  if (pwrite(fd, original, sizeof(original), 0) !=
          (ssize_t)sizeof(original) ||
      pwrite(ack_fd, original_ack, sizeof(original_ack), 0) !=
          (ssize_t)sizeof(original_ack))
    goto out;
  result = rejected ? 0 : -1;

out:
  if (fd >= 0)
    close(fd);
  if (ack_fd >= 0)
    close(ack_fd);
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

static int make_stage_ack(uint64_t clone_id)
{
  struct {
    uint64_t boot[2], epoch, device, inode, cgroup_id;
    uint64_t handoff_digest[4], lease_digest[4];
    uint32_t version, phase;
  } policy;
  unsigned char frame[344], lease[496], verifier[112], ack[576] = {0};
  unsigned char canonical[128] = {0}, seed[32], message[sizeof(ack_domain) + 512];
  size_t signature_size = 64;
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  int map_fd = -1;
  int result = -1;

  _Static_assert(sizeof(policy) == 120, "owner policy map ABI changed");
  map_fd = bpf_obj_get("/sys/fs/bpf/aos/kernel-export-owner/export_mounts");
  if (map_fd < 0 || bpf_map_lookup_elem(map_fd, &clone_id, &policy) != 0 ||
      policy.version != 3 || policy.phase != 1 ||
      read_exact_file(handoff, frame, sizeof(frame)) != 0 ||
      read_exact_file("/var/lib/aos/kernel-export-owner/lease", lease,
                      sizeof(lease)) != 0 ||
      read_exact_file("/var/lib/aos/kernel-export-owner/storage-verifier",
                      verifier, sizeof(verifier)) != 0)
    goto out;

  memcpy(canonical, policy.boot, 16);
  be64(canonical + 16, clone_id);
  be64(canonical + 24, policy.epoch);
  be64(canonical + 32, policy.device);
  be64(canonical + 40, policy.inode);
  be64(canonical + 48, policy.cgroup_id);
  memcpy(canonical + 56, policy.handoff_digest, 32);
  memcpy(canonical + 88, policy.lease_digest, 32);
  canonical[123] = (unsigned char)policy.version;
  canonical[127] = (unsigned char)policy.phase;

  memcpy(ack, "AOSKGA01", 8);
  ack[9] = 1;
  memcpy(ack + 16, frame, sizeof(frame));
  be64(ack + 392, policy.epoch);
  memcpy(ack + 432, verifier, 80);
  if (digest_parts(lease_digest_domain, sizeof(lease_digest_domain),
                   lease, sizeof(lease), ack + 360) != 0 ||
      digest_parts(stage_domain, sizeof(stage_domain), canonical,
                   sizeof(canonical), ack + 400) != 0)
    goto out;

  memset(seed, 0x33, sizeof(seed));
  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
  context = EVP_MD_CTX_new();
  if (key == NULL || context == NULL ||
      EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1)
    goto out;
  memcpy(message, ack_domain, sizeof(ack_domain));
  memcpy(message + sizeof(ack_domain), ack, 512);
  if (EVP_DigestSign(context, ack + 512, &signature_size,
                     message, sizeof(message)) != 1 || signature_size != 64 ||
      write_exact("/var/lib/aos/kernel-export-owner/ack", ack,
                  sizeof(ack)) != 0)
    goto out;
  result = 0;

out:
  if (map_fd >= 0)
    close(map_fd);
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

static int reject_tampered_ack(int clone_fd, int cgroup_fd,
                               const char *lease, const char *ack)
{
  unsigned char original, changed;
  int fd = open(ack, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
  int rejected;
  int restored;

  if (fd < 0 || pread(fd, &original, 1, 400) != 1) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  changed = original ^ 1;
  if (pwrite(fd, &changed, 1, 400) != 1) {
    close(fd);
    return -1;
  }
  rejected = owner("activate", clone_fd, cgroup_fd, lease, ack,
                   "10000") != 0 &&
             owner("record", clone_fd, cgroup_fd, lease, ack, NULL) != 0;
  restored = pwrite(fd, &original, 1, 400) == 1;
  close(fd);
  return rejected && restored ? 0 : -1;
}

static int reject_signed_ack_mismatch(int clone_fd, int cgroup_fd,
                                      const char *lease, const char *ack,
                                      size_t offset)
{
  unsigned char original[576], changed[576], seed[32];
  unsigned char message[sizeof(ack_domain) + 512];
  size_t signature_size = 64;
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  int fd = -1;
  int result = -1;

  if (offset >= 512 || read_exact_file(ack, original, sizeof(original)) != 0)
    return -1;
  memcpy(changed, original, sizeof(changed));
  changed[offset] ^= 1;
  memset(seed, 0x33, sizeof(seed));
  key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, seed, sizeof(seed));
  context = EVP_MD_CTX_new();
  if (key == NULL || context == NULL ||
      EVP_DigestSignInit(context, NULL, NULL, NULL, key) != 1)
    goto out;
  memcpy(message, ack_domain, sizeof(ack_domain));
  memcpy(message + sizeof(ack_domain), changed, 512);
  if (EVP_DigestSign(context, changed + 512, &signature_size,
                     message, sizeof(message)) != 1 || signature_size != 64)
    goto out;

  fd = open(ack, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0 || pwrite(fd, changed, sizeof(changed), 0) !=
                    (ssize_t)sizeof(changed))
    goto out;
  int rejected = owner("activate", clone_fd, cgroup_fd, lease, ack,
                       "10000") != 0 &&
                 owner("record", clone_fd, cgroup_fd, lease, ack, NULL) != 0;
  if (pwrite(fd, original, sizeof(original), 0) !=
      (ssize_t)sizeof(original))
    goto out;
  result = rejected ? 0 : -1;

out:
  if (fd >= 0)
    close(fd);
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

static int reject_record_mutation(int clone_fd, int cgroup_fd,
                                  size_t offset, int recompute_digest)
{
  unsigned char original[1208], changed[1208];
  int fd = -1, result = -1;

  if (offset >= sizeof(changed) ||
      read_exact_file(record_path, original, sizeof(original)) != 0)
    return -1;
  memcpy(changed, original, sizeof(changed));
  changed[offset] ^= 1;
  if (recompute_digest &&
      digest_parts(record_domain, sizeof(record_domain),
                   changed, 1176, changed + 1176) != 0)
    return -1;

  fd = open(record_path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0 || pwrite(fd, changed, sizeof(changed), 0) !=
                    (ssize_t)sizeof(changed))
    goto out;
  int rejected = owner("inspect-record", clone_fd, cgroup_fd,
                       NULL, NULL, NULL) != 0;
  if (pwrite(fd, original, sizeof(original), 0) !=
      (ssize_t)sizeof(original))
    goto out;
  result = rejected ? 0 : -1;

out:
  if (fd >= 0)
    close(fd);
  return result;
}

static int move_to_cgroup(const char *directory)
{
  char path[256], pid[24];
  int fd;
  int length;
  ssize_t written;

  if (snprintf(path, sizeof(path), "%s/cgroup.procs", directory) >=
      (int)sizeof(path))
    return -1;
  fd = open(path, O_WRONLY | O_CLOEXEC);
  length = snprintf(pid, sizeof(pid), "%ld", (long)getpid());
  written = fd < 0 ? -1 : write(fd, pid, (size_t)length);
  if (fd >= 0)
    close(fd);
  return written == length ? 0 : -1;
}

static int denied_read(int fd)
{
  char byte;
  errno = 0;
  return pread(fd, &byte, 1, 0) == -1 && errno == EACCES ? 0 : -1;
}

static int denied_scm_receive(int socket_fd)
{
  char byte, control[CMSG_SPACE(sizeof(int))] = {0};
  struct iovec io = {.iov_base = &byte, .iov_len = 1};
  struct msghdr message = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  ssize_t received = recvmsg(socket_fd, &message, 0);
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);

  /* Linux discards a denied descriptor and marks truncated ancillary data. */
  return received == 1 && (message.msg_flags & MSG_CTRUNC) != 0 &&
         (header == NULL || header->cmsg_len < CMSG_LEN(sizeof(int))) ? 0 : -1;
}

static int send_source_fd(int socket_fd, int source_fd)
{
  char byte = 'x', control[CMSG_SPACE(sizeof(source_fd))] = {0};
  struct iovec io = {.iov_base = &byte, .iov_len = 1};
  struct msghdr message = {
      .msg_iov = &io,
      .msg_iovlen = 1,
      .msg_control = control,
      .msg_controllen = sizeof(control),
  };
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);

  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(source_fd));
  memcpy(CMSG_DATA(header), &source_fd, sizeof(source_fd));
  return sendmsg(socket_fd, &message, 0) == 1 ? 0 : -1;
}

static int outside_child(const char *outside, int data_fd)
{
  int sockets[2];
  pid_t child;
  int status;

  if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, sockets) != 0)
    return -1;
  child = fork();

  if (child == 0) {
    close(sockets[0]);
    if (move_to_cgroup(outside) != 0 || denied_read(data_fd) != 0 ||
        denied_scm_receive(sockets[1]) != 0)
      _exit(1);
    _exit(0);
  }
  close(sockets[1]);
  if (child < 0 || send_source_fd(sockets[0], data_fd) != 0 ||
      waitpid(child, &status, 0) != child ||
      !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    close(sockets[0]);
    return -1;
  }
  close(sockets[0]);
  return 0;
}

static int conflicting_source_lock(int source_fd, int protected_fd)
{
  struct flock lock = {
      .l_type = F_WRLCK,
      .l_whence = SEEK_SET,
      .l_len = 1,
  };
  pid_t child = fork();
  int status;

  if (child == 0) {
    int fd;
    close(protected_fd);
    fd = openat(source_fd, "data", O_RDWR | O_CLOEXEC);
    errno = 0;
    if (fd < 0 || fcntl(fd, F_OFD_SETLK, &lock) != -1 ||
        (errno != EAGAIN && errno != EACCES))
      _exit(1);
    close(fd);
    _exit(0);
  }
  return child > 0 && waitpid(child, &status, 0) == child &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int start_blocked_fifo_reader(int fifo_fd, int *ready_fd, pid_t *reader)
{
  int sync[2];
  char ready;

  if (pipe2(sync, O_CLOEXEC) != 0)
    return -1;
  *reader = fork();
  if (*reader == 0) {
    char byte;
    close(sync[0]);
    if (write(sync[1], "r", 1) != 1 || read(fifo_fd, &byte, 1) != 1 ||
        byte != 'f')
      _exit(1);
    _exit(0);
  }
  close(sync[1]);
  if (*reader < 0 || read(sync[0], &ready, 1) != 1 || ready != 'r') {
    close(sync[0]);
    return -1;
  }
  *ready_fd = sync[0];
  usleep(100000);
  return 0;
}

static int await_fifo_reader(pid_t reader, int ready_fd, int writer_fd)
{
  int status;

  close(ready_fd);
  return write(writer_fd, "f", 1) == 1 &&
         waitpid(reader, &status, 0) == reader &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int make_socket_listener(const char *source)
{
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

  if (snprintf(address.sun_path, sizeof(address.sun_path),
               "%s/live.sock", source) >= (int)sizeof(address.sun_path) ||
      fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(fd, 1) != 0) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  return fd;
}

static int connect_clone_socket(const char *attached, int listener,
                                int *client, int *server)
{
  struct sockaddr_un address = {.sun_family = AF_UNIX};

  if (snprintf(address.sun_path, sizeof(address.sun_path),
               "%s/live.sock", attached) >= (int)sizeof(address.sun_path))
    return -1;
  *client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client < 0 ||
      connect(*client, (struct sockaddr *)&address, sizeof(address)) != 0)
    return -1;
  *server = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  return *server >= 0 ? 0 : -1;
}

static int connected_socket_survived(int client, int server)
{
  char byte;

  return send(client, "s", 1, 0) == 1 &&
         recv(server, &byte, 1, 0) == 1 && byte == 's' ? 0 : -1;
}

static int start_escaped_holder(const char *outside, const void *mapping,
                                unsigned char expected, int socket_fd,
                                pid_t *holder, int *release_fd)
{
  int ready[2], release[2];
  char signal;

  if (pipe2(ready, O_CLOEXEC) != 0 || pipe2(release, O_CLOEXEC) != 0)
    return -1;
  *holder = fork();
  if (*holder == 0) {
    close(ready[0]);
    close(release[1]);
    if (move_to_cgroup(outside) != 0 || write(ready[1], "r", 1) != 1 ||
        read(release[0], &signal, 1) != 1 || signal != 'g' ||
        ((const volatile unsigned char *)mapping)[0] != expected ||
        send(socket_fd, "e", 1, 0) != 1)
      _exit(1);
    _exit(0);
  }
  close(ready[1]);
  close(release[0]);
  if (*holder < 0 || read(ready[0], &signal, 1) != 1 || signal != 'r') {
    close(ready[0]);
    close(release[1]);
    return -1;
  }
  close(ready[0]);
  *release_fd = release[1];
  return 0;
}

static int kill_and_check_empty(const char *allowed)
{
  char path[256], events[256];
  int fd;

  if (snprintf(path, sizeof(path), "%s/cgroup.kill", allowed) >=
      (int)sizeof(path))
    return -1;
  fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0 || write(fd, "1\n", 2) != 2) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  close(fd);
  if (snprintf(path, sizeof(path), "%s/cgroup.events", allowed) >=
      (int)sizeof(path))
    return -1;
  for (int attempt = 0; attempt < 200; attempt++) {
    ssize_t length;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    length = fd < 0 ? -1 : read(fd, events, sizeof(events) - 1);
    if (fd >= 0)
      close(fd);
    if (length <= 0)
      return -1;
    events[length] = '\0';
    if (strstr(events, "populated 0\n") != NULL)
      return 0;
    usleep(10000);
  }
  return -1;
}

static int finish_escaped_holder(pid_t holder, int release_fd, int server)
{
  struct pollfd ready = {.fd = server, .events = POLLIN};
  char byte;
  int status;

  if (write(release_fd, "g", 1) != 1)
    return -1;
  close(release_fd);
  return poll(&ready, 1, 5000) == 1 &&
         recv(server, &byte, 1, 0) == 1 && byte == 'e' &&
         waitpid(holder, &status, 0) == holder &&
         WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int mutate_grant(uint64_t clone_id, uint64_t cgroup_id, int epoch)
{
  struct {
    uint64_t mount_id, cgroup_id;
  } key = {clone_id, cgroup_id};
  struct {
    uint64_t boot[2], epoch, expiry, digest[4];
    uint32_t state, version;
  } value;
  int fd = bpf_obj_get("/sys/fs/bpf/aos/kernel-export-owner/consumer_grants");
  int result = fd < 0 ? -1 : bpf_map_lookup_elem(fd, &key, &value);

  if (result == 0) {
    if (epoch)
      value.epoch ^= 1;
    else
      value.digest[0] ^= 1;
    result = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
  }
  if (fd >= 0)
    close(fd);
  return result;
}

int main(int argc, char **argv)
{
  const char *allowed = "/sys/fs/cgroup/kernel-export-owner-allowed";
  const char *outside = "/sys/fs/cgroup/kernel-export-owner-outside";
  const char *lease = "/var/lib/aos/kernel-export-owner/lease";
  const char *ack = "/var/lib/aos/kernel-export-owner/ack";
  const char *lease_backup = "/var/lib/aos/kernel-export-owner/lease.bak";
  const char *ack_backup = "/var/lib/aos/kernel-export-owner/ack.bak";
  const char *attached = "/run/kernel-export-owner-attached";
  struct mount_attr attributes = {
      .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
  };
  struct flock read_lock = {
      .l_type = F_RDLCK,
      .l_whence = SEEK_SET,
      .l_len = 1,
  };
  struct stat cgroup_stat;
  uint64_t clone_id;
  char byte;
  int source_fd, clone_fd, wrong_clone, allowed_fd, outside_fd, data_fd;
  int preopened_fd, fifo_writer, fifo_reader, fifo_ready, listener;
  int socket_client, socket_server, escaped_release;
  pid_t blocked_reader, escaped_holder;
  void *mapping;

  if (argc != 2 || mkdir(allowed, 0700) != 0 ||
      mkdir(outside, 0700) != 0 ||
      (mkdir("/var/lib/aos", 0700) != 0 && errno != EEXIST))
    return 2;
  source_fd = open(argv[1], O_PATH | O_DIRECTORY | O_CLOEXEC);
  allowed_fd = open(allowed, O_PATH | O_DIRECTORY | O_CLOEXEC);
  outside_fd = open(outside, O_PATH | O_DIRECTORY | O_CLOEXEC);
  listener = make_socket_listener(argv[1]);
  fifo_writer = mkfifoat(source_fd, "fifo", 0600) == 0 ?
      openat(source_fd, "fifo", O_RDWR | O_NONBLOCK | O_CLOEXEC) : -1;
  clone_fd = syscall(__NR_open_tree_attr, source_fd, "",
                     OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH,
                     &attributes, sizeof(attributes));
  wrong_clone = syscall(__NR_open_tree_attr, source_fd, "",
                        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH,
                        &attributes, sizeof(attributes));
  preopened_fd = openat(clone_fd, "data", O_RDONLY | O_CLOEXEC);
  if (source_fd < 0 || allowed_fd < 0 || outside_fd < 0 ||
      clone_fd < 0 || wrong_clone < 0 || listener < 0 || fifo_writer < 0 ||
      preopened_fd < 0) {
    fprintf(stderr,
            "kernel-export-owner-probe: fixture descriptors failed "
            "source=%d allowed=%d outside=%d clone=%d other=%d "
            "socket=%d fifo=%d data=%d: %s\n",
            source_fd, allowed_fd, outside_fd, clone_fd, wrong_clone,
            listener, fifo_writer, preopened_fd, strerror(errno));
    return 1;
  }
  if (fcntl(preopened_fd, F_OFD_SETLK, &read_lock) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: pre-stage OFD lock failed: %s\n",
            strerror(errno));
    return 1;
  }
  if (unique_mount_id(clone_fd, &clone_id) != 0 ||
      fstat(allowed_fd, &cgroup_stat) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: identity readback failed: %s\n",
            strerror(errno));
    return 1;
  }
  if (mkdir("/var/lib/aos/kernel-export-owner", 0700) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: private state directory failed: %s\n",
            strerror(errno));
    return 1;
  }
  if (make_handoff(clone_fd, allowed_fd) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: handoff fixture failed: %s\n",
            strerror(errno));
    return 1;
  }
  if (owner("stage", clone_fd, allowed_fd, NULL, NULL, NULL) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: owner deny-stage failed\n");
    return 1;
  }
  if (owner("inspect", clone_fd, allowed_fd, NULL, NULL, NULL) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: owner deny-stage readback failed\n");
    return 1;
  }
  if (fcntl(clone_fd, F_GETFD) < 0 || fcntl(clone_fd, F_GETFL) < 0 ||
      fcntl(clone_fd, F_SETFD, FD_CLOEXEC) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: protected descriptor metadata failed: %s\n",
            strerror(errno));
    return 1;
  }
  errno = 0;
  if (fcntl(preopened_fd, F_OFD_SETLK, &read_lock) != -1 ||
      errno != EACCES) {
    fprintf(stderr, "kernel-export-owner-probe: protected lock was not denied\n");
    return 1;
  }
  errno = 0;
  data_fd = openat(clone_fd, "data", O_WRONLY | O_CLOEXEC);
  if (data_fd >= 0 || (errno != EACCES && errno != EROFS)) {
    fprintf(stderr, "kernel-export-owner-probe: writable clone open was not denied: %s\n",
            strerror(errno));
    if (data_fd >= 0)
      close(data_fd);
    return 1;
  }
  if (move_to_cgroup(allowed) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: consumer cgroup move failed: %s\n",
            strerror(errno));
    return 1;
  }
  errno = 0;
  data_fd = openat(clone_fd, "data", O_RDONLY | O_CLOEXEC);
  if (data_fd >= 0 || errno != EACCES || denied_read(preopened_fd) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: staged policy allowed use\n");
    if (data_fd >= 0)
      close(data_fd);
    return 1;
  }
  if (make_lease(source_fd, clone_fd) != 0 ||
      lease_names_origin(source_fd, clone_fd) != 0 ||
      make_stage_ack(clone_id) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: signed fixture identity failed\n");
    return 1;
  }
  if (owner("inspect-record", clone_fd, allowed_fd,
            NULL, NULL, NULL) == 0 ||
      reject_tampered_ack(clone_fd, allowed_fd, lease, ack) != 0 ||
      reject_signed_ack_mismatch(clone_fd, allowed_fd, lease, ack, 200) != 0 ||
      reject_signed_ack_mismatch(clone_fd, allowed_fd, lease, ack, 360) != 0 ||
      reject_signed_ack_mismatch(clone_fd, allowed_fd, lease, ack, 400) != 0 ||
      reject_signed_origin_device_mismatch(clone_fd, allowed_fd,
                                           lease, ack) != 0 ||
      owner("record", wrong_clone, allowed_fd, lease, ack, NULL) == 0 ||
      owner("record", clone_fd, outside_fd, lease, ack, NULL) == 0 ||
      owner("record", clone_fd, allowed_fd, handoff, ack, NULL) == 0 ||
      owner("record", clone_fd, allowed_fd, lease, handoff, NULL) == 0 ||
      owner("record", clone_fd, allowed_fd, lease, ack, NULL) != 0 ||
      owner("inspect-record", clone_fd, allowed_fd,
            NULL, NULL, NULL) != 0 ||
      owner("record", clone_fd, allowed_fd, lease, ack, NULL) == 0 ||
      owner("inspect-record", wrong_clone, allowed_fd,
            NULL, NULL, NULL) == 0 ||
      owner("inspect-record", clone_fd, outside_fd,
            NULL, NULL, NULL) == 0) {
    fprintf(stderr, "kernel-export-owner-probe: deny-stage record failed\n");
    return 1;
  }
  if (rename(lease, lease_backup) != 0 ||
      rename(ack, ack_backup) != 0 ||
      owner("inspect-record", clone_fd, allowed_fd,
            NULL, NULL, NULL) != 0 ||
      rename(lease_backup, lease) != 0 ||
      rename(ack_backup, ack) != 0 ||
      reject_record_mutation(clone_fd, allowed_fd, 48, 1) != 0 ||
      reject_record_mutation(clone_fd, allowed_fd, 56, 1) != 0 ||
      reject_record_mutation(clone_fd, allowed_fd, 64, 1) != 0 ||
      reject_record_mutation(clone_fd, allowed_fd, 1176, 0) != 0 ||
      owner("inspect-record", clone_fd, allowed_fd,
            NULL, NULL, NULL) != 0 ||
      denied_read(preopened_fd) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: recovered record fence failed\n");
    return 1;
  }
  if (owner("activate", wrong_clone, allowed_fd, lease, ack, "10000") == 0 ||
      owner("activate", clone_fd, outside_fd, lease, ack, "10000") == 0 ||
      owner("activate", clone_fd, allowed_fd, handoff, ack, "10000") == 0 ||
      owner("activate", clone_fd, allowed_fd, lease, handoff, "10000") == 0 ||
      owner("activate", clone_fd, allowed_fd, lease, ack, "10000") != 0) {
    fprintf(stderr, "kernel-export-owner-probe: staging or activation failed: %s\n",
            strerror(errno));
    return 1;
  }

  if (mkdir(attached, 0700) != 0 ||
      syscall(__NR_move_mount, clone_fd, "", AT_FDCWD, attached,
              MOVE_MOUNT_F_EMPTY_PATH) != 0 ||
      connect_clone_socket(attached, listener, &socket_client,
                           &socket_server) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: clone socket setup failed: %s\n",
            strerror(errno));
    return 1;
  }
  fifo_reader = openat(clone_fd, "fifo", O_RDONLY | O_CLOEXEC);
  if (fifo_reader < 0 ||
      start_blocked_fifo_reader(fifo_reader, &fifo_ready,
                                &blocked_reader) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: FIFO read setup failed: %s\n",
            strerror(errno));
    return 1;
  }

  data_fd = openat(clone_fd, "data", O_RDONLY | O_CLOEXEC);
  if (data_fd < 0 || pread(data_fd, &byte, 1, 0) != 1 ||
      outside_child(outside, data_fd) != 0 ||
      owner("inspect-record", clone_fd, allowed_fd,
            NULL, NULL, NULL) == 0 ||
      owner("inspect", clone_fd, allowed_fd, lease, ack, NULL) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: current use or cgroup denial failed\n");
    return 1;
  }
  mapping = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, data_fd, 0);
  if (mapping == MAP_FAILED ||
      ((volatile unsigned char *)mapping)[0] != (unsigned char)byte ||
      start_escaped_holder(outside, mapping, (unsigned char)byte,
                           socket_client, &escaped_holder,
                           &escaped_release) != 0 ||
      mutate_grant(clone_id, cgroup_stat.st_ino, 1) != 0 ||
      denied_read(data_fd) != 0 ||
      mutate_grant(clone_id, cgroup_stat.st_ino, 1) != 0 ||
      pread(data_fd, &byte, 1, 0) != 1 ||
      mutate_grant(clone_id, cgroup_stat.st_ino, 0) != 0 ||
      denied_read(data_fd) != 0 ||
      owner("inspect", clone_fd, allowed_fd, lease, ack, NULL) == 0 ||
      owner("recover", -1, -1, NULL, NULL, NULL) != 0 ||
      owner("inspect-record", clone_fd, allowed_fd,
            NULL, NULL, NULL) == 0 ||
      denied_read(data_fd) != 0 ||
      owner("activate", clone_fd, allowed_fd, lease, ack, "10000") == 0 ||
      await_fifo_reader(blocked_reader, fifo_ready, fifo_writer) != 0 ||
      connected_socket_survived(socket_client, socket_server) != 0 ||
      conflicting_source_lock(source_fd, preopened_fd) != 0 ||
      ((volatile unsigned char *)mapping)[0] != (unsigned char)byte ||
      move_to_cgroup(outside) != 0 ||
      kill_and_check_empty(allowed) != 0 ||
      finish_escaped_holder(escaped_holder, escaped_release,
                            socket_server) != 0) {
    fprintf(stderr, "kernel-export-owner-probe: mismatch/restart or survivor proof failed\n");
    return 1;
  }
  /* A preexisting mapping survives revoke; terminal release remains closed. */
  munmap(mapping, 4096);
  close(socket_server);
  close(socket_client);
  close(listener);
  close(fifo_reader);
  close(fifo_writer);
  close(preopened_fd);
  close(data_fd);
  close(wrong_clone);
  close(clone_fd);
  close(source_fd);
  close(allowed_fd);
  close(outside_fd);
  return 0;
}
