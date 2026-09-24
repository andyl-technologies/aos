// SPDX-License-Identifier: Apache-2.0

/* A private map-owner experiment. No Storage or Provider ingress invokes it. */
#define AOS_KERNEL_EXPORT_OWNER 1
#define AOS_KERNEL_EXPORT_PIN_DIR "/sys/fs/bpf/aos/kernel-export-owner"
#include "aos-sandbox-kernel-export-deny.c"

#include <dirent.h>
#include <sys/file.h>
#include <sys/statvfs.h>

#include <openssl/evp.h>

#define STATE_DIR "/var/lib/aos/kernel-export-owner"
#define STATE_FILE STATE_DIR "/state"
#define STATE_TEMP STATE_DIR "/state.new"
#define RECORD_FILE STATE_DIR "/lease-record"
#define RECORD_TEMP STATE_DIR "/lease-record.new"
#define VERIFIER_FILE STATE_DIR "/storage-verifier"
#define LEASE_VERIFIER_V2_FILE STATE_DIR "/storage-lease-verifier-v2"
#define STAGE_VERIFIER_V2_FILE STATE_DIR "/storage-stage-verifier-v2"
#define LEASE_BYTES 496U
#define VERIFIER_BYTES 112U
#define HANDOFF_BYTES 344U
#define ACK_BYTES 576U
#define ACK_V2_BYTES 600U
#define RECORD_BYTES 1208U
#define PREPARED_REPORT_BYTES 152U
#define OWNER_PREPARED 1U
#define OWNER_ACTIVATING 2U
#define OWNER_ACTIVE 3U
#define OWNER_REVOKED 4U

static const unsigned char signature_domain[] =
    "aos.sandbox.storage.live-export-lease.signature.v1";
static const unsigned char digest_domain[] =
    "aos.sandbox.storage.live-export-lease.digest.v1";
static const unsigned char handoff_domain[] =
    "aos.sandbox.storage.kernel-export-deny-handoff.v1";
static const unsigned char stage_domain[] =
    "aos.sandbox.kernel-export-owner.prepared-map.v1";
static const unsigned char ack_domain[] =
    "aos.sandbox.storage.kernel-export-stage-ack.signature.v1";
static const unsigned char ack_v2_domain[] =
    "aos.sandbox.storage.kernel-export-stage-ack.signature.v2";
static const unsigned char record_domain[] =
    "aos.sandbox.kernel-export-owner.lease-record.v1";

enum record_offset {
  RECORD_BOOT = 16,
  RECORD_MOUNT = 32,
  RECORD_DEVICE = 40,
  RECORD_INODE = 48,
  RECORD_CGROUP = 56,
  RECORD_EPOCH = 64,
  RECORD_HANDOFF = 72,
  RECORD_LEASE = 104,
  RECORD_ACK = 600,
  RECORD_DIGEST = 1176,
};

_Static_assert(RECORD_DIGEST + 32 == RECORD_BYTES,
               "kernel export lease record size changed");

struct owner_state {
  unsigned char magic[8];
  __u64 boot_id[2];
  __u64 mount_id;
  __u64 root_device;
  __u64 root_inode;
  __u64 cgroup_id;
  __u64 epoch;
  __u64 handoff_digest[4];
  __u64 lease_digest[4];
  __u32 phase;
  __u32 reserved;
};

static int exact_read(int fd, void *data, size_t size)
{
  unsigned char *bytes = data;
  size_t offset = 0;

  while (offset < size) {
    ssize_t count = read(fd, bytes + offset, size - offset);
    if (count <= 0)
      return -1;
    offset += (size_t)count;
  }
  unsigned char extra;
  return read(fd, &extra, 1) == 0 ? 0 : -1;
}

static int exact_write(int fd, const void *data, size_t size)
{
  const unsigned char *bytes = data;
  size_t offset = 0;

  while (offset < size) {
    ssize_t count = write(fd, bytes + offset, size - offset);
    if (count <= 0)
      return -1;
    offset += (size_t)count;
  }
  return 0;
}

static int protected_file(const char *path, size_t size, void *data)
{
  struct stat st;
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  int result = -1;

  if (fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
      st.st_uid == 0 && (st.st_mode & 0077) == 0 &&
      st.st_size == (off_t)size)
    result = exact_read(fd, data, size);
  if (fd >= 0)
    close(fd);
  return result;
}

static int state_lock(void)
{
  struct stat st;
  int fd;

  if (mkdir(STATE_DIR, 0700) != 0 && errno != EEXIST)
    return -1;
  if (lstat(STATE_DIR, &st) != 0 || !S_ISDIR(st.st_mode) ||
      st.st_uid != 0 || (st.st_mode & 0077) != 0)
    return -1;
  fd = open(STATE_DIR "/lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
            0600);
  if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
      st.st_uid != 0 || (st.st_mode & 0077) != 0 || flock(fd, LOCK_EX) != 0) {
    if (fd >= 0)
      close(fd);
    return -1;
  }
  return fd;
}

static int directory_entries_only(const char *path, const char *permitted)
{
  DIR *directory = opendir(path);
  struct dirent *entry;
  int result = -1;

  if (directory == NULL)
    return -1;
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 ||
        strcmp(entry->d_name, "..") == 0)
      continue;
    if (permitted == NULL || strcmp(entry->d_name, permitted) != 0)
      goto out;
    errno = 0;
  }
  if (errno == 0)
    result = 0;

out:
  closedir(directory);
  return result;
}

static int verified_empty_owner(void)
{
  /* A missing state file is not enough: interrupted records or pinned maps
   * must never be promoted into a first-boot recovery success. */
  return directory_entries_only(STATE_DIR, "lock") == 0 &&
         directory_entries_only(AOS_KERNEL_EXPORT_PIN_DIR, NULL) == 0 ? 0 : -1;
}

static int read_state(struct owner_state *state)
{
  memset(state, 0, sizeof(*state));
  if (protected_file(STATE_FILE, sizeof(*state), state) != 0 ||
      memcmp(state->magic, "AOSKGO01", 8) != 0 ||
      state->reserved != 0 || state->epoch == 0 ||
      state->mount_id == 0 || state->cgroup_id == 0 ||
      state->phase < OWNER_PREPARED || state->phase > OWNER_REVOKED)
    return -1;
  return 0;
}

static int write_state(const struct owner_state *state)
{
  int directory = open(STATE_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                      O_NOFOLLOW);
  int fd = -1;
  int result = -1;

  if (directory < 0 || (unlink(STATE_TEMP) != 0 && errno != ENOENT))
    goto out;
  fd = open(STATE_TEMP, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
            0600);
  if (fd < 0 || exact_write(fd, state, sizeof(*state)) != 0 ||
      fsync(fd) != 0 || rename(STATE_TEMP, STATE_FILE) != 0 ||
      fsync(directory) != 0)
    goto out;
  result = 0;

out:
  if (fd >= 0)
    close(fd);
  if (directory >= 0)
    close(directory);
  return result;
}

static __u64 be64(const unsigned char *bytes)
{
  __u64 value = 0;
  for (size_t i = 0; i < 8; i++)
    value = (value << 8) | bytes[i];
  return value;
}

static void put_be64(unsigned char *bytes, __u64 value)
{
  for (int i = 7; i >= 0; i--) {
    bytes[i] = (unsigned char)value;
    value >>= 8;
  }
}

static void put_be32(unsigned char *bytes, __u32 value)
{
  for (int i = 3; i >= 0; i--) {
    bytes[i] = (unsigned char)value;
    value >>= 8;
  }
}

static bool all_zero(const unsigned char *bytes, size_t size)
{
  unsigned char any = 0;

  for (size_t i = 0; i < size; i++)
    any |= bytes[i];
  return any == 0;
}

static int handoff_from_bytes(const unsigned char frame[HANDOFF_BYTES],
                              __u64 mount_id, __u64 device, __u64 inode,
                              __u64 cgroup_id, const __u64 boot_id[2],
                              __u64 digest[4])
{
  unsigned char calculated[32];
  unsigned int size = 0;
  EVP_MD_CTX *context = NULL;
  time_t now = time(NULL);
  int result = -1;

  /* Offsets match Storage's sealed AOSKGH01 frame, not a new owner format. */
  if (memcmp(frame, "AOSKGH01", 8) != 0 ||
      frame[8] != 0 || frame[9] != 1 || frame[10] != 1 ||
      memcmp(frame + 11, "\0\0\0\0\0", 5) != 0 ||
      memcmp(frame + 224, boot_id, 16) != 0 ||
      be64(frame + 240) != mount_id ||
      be64(frame + 248) != device || be64(frame + 256) != inode ||
      be64(frame + 320) != cgroup_id || be64(frame + 328) != 0 ||
      all_zero(frame + 48, 16) || be64(frame + 64) == 0 ||
      all_zero(frame + 72, 16) || all_zero(frame + 88, 32) ||
      all_zero(frame + 120, 32) || all_zero(frame + 152, 32) ||
      be64(frame + 184) == 0 || all_zero(frame + 192, 32) ||
      all_zero(frame + 264, 16) || be64(frame + 280) == 0 ||
      all_zero(frame + 288, 32) ||
      now <= 0 || (int64_t)be64(frame + 336) <= now)
    return -1;

  context = EVP_MD_CTX_new();
  if (context == NULL ||
      EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(context, handoff_domain,
                       sizeof(handoff_domain)) != 1 ||
      EVP_DigestUpdate(context, frame + 48, HANDOFF_BYTES - 48) != 1 ||
      EVP_DigestFinal_ex(context, calculated, &size) != 1 ||
      size != sizeof(calculated) ||
      memcmp(calculated, frame + 16, sizeof(calculated)) != 0)
    goto out;
  memcpy(digest, calculated, sizeof(calculated));
  result = 0;

out:
  EVP_MD_CTX_free(context);
  return result;
}

static int handoff_from_frame(const char *path, __u64 mount_id,
                              __u64 device, __u64 inode, __u64 cgroup_id,
                              const __u64 boot_id[2], __u64 digest[4])
{
  unsigned char frame[HANDOFF_BYTES];

  if (protected_file(path, sizeof(frame), frame) != 0)
    return -1;
  return handoff_from_bytes(frame, mount_id, device, inode, cgroup_id,
                            boot_id, digest);
}

static int current_clone(int fd, __u64 *mount_id, __u64 *device,
                         __u64 *inode)
{
  struct stat st;
  struct statvfs vfs;
  int flags = fcntl(fd, F_GETFL);
  int descriptor = fcntl(fd, F_GETFD);

  if (mount_id_from_fd(fd, mount_id) != 0 || fstat(fd, &st) != 0 ||
      fstatvfs(fd, &vfs) != 0 || !S_ISDIR(st.st_mode) ||
      (flags & O_PATH) == 0 || (descriptor & FD_CLOEXEC) == 0 ||
      (vfs.f_flag & (ST_RDONLY | ST_NOSUID | ST_NODEV)) !=
          (ST_RDONLY | ST_NOSUID | ST_NODEV))
    return -1;
  *device = st.st_dev;
  *inode = st.st_ino;
  return *device != 0 && *inode != 0 ? 0 : -1;
}

static int read_mount(__u64 mount_id,
                      struct aos_kernel_export_owner_mount_v1 *policy)
{
  int fd = open_checked_map(MOUNT_MAP_PIN, "export_mounts", sizeof(mount_id),
                            sizeof(*policy), AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS);
  int result = fd < 0 ? -1 : bpf_map_lookup_elem(fd, &mount_id, policy);

  if (fd >= 0)
    close(fd);
  return result;
}

static int write_mount(__u64 mount_id,
                       const struct aos_kernel_export_owner_mount_v1 *policy)
{
  struct aos_kernel_export_owner_mount_v1 observed;
  int fd = open_checked_map(MOUNT_MAP_PIN, "export_mounts", sizeof(mount_id),
                            sizeof(*policy), AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS);
  int result = fd < 0 ? -1 : bpf_map_update_elem(fd, &mount_id, policy, BPF_EXIST);

  if (fd >= 0)
    close(fd);
  return result == 0 && read_mount(mount_id, &observed) == 0 &&
         memcmp(policy, &observed, sizeof(*policy)) == 0 ? 0 : -1;
}

static int canonical_prepared_policy(
    __u64 mount_id, const struct aos_kernel_export_owner_mount_v1 *policy,
    unsigned char canonical[128])
{
  if (policy->version != AOS_KERNEL_EXPORT_DENY_VERSION ||
      policy->phase != AOS_KERNEL_EXPORT_OWNER_PREPARED ||
      !all_zero((const unsigned char *)policy->lease_digest, 32))
    return -1;
  memset(canonical, 0, 128);
  memcpy(canonical, policy->boot_id, 16);
  put_be64(canonical + 16, mount_id);
  put_be64(canonical + 24, policy->epoch);
  put_be64(canonical + 32, policy->root_device);
  put_be64(canonical + 40, policy->root_inode);
  put_be64(canonical + 48, policy->holder_cgroup_id);
  memcpy(canonical + 56, policy->handoff_digest, 32);
  memcpy(canonical + 88, policy->lease_digest, 32);
  put_be32(canonical + 120, policy->version);
  put_be32(canonical + 124, policy->phase);
  return 0;
}

static int staged_policy_digest(__u64 mount_id,
                                const struct aos_kernel_export_owner_mount_v1 *policy,
                                unsigned char digest[32])
{
  unsigned char canonical[128];
  unsigned int size = 0;
  EVP_MD_CTX *context = NULL;
  int result = -1;

  if (canonical_prepared_policy(mount_id, policy, canonical) != 0)
    return -1;

  context = EVP_MD_CTX_new();
  if (context == NULL ||
      EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(context, stage_domain, sizeof(stage_domain)) != 1 ||
      EVP_DigestUpdate(context, canonical, sizeof(canonical)) != 1 ||
      EVP_DigestFinal_ex(context, digest, &size) != 1 || size != 32)
    goto out;
  result = 0;

out:
  EVP_MD_CTX_free(context);
  return result;
}

static int read_grant(__u64 mount_id, __u64 cgroup_id,
                      struct aos_kernel_export_owner_grant_v1 *grant)
{
  struct aos_kernel_export_grant_key_v2 key = {mount_id, cgroup_id};
  int fd = open_checked_map(GRANT_MAP_PIN, "consumer_grants", sizeof(key),
                            sizeof(*grant), AOS_KERNEL_EXPORT_DENY_MAX_GRANTS);
  int result = fd < 0 ? -1 : bpf_map_lookup_elem(fd, &key, grant);

  if (fd >= 0)
    close(fd);
  return result;
}

static int grant_absent(__u64 mount_id, __u64 cgroup_id)
{
  struct aos_kernel_export_grant_key_v2 key = {mount_id, cgroup_id};
  struct aos_kernel_export_owner_grant_v1 grant;
  int fd = open_checked_map(GRANT_MAP_PIN, "consumer_grants", sizeof(key),
                            sizeof(grant), AOS_KERNEL_EXPORT_DENY_MAX_GRANTS);
  int status;
  int lookup_errno;

  if (fd < 0)
    return -1;
  status = bpf_map_lookup_elem(fd, &key, &grant);
  lookup_errno = errno;
  close(fd);
  return status < 0 && lookup_errno == ENOENT ? 0 : -1;
}

static int write_grant(__u64 mount_id, __u64 cgroup_id,
                       const struct aos_kernel_export_owner_grant_v1 *grant)
{
  struct aos_kernel_export_grant_key_v2 key = {mount_id, cgroup_id};
  struct aos_kernel_export_owner_grant_v1 observed;
  int fd = open_checked_map(GRANT_MAP_PIN, "consumer_grants", sizeof(key),
                            sizeof(*grant), AOS_KERNEL_EXPORT_DENY_MAX_GRANTS);
  int result = fd < 0 ? -1 : bpf_map_update_elem(fd, &key, grant, BPF_ANY);

  if (fd >= 0)
    close(fd);
  return result == 0 && read_grant(mount_id, cgroup_id, &observed) == 0 &&
         memcmp(grant, &observed, sizeof(*grant)) == 0 ? 0 : -1;
}

/* Recovery fences the map before any descriptor or new lease can be released. */
static int revoke_state(struct owner_state *state)
{
  struct aos_kernel_export_owner_mount_v1 policy;
  struct aos_kernel_export_owner_grant_v1 grant;
  __u64 boot[2];

  if (current_boot_id(boot) != 0 ||
      memcmp(boot, state->boot_id, sizeof(boot)) != 0 ||
      inspect_installation(state->mount_id, &policy) != 0 ||
      policy.epoch != state->epoch || policy.epoch == UINT64_MAX ||
      policy.holder_cgroup_id != state->cgroup_id)
    return -1;
  policy.epoch++;
  policy.phase = AOS_KERNEL_EXPORT_OWNER_REVOKED;
  if (write_mount(state->mount_id, &policy) != 0)
    return -1;

  if (read_grant(state->mount_id, state->cgroup_id, &grant) == 0) {
    grant.state = AOS_KERNEL_EXPORT_GRANT_REVOKED;
    if (write_grant(state->mount_id, state->cgroup_id, &grant) != 0)
      return -1;
  }
  state->epoch = policy.epoch;
  state->phase = OWNER_REVOKED;
  return write_state(state);
}

static bool canonical_lease_source(const unsigned char lease[LEASE_BYTES],
                                   const struct owner_state *state)
{
  /* 216/224 name the mutable origin, not the later clone. Storage retain
   * requires equal dev/inode; this does not attest the origin mount ID. */
  return !all_zero(lease + 16, 32) && !all_zero(lease + 48, 16) &&
         !all_zero(lease + 64, 16) && !all_zero(lease + 80, 16) &&
         be64(lease + 96) != 0 && !all_zero(lease + 104, 32) &&
         !all_zero(lease + 136, 32) && !all_zero(lease + 168, 32) &&
         memcmp(lease + 200, state->boot_id, 16) == 0 &&
         be64(lease + 216) == state->root_device &&
         be64(lease + 224) == state->root_inode &&
         be64(lease + 232) != 0 && be64(lease + 232) != state->mount_id;
}

static bool canonical_lease_consumer(const unsigned char lease[LEASE_BYTES],
                                     time_t now)
{
  __u64 issued = be64(lease + 336);
  __u64 expiry = be64(lease + 344);

  return !all_zero(lease + 240, 32) && !all_zero(lease + 272, 16) &&
         !all_zero(lease + 288, 16) && be64(lease + 304) != 0 &&
         !all_zero(lease + 312, 16) && be64(lease + 328) != 0 &&
         now > 0 && (int64_t)issued > 0 && (int64_t)expiry > 0 &&
         issued <= (__u64)now && expiry > (__u64)now &&
         expiry - issued <= 86400;
}

static bool canonical_lease_signer(const unsigned char lease[LEASE_BYTES],
                                   const unsigned char verifier[VERIFIER_BYTES])
{
  return memcmp(lease + 352, verifier, 80) == 0 &&
         !all_zero(lease + 352, 16) && be64(lease + 368) != 0 &&
         !all_zero(lease + 376, 32) && !all_zero(lease + 408, 16) &&
         be64(lease + 424) != 0 && !all_zero(lease + 432, 64);
}

static int verify_lease_bytes(const unsigned char lease[LEASE_BYTES],
                              const unsigned char handoff[HANDOFF_BYTES],
                              const unsigned char verifier[VERIFIER_BYTES],
                              const struct owner_state *state, __u64 digest[4],
                              __u64 *remaining_ms)
{
  unsigned char message[sizeof(signature_domain) + 432];
  unsigned char hash[32];
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  time_t now = time(NULL);
  int result = -1;

  if (memcmp(lease, "AOSSLE01", 8) != 0 || lease[8] != 0 || lease[9] != 1 ||
      memcmp(lease + 10, "\0\0\0\0\0\0", 6) != 0 ||
      memcmp(handoff + 16, state->handoff_digest, 32) != 0 ||
      memcmp(lease + 288, handoff + 48, 16) != 0 ||
      be64(lease + 304) != be64(handoff + 64) ||
      !canonical_lease_source(lease, state) ||
      !canonical_lease_consumer(lease, now) ||
      !canonical_lease_signer(lease, verifier))
    goto out;

  memcpy(message, signature_domain, sizeof(signature_domain));
  memcpy(message + sizeof(signature_domain), lease, 432);
  key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, verifier + 80, 32);
  context = EVP_MD_CTX_new();
  if (key == NULL || context == NULL ||
      EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) != 1 ||
      EVP_DigestVerify(context, lease + 432, 64, message,
                       sizeof(message)) != 1)
    goto out;

  unsigned int hash_size = 0;
  EVP_MD_CTX *hash_context = EVP_MD_CTX_new();
  if (hash_context == NULL ||
      EVP_DigestInit_ex(hash_context, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(hash_context, digest_domain,
                       sizeof(digest_domain)) != 1 ||
      EVP_DigestUpdate(hash_context, lease, LEASE_BYTES) != 1 ||
      EVP_DigestFinal_ex(hash_context, hash, &hash_size) != 1 ||
      hash_size != sizeof(hash)) {
    EVP_MD_CTX_free(hash_context);
    goto out;
  }
  EVP_MD_CTX_free(hash_context);
  memcpy(digest, hash, sizeof(hash));
  /* Whole-second wall time is conservative at both lease boundaries. */
  *remaining_ms = ((__u64)be64(lease + 344) - (__u64)now - 1) * 1000ULL;
  result = 0;

out:
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

static int verify_lease(const char *lease_path, const char *handoff_path,
                        const struct owner_state *state, __u64 digest[4],
                        __u64 *remaining_ms)
{
  unsigned char lease[LEASE_BYTES], handoff[HANDOFF_BYTES];
  unsigned char verifier[VERIFIER_BYTES];

  if (protected_file(lease_path, sizeof(lease), lease) != 0 ||
      protected_file(handoff_path, sizeof(handoff), handoff) != 0 ||
      protected_file(VERIFIER_FILE, sizeof(verifier), verifier) != 0)
    return -1;
  return verify_lease_bytes(lease, handoff, verifier, state, digest,
                            remaining_ms);
}

static int verify_stage_ack_bytes(const unsigned char ack[ACK_BYTES],
                                  const unsigned char frame[HANDOFF_BYTES],
                                  const unsigned char verifier[VERIFIER_BYTES],
                                  const struct owner_state *state,
                                  const struct aos_kernel_export_owner_mount_v1 *prepared,
                                  const __u64 lease_digest[4])
{
  unsigned char policy_digest[32];
  unsigned char message[sizeof(ack_domain) + 512];
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  int result = -1;

  if (memcmp(ack, "AOSKGA01", 8) != 0 ||
      ack[8] != 0 || ack[9] != 1 ||
      memcmp(ack + 10, "\0\0\0\0\0\0", 6) != 0 ||
      memcmp(ack + 16, frame, HANDOFF_BYTES) != 0 ||
      memcmp(frame + 16, state->handoff_digest, 32) != 0 ||
      memcmp(ack + 360, lease_digest, 32) != 0 ||
      be64(ack + 392) != state->epoch ||
      staged_policy_digest(state->mount_id, prepared,
                           policy_digest) != 0 ||
      memcmp(ack + 400, policy_digest, sizeof(policy_digest)) != 0 ||
      memcmp(ack + 432, verifier, 80) != 0)
    return -1;

  memcpy(message, ack_domain, sizeof(ack_domain));
  memcpy(message + sizeof(ack_domain), ack, 512);
  key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, verifier + 80, 32);
  context = EVP_MD_CTX_new();
  if (key != NULL && context != NULL &&
      EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
      EVP_DigestVerify(context, ack + 512, 64, message,
                       sizeof(message)) == 1)
    result = 0;
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

static int verify_stage_ack(const char *ack_path, const char *handoff_path,
                            const struct owner_state *state,
                            const struct aos_kernel_export_owner_mount_v1 *prepared,
                            const __u64 lease_digest[4])
{
  unsigned char ack[ACK_BYTES], frame[HANDOFF_BYTES];
  unsigned char verifier[VERIFIER_BYTES];

  if (protected_file(ack_path, sizeof(ack), ack) != 0 ||
      protected_file(handoff_path, sizeof(frame), frame) != 0 ||
      protected_file(VERIFIER_FILE, sizeof(verifier), verifier) != 0)
    return -1;
  return verify_stage_ack_bytes(ack, frame, verifier, state, prepared,
                                lease_digest);
}

/* V2 is a read-only fixture verifier; the v1 record and effect path stay fixed. */
static int verify_stage_ack_v2_bytes(
    const unsigned char ack[ACK_V2_BYTES],
    const unsigned char frame[HANDOFF_BYTES],
    const unsigned char lease[LEASE_BYTES],
    const unsigned char lease_verifier[VERIFIER_BYTES],
    const unsigned char stage_verifier[VERIFIER_BYTES],
    const struct owner_state *state,
    const struct aos_kernel_export_owner_mount_v1 *prepared,
    const __u64 lease_digest[4])
{
  unsigned char policy_digest[32];
  unsigned char message[sizeof(ack_v2_domain) + 536];
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  int result = -1;

  if (memcmp(ack, "AOSKGA02", 8) != 0 ||
      ack[8] != 0 || ack[9] != 2 ||
      memcmp(ack + 10, "\0\0\0\0\0\0", 6) != 0 ||
      memcmp(ack + 16, frame, HANDOFF_BYTES) != 0 ||
      memcmp(frame + 16, state->handoff_digest, 32) != 0 ||
      memcmp(ack + 360, lease_digest, 32) != 0 ||
      be64(ack + 392) != be64(lease + 232) ||
      be64(ack + 392) == state->mount_id ||
      be64(ack + 400) != state->root_device ||
      be64(ack + 408) != state->root_inode ||
      be64(ack + 400) != be64(lease + 216) ||
      be64(ack + 408) != be64(lease + 224) ||
      be64(ack + 416) != state->epoch ||
      staged_policy_digest(state->mount_id, prepared,
                           policy_digest) != 0 ||
      memcmp(ack + 424, policy_digest, sizeof(policy_digest)) != 0 ||
      memcmp(ack + 456, stage_verifier, 80) != 0 ||
      memcmp(stage_verifier, lease_verifier, 80) == 0 ||
      memcmp(stage_verifier + 80, lease_verifier + 80, 32) == 0 ||
      all_zero(stage_verifier, 16) ||
      be64(stage_verifier + 16) == 0 ||
      all_zero(stage_verifier + 24, 32) ||
      all_zero(stage_verifier + 56, 16) ||
      be64(stage_verifier + 72) == 0 ||
      all_zero(stage_verifier + 80, 32))
    return -1;

  memcpy(message, ack_v2_domain, sizeof(ack_v2_domain));
  memcpy(message + sizeof(ack_v2_domain), ack, 536);
  key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                     stage_verifier + 80, 32);
  context = EVP_MD_CTX_new();
  if (key != NULL && context != NULL &&
      EVP_DigestVerifyInit(context, NULL, NULL, NULL, key) == 1 &&
      EVP_DigestVerify(context, ack + 536, 64, message,
                       sizeof(message)) == 1)
    result = 0;
  EVP_MD_CTX_free(context);
  EVP_PKEY_free(key);
  return result;
}

static int prepared_current(const struct owner_state *state, int clone_fd,
                            int cgroup_fd, const char *handoff_path,
                            unsigned char frame[HANDOFF_BYTES],
                            struct aos_kernel_export_owner_mount_v1 *policy);

static int inspect_stage_ack_v2(const struct owner_state *state, int clone_fd,
                                int cgroup_fd, const char *handoff_path,
                                const char *lease_path, const char *ack_path)
{
  struct aos_kernel_export_owner_mount_v1 before, after;
  unsigned char frame[HANDOFF_BYTES], after_frame[HANDOFF_BYTES];
  unsigned char lease[LEASE_BYTES], ack[ACK_V2_BYTES];
  unsigned char lease_verifier[VERIFIER_BYTES];
  unsigned char stage_verifier[VERIFIER_BYTES];
  __u64 lease_digest[4], remaining_ms;

  if (prepared_current(state, clone_fd, cgroup_fd, handoff_path,
                       frame, &before) != 0 ||
      protected_file(lease_path, sizeof(lease), lease) != 0 ||
      protected_file(ack_path, sizeof(ack), ack) != 0 ||
      protected_file(LEASE_VERIFIER_V2_FILE, sizeof(lease_verifier),
                     lease_verifier) != 0 ||
      protected_file(STAGE_VERIFIER_V2_FILE, sizeof(stage_verifier),
                     stage_verifier) != 0 ||
      verify_lease_bytes(lease, frame, lease_verifier, state,
                         lease_digest, &remaining_ms) != 0 ||
      verify_stage_ack_v2_bytes(ack, frame, lease, lease_verifier,
                                 stage_verifier, state, &before,
                                 lease_digest) != 0 ||
      prepared_current(state, clone_fd, cgroup_fd, handoff_path,
                       after_frame, &after) != 0 ||
      memcmp(frame, after_frame, sizeof(frame)) != 0 ||
      memcmp(&before, &after, sizeof(before)) != 0)
    return -1;
  return 0;
}

static int stage(int clone_fd, int cgroup_fd, const char *handoff_path)
{
  struct owner_state state = {.phase = OWNER_PREPARED, .epoch = 1};
  struct aos_kernel_export_owner_mount_v1 policy;
  struct stat existing;

  memcpy(state.magic, "AOSKGO01", 8);
  if (lstat(STATE_FILE, &existing) == 0 || errno != ENOENT ||
      current_clone(clone_fd, &state.mount_id, &state.root_device,
                    &state.root_inode) != 0 ||
      cgroup_id_from_fd(cgroup_fd, &state.cgroup_id) != 0 ||
      current_boot_id(state.boot_id) != 0 ||
      handoff_from_frame(handoff_path, state.mount_id, state.root_device,
                         state.root_inode, state.cgroup_id, state.boot_id,
                         state.handoff_digest) != 0 ||
      install(state.mount_id) != 0 ||
      inspect_installation(state.mount_id, &policy) != 0 ||
      grant_absent(state.mount_id, state.cgroup_id) != 0)
    return -1;

  policy.root_device = state.root_device;
  policy.root_inode = state.root_inode;
  policy.holder_cgroup_id = state.cgroup_id;
  memcpy(policy.handoff_digest, state.handoff_digest,
         sizeof(policy.handoff_digest));
  policy.phase = AOS_KERNEL_EXPORT_OWNER_PREPARED;
  if (write_mount(state.mount_id, &policy) != 0 ||
      write_state(&state) != 0)
    return -1;
  return 0;
}

static int prepared_current(const struct owner_state *state, int clone_fd,
                            int cgroup_fd, const char *handoff_path,
                            unsigned char frame[HANDOFF_BYTES],
                            struct aos_kernel_export_owner_mount_v1 *policy)
{
  __u64 boot[2], mount_id, device, inode, cgroup_id, handoff[4];

  if (state->phase != OWNER_PREPARED ||
      current_boot_id(boot) != 0 ||
      memcmp(boot, state->boot_id, sizeof(boot)) != 0 ||
      current_clone(clone_fd, &mount_id, &device, &inode) != 0 ||
      cgroup_id_from_fd(cgroup_fd, &cgroup_id) != 0 ||
      protected_file(handoff_path, HANDOFF_BYTES, frame) != 0 ||
      handoff_from_bytes(frame, mount_id, device, inode, cgroup_id,
                         boot, handoff) != 0 ||
      mount_id != state->mount_id || device != state->root_device ||
      inode != state->root_inode || cgroup_id != state->cgroup_id ||
      memcmp(handoff, state->handoff_digest, sizeof(handoff)) != 0 ||
      inspect_installation(mount_id, policy) != 0 ||
      policy->phase != AOS_KERNEL_EXPORT_OWNER_PREPARED ||
      policy->epoch != state->epoch ||
      policy->root_device != device || policy->root_inode != inode ||
      policy->holder_cgroup_id != cgroup_id ||
      memcmp(policy->handoff_digest, handoff, sizeof(handoff)) != 0 ||
      !all_zero((const unsigned char *)policy->lease_digest, 32) ||
      grant_absent(mount_id, cgroup_id) != 0)
    return -1;
  return 0;
}

/* A root-only point observation, not a signed or held grant statement. */
static int report_prepared(const struct owner_state *state, int clone_fd,
                           int cgroup_fd, const char *handoff_path)
{
  struct aos_kernel_export_owner_mount_v1 before, after;
  unsigned char first_frame[HANDOFF_BYTES], second_frame[HANDOFF_BYTES];
  unsigned char report[PREPARED_REPORT_BYTES] = {0};
  __u64 now;

  if (prepared_current(state, clone_fd, cgroup_fd, handoff_path,
                       first_frame, &before) != 0 ||
      canonical_prepared_policy(state->mount_id, &before,
                                report + 16) != 0 ||
      prepared_current(state, clone_fd, cgroup_fd, handoff_path,
                       second_frame, &after) != 0 ||
      memcmp(&before, &after, sizeof(before)) != 0 ||
      memcmp(first_frame, second_frame, sizeof(first_frame)) != 0 ||
      boot_time_ns(&now) != 0 || now == 0)
    return -1;

  memcpy(report, "AOSKPR01", 8);
  report[9] = 1;
  put_be64(report + 144, now);
  return exact_write(STDOUT_FILENO, report, sizeof(report));
}

static int record_digest(const unsigned char record[RECORD_BYTES],
                         unsigned char digest[32])
{
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  unsigned int size = 0;
  int result = -1;

  if (context != NULL &&
      EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
      EVP_DigestUpdate(context, record_domain, sizeof(record_domain)) == 1 &&
      EVP_DigestUpdate(context, record, RECORD_DIGEST) == 1 &&
      EVP_DigestFinal_ex(context, digest, &size) == 1 && size == 32)
    result = 0;
  EVP_MD_CTX_free(context);
  return result;
}

static int write_record(const unsigned char record[RECORD_BYTES])
{
  struct stat existing;
  int directory = -1, fd = -1, result = -1;

  if (lstat(RECORD_FILE, &existing) == 0 || errno != ENOENT)
    return -1;
  directory = open(STATE_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (directory < 0 || (unlink(RECORD_TEMP) != 0 && errno != ENOENT))
    goto out;
  fd = open(RECORD_TEMP, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW,
            0600);
  if (fd < 0 || exact_write(fd, record, RECORD_BYTES) != 0 ||
      fsync(fd) != 0 || rename(RECORD_TEMP, RECORD_FILE) != 0 ||
      fsync(directory) != 0)
    goto out;
  result = 0;

out:
  if (fd >= 0)
    close(fd);
  if (directory >= 0)
    close(directory);
  return result;
}

static int read_record(unsigned char record[RECORD_BYTES])
{
  unsigned char digest[32];

  if (protected_file(RECORD_FILE, RECORD_BYTES, record) != 0 ||
      memcmp(record, "AOSKLR01", 8) != 0 ||
      record[8] != 0 || record[9] != 1 || record[10] != OWNER_PREPARED ||
      memcmp(record + 11, "\0\0\0\0\0", 5) != 0 ||
      record_digest(record, digest) != 0 ||
      memcmp(record + RECORD_DIGEST, digest, sizeof(digest)) != 0)
    return -1;
  return 0;
}

/* This readback is local recovery evidence, never grant or release authority. */
static int inspect_record(const struct owner_state *state, int clone_fd,
                          int cgroup_fd, const char *handoff_path)
{
  struct aos_kernel_export_owner_mount_v1 policy;
  unsigned char frame[HANDOFF_BYTES], record[RECORD_BYTES];
  unsigned char verifier[VERIFIER_BYTES];
  __u64 lease_digest[4], remaining_ms;

  if (prepared_current(state, clone_fd, cgroup_fd, handoff_path,
                       frame, &policy) != 0 ||
      read_record(record) != 0 ||
      protected_file(VERIFIER_FILE, sizeof(verifier), verifier) != 0 ||
      memcmp(record + RECORD_BOOT, state->boot_id, 16) != 0 ||
      be64(record + RECORD_MOUNT) != state->mount_id ||
      be64(record + RECORD_DEVICE) != state->root_device ||
      be64(record + RECORD_INODE) != state->root_inode ||
      be64(record + RECORD_CGROUP) != state->cgroup_id ||
      be64(record + RECORD_EPOCH) != state->epoch ||
      memcmp(record + RECORD_HANDOFF, state->handoff_digest, 32) != 0 ||
      verify_lease_bytes(record + RECORD_LEASE, frame, verifier, state,
                         lease_digest, &remaining_ms) != 0 ||
      verify_stage_ack_bytes(record + RECORD_ACK, frame, verifier, state,
                              &policy, lease_digest) != 0)
    return -1;
  return 0;
}

/* No ACTIVE map row or descriptor egress follows this durable snapshot. */
static int record_prepared(struct owner_state *state, int clone_fd,
                           int cgroup_fd, const char *handoff_path,
                           const char *lease_path, const char *ack_path)
{
  struct aos_kernel_export_owner_mount_v1 policy;
  unsigned char frame[HANDOFF_BYTES], record[RECORD_BYTES] = {0};
  unsigned char verifier[VERIFIER_BYTES], digest[32];
  __u64 lease_digest[4], remaining_ms;

  if (prepared_current(state, clone_fd, cgroup_fd, handoff_path,
                       frame, &policy) != 0 ||
      protected_file(lease_path, LEASE_BYTES, record + RECORD_LEASE) != 0 ||
      protected_file(ack_path, ACK_BYTES, record + RECORD_ACK) != 0 ||
      protected_file(VERIFIER_FILE, sizeof(verifier), verifier) != 0 ||
      verify_lease_bytes(record + RECORD_LEASE, frame, verifier, state,
                         lease_digest, &remaining_ms) != 0 ||
      verify_stage_ack_bytes(record + RECORD_ACK, frame, verifier, state,
                              &policy, lease_digest) != 0)
    return -1;

  memcpy(record, "AOSKLR01", 8);
  record[9] = 1;
  record[10] = OWNER_PREPARED;
  memcpy(record + RECORD_BOOT, state->boot_id, 16);
  put_be64(record + RECORD_MOUNT, state->mount_id);
  put_be64(record + RECORD_DEVICE, state->root_device);
  put_be64(record + RECORD_INODE, state->root_inode);
  put_be64(record + RECORD_CGROUP, state->cgroup_id);
  put_be64(record + RECORD_EPOCH, state->epoch);
  memcpy(record + RECORD_HANDOFF, state->handoff_digest, 32);
  if (record_digest(record, digest) != 0)
    return -1;
  memcpy(record + RECORD_DIGEST, digest, sizeof(digest));

  if (write_record(record) != 0)
    return -1;
  return inspect_record(state, clone_fd, cgroup_fd, handoff_path);
}

static int inspect_activated_effect(
    const struct owner_state *expected_state, int clone_fd, int cgroup_fd,
    const char *handoff_path, const char *lease_path, const char *ack_path,
    const struct aos_kernel_export_owner_mount_v1 *expected_policy,
    const struct aos_kernel_export_owner_grant_v1 *expected_grant);

static int deny_failed_activation(struct owner_state *state)
{
  if (revoke_state(state) != 0)
    fprintf(stderr, "kernel-export-owner: failed activation; deny-first "
                    "recovery could not be verified\n");
  return -1;
}

static int activate(struct owner_state *state, int clone_fd, int cgroup_fd,
                    const char *handoff_path, const char *lease_path,
                    const char *ack_path, __u64 ttl_ms)
{
  struct aos_kernel_export_owner_mount_v1 policy;
  struct aos_kernel_export_owner_grant_v1 grant = {
      .state = AOS_KERNEL_EXPORT_GRANT_ACTIVE,
      .version = AOS_KERNEL_EXPORT_DENY_VERSION,
  };
  __u64 mount_id, device, inode, cgroup_id, now, remaining_ms, digest[4];
  __u64 handoff[4];

  if (state->phase != OWNER_PREPARED ||
      current_clone(clone_fd, &mount_id, &device, &inode) != 0 ||
      cgroup_id_from_fd(cgroup_fd, &cgroup_id) != 0 ||
      handoff_from_frame(handoff_path, mount_id, device, inode, cgroup_id,
                         state->boot_id, handoff) != 0 ||
      mount_id != state->mount_id || device != state->root_device ||
      inode != state->root_inode || cgroup_id != state->cgroup_id ||
      memcmp(handoff, state->handoff_digest, sizeof(handoff)) != 0 ||
      verify_lease(lease_path, handoff_path, state, digest,
                   &remaining_ms) != 0 ||
      ttl_ms == 0 || ttl_ms > MAX_GRANT_TTL_MS ||
      ttl_ms > remaining_ms || boot_time_ns(&now) != 0 ||
      now > UINT64_MAX - ttl_ms * 1000000ULL ||
      inspect_installation(mount_id, &policy) != 0 ||
      policy.phase != AOS_KERNEL_EXPORT_OWNER_PREPARED ||
      policy.epoch != state->epoch ||
      policy.root_device != device || policy.root_inode != inode ||
      policy.holder_cgroup_id != cgroup_id ||
      memcmp(policy.handoff_digest, handoff, sizeof(handoff)) != 0 ||
      verify_stage_ack(ack_path, handoff_path, state, &policy,
                       digest) != 0 ||
      grant_absent(mount_id, cgroup_id) != 0)
    return -1;

  state->phase = OWNER_ACTIVATING;
  memcpy(state->lease_digest, digest, sizeof(digest));
  if (write_state(state) != 0)
    return deny_failed_activation(state);

  memcpy(policy.lease_digest, digest, sizeof(digest));
  if (write_mount(mount_id, &policy) != 0)
    return deny_failed_activation(state);
  memcpy(grant.boot_id, policy.boot_id, sizeof(grant.boot_id));
  memcpy(grant.lease_digest, digest, sizeof(digest));
  grant.epoch = policy.epoch;
  grant.expires_boot_ns = now + ttl_ms * 1000000ULL;
  if (write_grant(mount_id, cgroup_id, &grant) != 0)
    return deny_failed_activation(state);

  policy.phase = AOS_KERNEL_EXPORT_OWNER_ACTIVE;
  if (write_mount(mount_id, &policy) != 0)
    return deny_failed_activation(state);
  state->phase = OWNER_ACTIVE;
  if (write_state(state) != 0)
    return deny_failed_activation(state);
  if (inspect_activated_effect(state, clone_fd, cgroup_fd, handoff_path,
                               lease_path, ack_path, &policy, &grant) != 0)
    return deny_failed_activation(state);
  return 0;
}

static int inspect_current(const struct owner_state *state, int clone_fd,
                           int cgroup_fd, const char *handoff_path,
                           const char *lease_path, const char *ack_path)
{
  struct aos_kernel_export_owner_mount_v1 policy;
  struct aos_kernel_export_owner_grant_v1 grant;
  __u64 mount_id, device, inode, cgroup_id, now, remaining_ms;
  __u64 handoff[4], lease_digest[4];

  if (current_clone(clone_fd, &mount_id, &device, &inode) != 0 ||
      cgroup_id_from_fd(cgroup_fd, &cgroup_id) != 0 ||
      handoff_from_frame(handoff_path, mount_id, device, inode, cgroup_id,
                         state->boot_id, handoff) != 0 ||
      mount_id != state->mount_id || device != state->root_device ||
      inode != state->root_inode || cgroup_id != state->cgroup_id ||
      memcmp(handoff, state->handoff_digest, sizeof(handoff)) != 0 ||
      inspect_installation(mount_id, &policy) != 0 ||
      policy.epoch != state->epoch ||
      policy.root_device != device || policy.root_inode != inode ||
      policy.holder_cgroup_id != cgroup_id ||
      memcmp(policy.handoff_digest, handoff, sizeof(handoff)) != 0 ||
      memcmp(policy.lease_digest, state->lease_digest, 32) != 0)
    return -1;

  if (state->phase == OWNER_PREPARED)
    return lease_path == NULL && ack_path == NULL &&
           policy.phase == AOS_KERNEL_EXPORT_OWNER_PREPARED &&
           grant_absent(mount_id, cgroup_id) == 0 ? 0 : -1;

  if (state->phase != OWNER_ACTIVE || lease_path == NULL ||
      ack_path == NULL ||
      policy.phase != AOS_KERNEL_EXPORT_OWNER_ACTIVE ||
      verify_lease(lease_path, handoff_path, state, lease_digest,
                   &remaining_ms) != 0 ||
      memcmp(lease_digest, state->lease_digest, sizeof(lease_digest)) != 0 ||
      read_grant(mount_id, cgroup_id, &grant) != 0 ||
      grant.state != AOS_KERNEL_EXPORT_GRANT_ACTIVE ||
      grant.version != AOS_KERNEL_EXPORT_DENY_VERSION ||
      grant.epoch != state->epoch ||
      memcmp(grant.boot_id, state->boot_id, sizeof(grant.boot_id)) != 0 ||
      memcmp(grant.lease_digest, lease_digest, sizeof(lease_digest)) != 0 ||
      boot_time_ns(&now) != 0 || grant.expires_boot_ns <= now)
    return -1;

  /* The signed acknowledgment commits the deny-stage row, not ACTIVE bytes. */
  policy.phase = AOS_KERNEL_EXPORT_OWNER_PREPARED;
  memset(policy.lease_digest, 0, sizeof(policy.lease_digest));
  if (verify_stage_ack(ack_path, handoff_path, state, &policy,
                       lease_digest) != 0)
    return -1;
  return 0;
}

/* A successful activation must reobserve every owner-local effect. */
static int inspect_activated_effect(
    const struct owner_state *expected_state, int clone_fd, int cgroup_fd,
    const char *handoff_path, const char *lease_path, const char *ack_path,
    const struct aos_kernel_export_owner_mount_v1 *expected_policy,
    const struct aos_kernel_export_owner_grant_v1 *expected_grant)
{
  struct owner_state persisted_state;
  struct aos_kernel_export_owner_mount_v1 observed_policy;
  struct aos_kernel_export_owner_grant_v1 observed_grant;

  if (read_state(&persisted_state) != 0 ||
      memcmp(&persisted_state, expected_state, sizeof(persisted_state)) != 0 ||
      inspect_current(&persisted_state, clone_fd, cgroup_fd, handoff_path,
                      lease_path, ack_path) != 0 ||
      inspect_installation(expected_state->mount_id, &observed_policy) != 0 ||
      memcmp(&observed_policy, expected_policy, sizeof(observed_policy)) != 0 ||
      read_grant(expected_state->mount_id, expected_state->cgroup_id,
                 &observed_grant) != 0 ||
      memcmp(&observed_grant, expected_grant, sizeof(observed_grant)) != 0)
    return -1;
  return 0;
}

int main(int argc, char **argv)
{
  struct owner_state state;
  char *end = NULL;
  unsigned long long ttl_ms = 0;
  int lock_fd = -1;
  int clone_fd = -1;
  int cgroup_fd = -1;
  int result = -1;

  if (argc == 2 && strcmp(argv[1], "validate") == 0)
    return validate_object() == 0 ? 0 : 1;
  if (geteuid() != 0 || check_bpffs() != 0 ||
      (lock_fd = state_lock()) < 0)
    return 1;

  if (argc == 2 && strcmp(argv[1], "recover") == 0) {
    result = read_state(&state) == 0 ? revoke_state(&state) : verified_empty_owner();
    goto out;
  }
  if (argc < 5 || parse_fd(argv[2], &clone_fd) != 0 ||
      parse_fd(argv[3], &cgroup_fd) != 0 ||
      fcntl(clone_fd, F_SETFD, FD_CLOEXEC) != 0 ||
      fcntl(cgroup_fd, F_SETFD, FD_CLOEXEC) != 0)
    goto out;
  if ((argc == 5 || argc == 7) && strcmp(argv[1], "inspect") == 0 &&
      read_state(&state) == 0) {
    result = inspect_current(&state, clone_fd, cgroup_fd, argv[4],
                             argc == 7 ? argv[5] : NULL,
                             argc == 7 ? argv[6] : NULL);
    goto out;
  }
  if (argc == 5 && strcmp(argv[1], "report-prepared") == 0 &&
      read_state(&state) == 0) {
    result = report_prepared(&state, clone_fd, cgroup_fd, argv[4]);
    goto out;
  }
  if (argc == 7 && strcmp(argv[1], "inspect-stage-v2") == 0 &&
      read_state(&state) == 0) {
    result = inspect_stage_ack_v2(&state, clone_fd, cgroup_fd, argv[4],
                                   argv[5], argv[6]);
    goto out;
  }
  if (argc == 5 && strcmp(argv[1], "inspect-record") == 0 &&
      read_state(&state) == 0) {
    result = inspect_record(&state, clone_fd, cgroup_fd, argv[4]);
    goto out;
  }
  if (argc == 7 && strcmp(argv[1], "record") == 0 &&
      read_state(&state) == 0) {
    result = record_prepared(&state, clone_fd, cgroup_fd, argv[4],
                             argv[5], argv[6]);
    goto out;
  }
  if (argc == 5 && strcmp(argv[1], "stage") == 0) {
    result = stage(clone_fd, cgroup_fd, argv[4]);
    goto out;
  }
  if (argc == 8 && strcmp(argv[1], "activate") == 0 &&
      read_state(&state) == 0) {
    errno = 0;
    ttl_ms = strtoull(argv[7], &end, 10);
    if (errno == 0 && end != argv[7] && *end == '\0')
      result = activate(&state, clone_fd, cgroup_fd, argv[4],
                        argv[5], argv[6], ttl_ms);
  }

out:
  close(lock_fd);
  return result == 0 ? 0 : 1;
}
