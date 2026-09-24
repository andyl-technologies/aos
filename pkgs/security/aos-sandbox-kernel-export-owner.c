// SPDX-License-Identifier: Apache-2.0

/* A private map-owner experiment. No Storage or Provider ingress invokes it. */
#define AOS_KERNEL_EXPORT_OWNER 1
#define AOS_KERNEL_EXPORT_PIN_DIR "/sys/fs/bpf/aos/kernel-export-owner"
#include "aos-sandbox-kernel-export-deny.c"

#include <sys/file.h>
#include <sys/statvfs.h>

#include <openssl/evp.h>

#define STATE_DIR "/var/lib/aos/kernel-export-owner"
#define STATE_FILE STATE_DIR "/state"
#define STATE_TEMP STATE_DIR "/state.new"
#define VERIFIER_FILE STATE_DIR "/storage-verifier"
#define LEASE_BYTES 496U
#define VERIFIER_BYTES 112U
#define HANDOFF_BYTES 344U
#define ACK_BYTES 576U
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

static int handoff_from_frame(const char *path, __u64 mount_id,
                              __u64 device, __u64 inode, __u64 cgroup_id,
                              const __u64 boot_id[2], __u64 digest[4])
{
  unsigned char frame[HANDOFF_BYTES], calculated[32];
  unsigned int size = 0;
  EVP_MD_CTX *context = NULL;
  time_t now = time(NULL);
  int result = -1;

  /* Offsets match Storage's sealed AOSKGH01 frame, not a new owner format. */
  if (protected_file(path, sizeof(frame), frame) != 0 ||
      memcmp(frame, "AOSKGH01", 8) != 0 ||
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
      EVP_DigestUpdate(context, frame + 48, sizeof(frame) - 48) != 1 ||
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

static int staged_policy_digest(__u64 mount_id,
                                const struct aos_kernel_export_owner_mount_v1 *policy,
                                unsigned char digest[32])
{
  unsigned char canonical[128] = {0};
  unsigned int size = 0;
  EVP_MD_CTX *context = NULL;
  int result = -1;

  if (policy->version != AOS_KERNEL_EXPORT_DENY_VERSION ||
      policy->phase != AOS_KERNEL_EXPORT_OWNER_PREPARED ||
      !all_zero((const unsigned char *)policy->lease_digest, 32))
    return -1;
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

static int verify_lease(const char *lease_path, const char *handoff_path,
                        const struct owner_state *state, __u64 digest[4],
                        __u64 *remaining_ms)
{
  unsigned char lease[LEASE_BYTES];
  unsigned char handoff[HANDOFF_BYTES];
  unsigned char verifier[VERIFIER_BYTES];
  unsigned char message[sizeof(signature_domain) + 432];
  unsigned char hash[32];
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  time_t now = time(NULL);
  int result = -1;

  if (protected_file(lease_path, sizeof(lease), lease) != 0 ||
      protected_file(handoff_path, sizeof(handoff), handoff) != 0 ||
      protected_file(VERIFIER_FILE, sizeof(verifier), verifier) != 0 ||
      memcmp(lease, "AOSSLE01", 8) != 0 || lease[8] != 0 || lease[9] != 1 ||
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
      EVP_DigestUpdate(hash_context, lease, sizeof(lease)) != 1 ||
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

static int verify_stage_ack(const char *ack_path, const char *handoff_path,
                            const struct owner_state *state,
                            const struct aos_kernel_export_owner_mount_v1 *prepared,
                            const __u64 lease_digest[4])
{
  unsigned char ack[ACK_BYTES], frame[HANDOFF_BYTES];
  unsigned char verifier[VERIFIER_BYTES], policy_digest[32];
  unsigned char message[sizeof(ack_domain) + 512];
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *context = NULL;
  int result = -1;

  if (protected_file(ack_path, sizeof(ack), ack) != 0 ||
      protected_file(handoff_path, sizeof(frame), frame) != 0 ||
      protected_file(VERIFIER_FILE, sizeof(verifier), verifier) != 0 ||
      memcmp(ack, "AOSKGA01", 8) != 0 ||
      ack[8] != 0 || ack[9] != 1 ||
      memcmp(ack + 10, "\0\0\0\0\0\0", 6) != 0 ||
      memcmp(ack + 16, frame, sizeof(frame)) != 0 ||
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

static int stage(int clone_fd, int cgroup_fd, const char *handoff_path)
{
  struct owner_state state = {.phase = OWNER_PREPARED, .epoch = 1};
  struct aos_kernel_export_owner_mount_v1 policy;
  struct aos_kernel_export_owner_grant_v1 grant;
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
      read_grant(state.mount_id, state.cgroup_id, &grant) == 0)
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

static int activate(struct owner_state *state, int clone_fd, int cgroup_fd,
                    const char *handoff_path, const char *lease_path,
                    const char *ack_path, __u64 ttl_ms)
{
  struct aos_kernel_export_owner_mount_v1 policy;
  struct aos_kernel_export_owner_grant_v1 grant = {
      .state = AOS_KERNEL_EXPORT_GRANT_ACTIVE,
      .version = AOS_KERNEL_EXPORT_DENY_VERSION,
  };
  struct aos_kernel_export_owner_grant_v1 existing_grant;
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
      read_grant(mount_id, cgroup_id, &existing_grant) == 0)
    return -1;

  state->phase = OWNER_ACTIVATING;
  memcpy(state->lease_digest, digest, sizeof(digest));
  if (write_state(state) != 0)
    return -1;

  memcpy(policy.lease_digest, digest, sizeof(digest));
  if (write_mount(mount_id, &policy) != 0)
    return -1;
  memcpy(grant.boot_id, policy.boot_id, sizeof(grant.boot_id));
  memcpy(grant.lease_digest, digest, sizeof(digest));
  grant.epoch = policy.epoch;
  grant.expires_boot_ns = now + ttl_ms * 1000000ULL;
  if (write_grant(mount_id, cgroup_id, &grant) != 0)
    return -1;

  policy.phase = AOS_KERNEL_EXPORT_OWNER_ACTIVE;
  if (write_mount(mount_id, &policy) != 0)
    return revoke_state(state);
  state->phase = OWNER_ACTIVE;
  if (write_state(state) != 0)
    return revoke_state(state);
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
           read_grant(mount_id, cgroup_id, &grant) != 0 ? 0 : -1;

  if (state->phase != OWNER_ACTIVE || lease_path == NULL ||
      ack_path == NULL ||
      policy.phase != AOS_KERNEL_EXPORT_OWNER_ACTIVE ||
      verify_lease(lease_path, handoff_path, state, lease_digest,
                   &remaining_ms) != 0 ||
      memcmp(lease_digest, state->lease_digest, sizeof(lease_digest)) != 0 ||
      read_grant(mount_id, cgroup_id, &grant) != 0 ||
      grant.state != AOS_KERNEL_EXPORT_GRANT_ACTIVE ||
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
    result = read_state(&state) == 0 ? revoke_state(&state) : -1;
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
