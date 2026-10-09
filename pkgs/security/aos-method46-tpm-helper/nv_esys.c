/* SPDX-License-Identifier: Apache-2.0 */
/*
 * One private inherited sequenced-packet carrier, one explicit device TCTI, one salted
 * HMAC session. Only the owning daemon interprets this protocol. There is no
 * listener, shell, TCTI loader/environment, hierarchy credential, provisioning
 * command or independently callable signing authority. The first packet loans
 * exactly two already-held lock OFDs, never journal data or writer APIs.
 *
 * ESYS owns all TPM layouts and response-HMAC checking. Any error exits this
 * carrier, including an ambiguous extend: no following read on a possibly
 * pending ESYS command can manufacture retry authority. A fresh owner must
 * reopen both journals and reconcile through a new authenticated TPM session.
 */
#define _GNU_SOURCE
#include "nv_esys.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <tss2_esys.h>
#include <tss2_mu.h>
#include <tss2_tcti_device.h>

#define HELLO_BYTES 160U
#define LOCK_ACK_BYTES 48U
#define AUTH_BYTES 80U
#define REQUEST_BYTES 84U
#define RESPONSE_BYTES 128U
#define WRITTEN_ATTRIBUTES UINT32_C(0x20040044)
#define FIXED_DEVICE "/dev/tpmrm0"

/* Linux socket UAPI; older libc headers do not name generated record pidfds. */
#ifndef SCM_PIDFD
#define SCM_PIDFD 0x04
#endif

struct floor_context {
    TSS2_TCTI_CONTEXT *device;
    ESYS_CONTEXT *esys;
    ESYS_TR salt;
    ESYS_TR index;
    ESYS_TR session;
    bool device_ready;
    uint32_t index_handle;
    struct stat device_identity;
    uint8_t salt_name[34];
    TSS2_RC failure_rc;
    int failure_errno;
};

static void erase(void *pointer, size_t length)
{
    volatile uint8_t *bytes = pointer;
    while (length-- != 0U)
        *bytes++ = 0;
}

struct private_channel {
    int fd;
    uint64_t cut;
};

static int channel_timeout(const struct private_channel *channel)
{
    if (channel->cut == 0U)
        return -1;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -2;
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L
        || (uint64_t)now.tv_sec > UINT64_MAX / UINT64_C(1000000000)) {
        errno = EOVERFLOW;
        return -2;
    }
    uint64_t seconds = (uint64_t)now.tv_sec * UINT64_C(1000000000);
    if (seconds > UINT64_MAX - (uint64_t)now.tv_nsec) {
        errno = EOVERFLOW;
        return -2;
    }
    uint64_t elapsed = seconds + (uint64_t)now.tv_nsec;
    if (elapsed >= channel->cut) {
        errno = ETIMEDOUT;
        return -2;
    }
    uint64_t remaining = channel->cut - elapsed;
    uint64_t milliseconds = remaining / UINT64_C(1000000)
        + (remaining % UINT64_C(1000000) != 0U);
    return milliseconds > INT32_MAX ? INT32_MAX : (int)milliseconds;
}

static int wait_channel_on(const struct private_channel *channel, short events)
{
    struct pollfd descriptor = { .fd = channel->fd, .events = events };
    for (;;) {
        int timeout = channel_timeout(channel);
        if (timeout == -2)
            return -1;
        int ready = poll(&descriptor, 1, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready == 0 && channel->cut != 0U)
            errno = ETIMEDOUT;
        return ready > 0 && (descriptor.revents & events) != 0 ? 0 : -1;
    }
}

static int receive_frame_on(const struct private_channel *channel,
    uint8_t *bytes, size_t length, pid_t parent, size_t expected_locks,
    int locks[2], size_t *actual_length)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(2 * sizeof(int))
            + CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct iovec vector = { .iov_base = bytes, .iov_len = length };
    struct msghdr message = {
        .msg_iov = &vector,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    ssize_t count;
    for (;;) {
        if (wait_channel_on(channel, POLLIN) != 0)
            return -1;
        message.msg_controllen = sizeof(control.bytes);
        message.msg_flags = 0;
        count = recvmsg(channel->fd, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        break;
    }
    size_t rights_count = 0;
    size_t credential_count = 0;
    size_t pidfd_count = 0;
    int valid = (actual_length != NULL ? count > 0 && count <= (ssize_t)length
                                      : count == (ssize_t)length)
        && (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) == 0;
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_len < CMSG_LEN(0)
            || header->cmsg_len > message.msg_controllen
                - (size_t)((uint8_t *)header - control.bytes)) {
            valid = 0;
            break;
        }
        if (header->cmsg_level != SOL_SOCKET) {
            valid = 0;
            continue;
        }
        if (header->cmsg_type == SCM_RIGHTS) {
            size_t entries = (header->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            int *received = (int *)CMSG_DATA(header);
            valid &= header->cmsg_len == CMSG_LEN(expected_locks * sizeof(int));
            for (size_t index = 0; index < entries; ++index) {
                if (rights_count < expected_locks && rights_count < 2U)
                    locks[rights_count] = received[index];
                else {
                    close(received[index]);
                    valid = 0;
                }
                ++rights_count;
            }
        } else if (header->cmsg_type == SCM_CREDENTIALS) {
            struct ucred credentials = {0};
            if (header->cmsg_len != CMSG_LEN(sizeof(credentials))) {
                valid = 0;
                continue;
            }
            memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
            valid &= credentials.pid == parent && credentials.uid == geteuid()
                && credentials.gid == getegid();
            ++credential_count;
        } else if (header->cmsg_type == SCM_PIDFD) {
            if (header->cmsg_len != CMSG_LEN(sizeof(int))) {
                valid = 0;
                continue;
            }
            int pidfd;
            memcpy(&pidfd, CMSG_DATA(header), sizeof(pidfd));
            close(pidfd);
            ++pidfd_count;
        } else
            valid = 0;
    }
    valid &= rights_count == expected_locks && credential_count == 1U
        && pidfd_count == 1U && getppid() == parent;
    if (valid && actual_length != NULL)
        *actual_length = (size_t)count;
    return valid ? 0 : -1;
}

static int receive_frame(uint8_t *bytes, size_t length, pid_t parent,
    size_t expected_locks, int locks[2])
{
    const struct private_channel channel = { .fd = STDIN_FILENO, .cut = 0 };
    return receive_frame_on(&channel, bytes, length, parent, expected_locks,
        locks, NULL);
}

static int send_frame_on(const struct private_channel *channel,
    const uint8_t *bytes, size_t length)
{
    for (;;) {
        if (wait_channel_on(channel, POLLOUT) != 0)
            return -1;
        ssize_t count = send(channel->fd, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        return count == (ssize_t)length ? 0 : -1;
    }
}

static int send_frame(const uint8_t *bytes, size_t length)
{
    const struct private_channel channel = { .fd = STDIN_FILENO, .cut = 0 };
    return send_frame_on(&channel, bytes, length);
}

static uint32_t get_u32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16)
        | ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static uint64_t get_u64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8U; ++index)
        value = (value << 8) | bytes[index];
    return value;
}

static int validate_locks(const uint8_t hello[HELLO_BYTES], const int locks[2])
{
    struct stat observed[2];
    for (size_t index = 0; index < 2U; ++index) {
        const uint8_t *expected = hello + 120U + index * 20U;
        if (locks[index] < 3 || fstat(locks[index], &observed[index]) != 0
            || !S_ISREG(observed[index].st_mode) || observed[index].st_nlink != 1
            || observed[index].st_size != 0
            || (fcntl(locks[index], F_GETFL) & O_ACCMODE) != O_RDWR
            || (observed[index].st_mode & 07777U) != 0600U
            || observed[index].st_uid != geteuid()
            || (uint64_t)observed[index].st_dev != get_u64(expected)
            || (uint64_t)observed[index].st_ino != get_u64(expected + 8)
            || (uint32_t)observed[index].st_uid != get_u32(expected + 16))
            return -1;
    }
    /* No flock call: unlocking this description would also unlock the parent.
     * The exact OFD loan originates only from its healthy protected writer. */
    return observed[0].st_dev != observed[1].st_dev
        || observed[0].st_ino != observed[1].st_ino ? 0 : -1;
}

static void put_u16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void put_u32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static int nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t aggregate = 0;
    for (size_t index = 0; index < length; ++index)
        aggregate |= bytes[index];
    return aggregate != 0;
}

static int same_device(struct floor_context *context)
{
    struct stat observed;
    if (lstat(FIXED_DEVICE, &observed) != 0 || !S_ISCHR(observed.st_mode)
        || observed.st_uid != 0 || (observed.st_mode & 0002U) != 0)
        return -1;
    return observed.st_dev == context->device_identity.st_dev
        && observed.st_ino == context->device_identity.st_ino
        && observed.st_rdev == context->device_identity.st_rdev ? 0 : -1;
}

static TSS2_RC session_attributes(struct floor_context *context, TPMA_SESSION attributes)
{
    return Esys_TRSess_SetAttributes(context->esys, context->session,
        TPMA_SESSION_CONTINUESESSION | attributes,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT);
}

static int public_name_matches(const TPM2B_PUBLIC *public, const TPM2B_NAME *name)
{
    int valid = public != NULL && name != NULL
        && name->size == 34 && name->name[0] == 0 && name->name[1] == 11;

    /* Never trust a returned Name independently of the RSA public key used to
     * encrypt the session salt. The official MU codec supplies canonical TPMT
     * bytes; OpenSSL recomputes the pinned SHA-256 Name before StartAuthSession. */
    uint8_t marshalled[sizeof(TPMT_PUBLIC)] = {0};
    uint8_t digest[32] = {0};
    size_t offset = 0;
    unsigned int digest_size = 0;
    if (valid) {
        valid = Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea, marshalled,
            sizeof(marshalled), &offset) == TSS2_RC_SUCCESS
            && EVP_Digest(marshalled, offset, digest, &digest_size,
                EVP_sha256(), NULL) == 1
            && digest_size == sizeof(digest)
            && memcmp(digest, name->name + 2, sizeof(digest)) == 0;
    }
    return valid ? 0 : -1;
}

static int validate_salt_public(struct floor_context *context,
    const TPM2B_PUBLIC *public, const TPM2B_NAME *name)
{
    TPMA_OBJECT required = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
        | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
    int valid = public != NULL && name != NULL
        && name->size == sizeof(context->salt_name)
        && memcmp(name->name, context->salt_name, sizeof(context->salt_name)) == 0
        && public->publicArea.nameAlg == TPM2_ALG_SHA256
        && public->publicArea.type == TPM2_ALG_RSA
        && public->publicArea.parameters.rsaDetail.keyBits >= 2048U
        && (public->publicArea.objectAttributes & required) == required
        && (public->publicArea.objectAttributes & TPMA_OBJECT_SIGN_ENCRYPT) == 0;
    return valid && public_name_matches(public, name) == 0 ? 0 : -1;
}

static int check_initial_salt(struct floor_context *context)
{
    TSS2_SYS_CONTEXT *sys = NULL;
    TPM2B_PUBLIC public = {0};
    TPM2B_NAME name = {0};
    TPM2B_NAME qualified = {0};

    /* FromTPMPublic cached this exact completed ReadPublic response. A new
     * ReadPublic would validate a different observation, not the RSA public
     * key ESYS will actually use for salt encryption. Official SAPI Complete
     * resets the decoder over the retained response, without issuing a command
     * or accessing ESYS-private resource layouts. Do this before any new API
     * command can overwrite that response buffer. */
    return Esys_GetSysContext(context->esys, &sys) == TSS2_RC_SUCCESS
        && Tss2_Sys_ReadPublic_Complete(sys, &public, &name, &qualified) == TSS2_RC_SUCCESS
        && validate_salt_public(context, &public, &name) == 0 ? 0 : -1;
}

static int check_salt(struct floor_context *context, ESYS_TR session)
{
    TPM2B_PUBLIC *public = NULL;
    TPM2B_NAME *name = NULL;
    TPM2B_NAME *qualified = NULL;
    TSS2_RC status = Esys_ReadPublic(context->esys, context->salt,
        session, ESYS_TR_NONE, ESYS_TR_NONE, &public, &name, &qualified);
    int valid = status == TSS2_RC_SUCCESS
        && validate_salt_public(context, public, name) == 0;
    Esys_Free(public);
    Esys_Free(name);
    Esys_Free(qualified);
    return valid ? 0 : -1;
}

static void close_context(struct floor_context *context)
{
    /* Finalize does no hierarchy or NV mutation. The RM carrier owns the
     * transient session lifetime; closing it also fences this private channel. */
    if (context->esys != NULL) {
        // SetAuth changes only the local ESYS resource copy, never TPM auth.
        TPM2B_AUTH empty = {0};
        if (context->index != ESYS_TR_NONE)
            (void)Esys_TR_SetAuth(context->esys, context->index, &empty);
        Esys_Finalize(&context->esys);
    }
    if (context->device != NULL) {
        if (context->device_ready)
            Tss2_Tcti_Finalize(context->device);
        free(context->device);
    }
    erase(context, sizeof(*context));
}

static int validate_hello(const uint8_t hello[HELLO_BYTES],
    const struct aos_nv_custody_profile *profile)
{
    uint32_t index = get_u32(hello + 44);
    uint32_t salt = get_u32(hello + 48);
    bool known = false;
    if (profile == NULL || profile->role_count == 0 || profile->role_count > 2)
        return -1;
    for (size_t role = 0; role < profile->role_count; ++role)
        known |= index == profile->roles[role].index
            && salt == profile->roles[role].salt;
    if (!known)
        return -1;
    if (memcmp(hello, "AOSBTH02", 8) != 0 || hello[8] != 0 || hello[9] != 2
        || hello[10] != 0 || hello[11] != 0 || nonzero(hello + 86, 34)
        || !nonzero(hello + 12, 32) || hello[52] != 0 || hello[53] != 11
        || !nonzero(hello + 54, 32))
        return -1;
    return 0;
}

static int validate_auth(const uint8_t auth[AUTH_BYTES], const uint8_t hello[HELLO_BYTES])
{
    return memcmp(auth, "AOSBTA02", 8) == 0 && auth[8] == 0 && auth[9] == 2
        && auth[10] == 0 && auth[11] == 0
        && memcmp(auth + 12, hello + 12, 36) == 0
        && nonzero(auth + 48, 32) ? 0 : -1;
}

static int require_fixed_text(const char *path, long magic, const char *expected)
{
    uint8_t bytes[256];
    struct statfs filesystem;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int valid = fstatfs(fd, &filesystem) == 0 && filesystem.f_type == magic;
    size_t length = 0;
    while (valid && length < sizeof(bytes)) {
        ssize_t count = read(fd, bytes + length, sizeof(bytes) - length);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            valid = 0;
        if (count <= 0)
            break;
        length += (size_t)count;
    }
    close(fd);
    if (!valid || length == 0 || length == sizeof(bytes))
        return -1;
    if (bytes[length - 1] == '\n' || bytes[length - 1] == '\0')
        --length;
    return length == strlen(expected)
        && memcmp(bytes, expected, length) == 0 ? 0 : -1;
}

static int require_helper_role(const uint8_t hello[HELLO_BYTES],
    const struct aos_nv_custody_profile *profile)
{
    const char *context = NULL;
    for (size_t role = 0; role < profile->role_count; ++role) {
        if (get_u32(hello + 44) == profile->roles[role].index)
            context = profile->roles[role].context;
    }
    if (context == NULL)
        return -1;
    return require_fixed_text("/sys/fs/selinux/enforce", SELINUX_MAGIC, "1") == 0
        && require_fixed_text("/proc/self/attr/current", PROC_SUPER_MAGIC, context) == 0 ? 0 : -1;
}

/* One direct-device bootstrap for both closed purposes. Returned allocations
 * enter the actual context immediately. TCTI/ESYS internals before return are
 * not resident application custody and may outlast an application deadline. */
static int open_direct_device(struct floor_context *context)
{
    if (lstat(FIXED_DEVICE, &context->device_identity) != 0
        || same_device(context) != 0) {
        context->failure_errno = errno;
        return -1;
    }

    size_t size = 0;
    context->failure_rc = Tss2_Tcti_Device_Init(NULL, &size, FIXED_DEVICE);
    if (context->failure_rc != TSS2_RC_SUCCESS || size == 0 || size > 65536U)
        return -1;
    context->device = calloc(1, size);
    if (context->device == NULL) {
        context->failure_errno = errno;
        return -1;
    }
    context->failure_rc = Tss2_Tcti_Device_Init(context->device, &size, FIXED_DEVICE);
    if (context->failure_rc != TSS2_RC_SUCCESS)
        return -1;
    context->device_ready = true;
    if (same_device(context) != 0) {
        context->failure_errno = errno;
        return -1;
    }
    context->failure_rc = Esys_Initialize(&context->esys, context->device, NULL);
    if (context->failure_rc != TSS2_RC_SUCCESS)
        return -1;
    context->failure_rc = Esys_SetTimeout(context->esys, 5000);
    return context->failure_rc == TSS2_RC_SUCCESS ? 0 : -1;
}

static int open_context(struct floor_context *context, const uint8_t hello[HELLO_BYTES],
    const uint8_t authentication[AUTH_BYTES],
    const struct aos_nv_custody_profile *profile)
{
    if (validate_hello(hello, profile) != 0 || validate_auth(authentication, hello) != 0
        || prctl(PR_GET_DUMPABLE) != 0 || require_helper_role(hello, profile) != 0)
        return -1;
    uint32_t index = get_u32(hello + 44);
    uint32_t salt = get_u32(hello + 48);
    memcpy(context->salt_name, hello + 52, sizeof(context->salt_name));
    context->index_handle = index;
    if (open_direct_device(context) != 0)
        return -1;
    if (Esys_TR_FromTPMPublic(context->esys, salt, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, &context->salt) != TSS2_RC_SUCCESS
        || check_initial_salt(context) != 0)
        return -1;

    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 }, .mode = { .aes = TPM2_ALG_CFB } };
    if (Esys_StartAuthSession(context->esys, context->salt, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
            &symmetric, TPM2_ALG_SHA256, &context->session) != TSS2_RC_SUCCESS
        || session_attributes(context, 0) != TSS2_RC_SUCCESS
        || check_salt(context, context->session) != 0
        || Esys_TR_FromTPMPublic(context->esys, index, context->session,
            ESYS_TR_NONE, ESYS_TR_NONE, &context->index) != TSS2_RC_SUCCESS)
        return -1;

    TPM2B_AUTH auth = { .size = 32 };
    memcpy(auth.buffer, authentication + 48, 32);
    TSS2_RC status = Esys_TR_SetAuth(context->esys, context->index, &auth);
    erase(&auth, sizeof(auth));
    return status == TSS2_RC_SUCCESS && same_device(context) == 0 ? 0 : -1;
}

static int read_observation(struct floor_context *context, uint8_t reply[RESPONSE_BYTES])
{
    TPM2B_NV_PUBLIC *public = NULL;
    TPM2B_NAME *name = NULL;
    TPM2B_MAX_NV_BUFFER *value = NULL;
    int valid = 0;
    if (same_device(context) != 0
        || session_attributes(context, 0) != TSS2_RC_SUCCESS
        || check_salt(context, context->session) != 0
        || Esys_NV_ReadPublic(context->esys, context->index, context->session,
            ESYS_TR_NONE, ESYS_TR_NONE, &public, &name) != TSS2_RC_SUCCESS
        || public == NULL || name == NULL || name->size != 34
        || public->nvPublic.nvIndex != context->index_handle
        || public->nvPublic.nameAlg != TPM2_ALG_SHA256
        || public->nvPublic.attributes != WRITTEN_ATTRIBUTES
        || public->nvPublic.dataSize != 32 || public->nvPublic.authPolicy.size != 0)
        goto finished;
    if (session_attributes(context, TPMA_SESSION_ENCRYPT) != TSS2_RC_SUCCESS
        || Esys_NV_Read(context->esys, context->index, context->index,
            context->session, ESYS_TR_NONE, ESYS_TR_NONE, 32, 0, &value) != TSS2_RC_SUCCESS
        || value == NULL || value->size != 32 || !nonzero(value->buffer, 32)
        || same_device(context) != 0)
        goto finished;
    memcpy(reply + 52, name->name, 34);
    put_u16(reply + 86, public->nvPublic.nameAlg);
    put_u32(reply + 88, public->nvPublic.attributes);
    put_u16(reply + 92, public->nvPublic.dataSize);
    put_u16(reply + 94, public->nvPublic.authPolicy.size);
    memcpy(reply + 96, value->buffer, 32);
    valid = 1;
finished:
    Esys_Free(public);
    Esys_Free(name);
    Esys_Free(value);
    return valid ? 0 : -1;
}

static int extend_index(struct floor_context *context, const uint8_t input[32])
{
    TPM2B_MAX_NV_BUFFER data = { .size = 32 };
    memcpy(data.buffer, input, 32);
    if (same_device(context) != 0
        || session_attributes(context, TPMA_SESSION_DECRYPT) != TSS2_RC_SUCCESS)
        return -1;
    return Esys_NV_Extend(context->esys, context->index, context->index,
        context->session, ESYS_TR_NONE, ESYS_TR_NONE, &data) == TSS2_RC_SUCCESS
        && same_device(context) == 0 ? 0 : -1;
}

int aos_nv_custody_run(int argc, const struct aos_nv_custody_profile *profile)
{
    struct floor_context context = {
        .salt = ESYS_TR_NONE,
        .index = ESYS_TR_NONE,
        .session = ESYS_TR_NONE,
    };
    uint8_t hello[HELLO_BYTES] = {0};
    uint8_t authentication[AUTH_BYTES] = {0};
    uint8_t nonce[32] = {0};
    uint64_t sequence = 1;
    int status = EXIT_FAILURE;
    int locks[2] = {-1, -1};
    pid_t parent = getppid();
    if (argc != 1 || parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0
        || getppid() != parent || close_range(3, ~0U, 0) != 0
        || receive_frame(hello, sizeof(hello), parent, 2U, locks) != 0
        || validate_hello(hello, profile) != 0
        || require_helper_role(hello, profile) != 0
        || validate_locks(hello, locks) != 0)
        goto finished;
    memcpy(nonce, hello + 12, sizeof(nonce));
    /* Public HELLO follows the parent's fixed image/loader observation. Become
     * nondumpable before acknowledging custody, and only then receive auth.
     * No later exec or fork occurs; no device is opened before authentication. */
    uint8_t acknowledgment[LOCK_ACK_BYTES] = {0};
    memcpy(acknowledgment, "AOSBTK02", 8);
    acknowledgment[9] = 2;
    memcpy(acknowledgment + 12, nonce, sizeof(nonce));
    acknowledgment[45] = 2;
    if (prctl(PR_SET_DUMPABLE, 0) != 0
        || prctl(PR_GET_DUMPABLE) != 0
        || send_frame(acknowledgment, sizeof(acknowledgment)) != 0
        || receive_frame(authentication, sizeof(authentication), parent, 0U, locks) != 0
        || validate_auth(authentication, hello) != 0
        || open_context(&context, hello, authentication, profile) != 0)
        goto finished;
    erase(authentication, sizeof(authentication));
    erase(hello, sizeof(hello));

    for (;;) {
        uint8_t request[REQUEST_BYTES] = {0};
        uint8_t reply[RESPONSE_BYTES] = {0};
        if (receive_frame(request, sizeof(request), parent, 0U, locks) != 0)
            break;
        uint8_t operation = request[10];
        if (memcmp(request, "AOSBTQ02", 8) != 0 || request[8] != 0 || request[9] != 2
            || request[11] != 0 || memcmp(request + 12, nonce, sizeof(nonce)) != 0
            || get_u64(request + 44) != sequence || sequence == UINT64_MAX
            || (operation != 1 && operation != 2)
            || (operation == 1 && nonzero(request + 52, 32))
            || (operation == 2 && !nonzero(request + 52, 32)))
            break;
        if (operation == 2 && extend_index(&context, request + 52) != 0)
            break;
        memcpy(reply, "AOSBTR02", 8);
        reply[9] = 2;
        reply[10] = operation;
        memcpy(reply + 12, nonce, sizeof(nonce));
        memcpy(reply + 44, request + 44, 8);
        if (read_observation(&context, reply) != 0
            || send_frame(reply, sizeof(reply)) != 0)
            break;
        ++sequence;
    }
finished:
    erase(authentication, sizeof(authentication));
    erase(hello, sizeof(hello));
    close_context(&context);
    /* Explicit orderly close drains TPM before dropping custody. SIGKILL's
     * deferred __fput order is NOT such a proof: required-mode PID 1 must wait
     * for the exact existing service cgroup population to become empty. */
    for (size_t index = 0; index < 2U; ++index) {
        if (locks[index] >= 0)
            close(locks[index]);
    }
    return status;
}

/* Undeployed V5 offline protocol. These fixed widths do not change V2. The
 * private returned-output slots survive every later check until explicit exit;
 * they cannot retain allocations which ESYS discards before returning. */
#define OFFLINE_HEADER_BYTES 152U
#define OFFLINE_BODY_BYTES 2208U
#define OFFLINE_FRAME_BYTES (OFFLINE_HEADER_BYTES + OFFLINE_BODY_BYTES)
#define OFFLINE_RSA_ATTRIBUTES UINT32_C(0x00030072)
#define OFFLINE_NV_ATTRIBUTES UINT32_C(0x00040044)
#ifndef AOS_NIX_OFFLINE_COMPILED_CONTRACT
#define AOS_NIX_OFFLINE_COMPILED_CONTRACT ""
#endif

static const char offline_compiled_contract[] = AOS_NIX_OFFLINE_COMPILED_CONTRACT;

_Static_assert(sizeof(uint32_t) == 4 && sizeof(uint64_t) == 8,
    "offline V5 integer ABI differs");
_Static_assert(sizeof(((TPM2B_PRIVATE *)0)->buffer) == 1550,
    "offline V5 private MU bound differs");

struct offline_context {
    struct floor_context floor;
    struct private_channel channel;
    ESYS_TR parent;
    ESYS_TR loaded;
    TPM2B_PUBLIC *public[4];
    TPM2B_NAME *name[6];
    TPM2B_NV_PUBLIC *nv_public[2];
    TPM2B_PRIVATE *private;
    uint8_t header[OFFLINE_HEADER_BYTES];
    uint8_t authentication[168];
    uint8_t request[OFFLINE_FRAME_BYTES];
    uint8_t reply[OFFLINE_FRAME_BYTES];
    uint8_t work[OFFLINE_BODY_BYTES];
    TPM2B_PUBLIC input_public[2];
    TPM2B_PRIVATE input_private;
    TPM2B_NAME input_name[2];
    uint32_t salt_handle;
    uint32_t nv_handle;
    TSS2_RC absent_salt;
    TSS2_RC absent_nv;
    uint32_t stage;
};

static int offline_cut(struct offline_context *context)
{
    if (channel_timeout(&context->channel) == -2) {
        context->floor.failure_errno = errno;
        return -1;
    }
    if (context->floor.device_ready && same_device(&context->floor) != 0) {
        context->floor.failure_errno = errno;
        return -1;
    }
    return 0;
}

static int offline_status(struct offline_context *context, TSS2_RC status)
{
    if (status != TSS2_RC_SUCCESS) {
        context->floor.failure_rc = status;
        return -1;
    }
    return offline_cut(context);
}

/* Finish, not Async, is repeated on TRY_AGAIN. A lost result never resubmits
 * an action. TCTI bootstrap, RAND and internal allocation remain nonpreemptible
 * intervals; the parent owns the actual child/debt even after this cut. */
#define OFFLINE_ASYNC(context, call) do { \
    if (offline_cut(context) != 0 || offline_status(context, (call)) != 0) \
        return -1; \
} while (0)

#define OFFLINE_FINISH(context, call) do { \
    TSS2_RC finished; \
    do { \
        if (offline_cut(context) != 0) \
            return -1; \
        finished = (call); \
    } while (finished == TSS2_ESYS_RC_TRY_AGAIN); \
    if (offline_status(context, finished) != 0) \
        return -1; \
} while (0)

static TPM2B_PUBLIC offline_template(void)
{
    TPM2B_PUBLIC public = {0};
    public.publicArea.type = TPM2_ALG_RSA;
    public.publicArea.nameAlg = TPM2_ALG_SHA256;
    public.publicArea.objectAttributes = OFFLINE_RSA_ATTRIBUTES;
    public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
    public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
    public.publicArea.parameters.rsaDetail.keyBits = 2048;
    public.publicArea.parameters.rsaDetail.exponent = 0;
    return public;
}

static int offline_public(const TPM2B_PUBLIC *public, const TPM2B_NAME *name)
{
    if (public == NULL || public->publicArea.type != TPM2_ALG_RSA
        || public->publicArea.nameAlg != TPM2_ALG_SHA256
        || public->publicArea.objectAttributes != OFFLINE_RSA_ATTRIBUTES
        || public->publicArea.authPolicy.size != 0
        || public->publicArea.parameters.rsaDetail.symmetric.algorithm != TPM2_ALG_AES
        || public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes != 128
        || public->publicArea.parameters.rsaDetail.symmetric.mode.aes != TPM2_ALG_CFB
        || public->publicArea.parameters.rsaDetail.scheme.scheme != TPM2_ALG_NULL
        || public->publicArea.parameters.rsaDetail.keyBits != 2048
        || public->publicArea.parameters.rsaDetail.exponent != 0
        || public->publicArea.unique.rsa.size != 256)
        return -1;
    return public_name_matches(public, name);
}

static int offline_marshal_public(const TPM2B_PUBLIC *public, uint8_t bytes[284])
{
    size_t offset = 0;
    return Tss2_MU_TPM2B_PUBLIC_Marshal(public, bytes, 284, &offset)
        == TSS2_RC_SUCCESS && offset == 284 ? 0 : -1;
}

static int offline_marshal_nv(struct offline_context *context,
    const TPM2B_NV_PUBLIC *public, const TPM2B_NAME *name, uint8_t bytes[16])
{
    if (public == NULL || name == NULL || name->size != 34
        || public->nvPublic.nvIndex != context->nv_handle
        || public->nvPublic.nameAlg != TPM2_ALG_SHA256
        || public->nvPublic.attributes != OFFLINE_NV_ATTRIBUTES
        || public->nvPublic.authPolicy.size != 0 || public->nvPublic.dataSize != 32)
        return -1;
    uint8_t canonical[14], digest[32];
    size_t offset = 0;
    unsigned int digest_size = 0;
    if (Tss2_MU_TPMS_NV_PUBLIC_Marshal(&public->nvPublic, canonical,
            sizeof(canonical), &offset) != TSS2_RC_SUCCESS || offset != 14
        || EVP_Digest(canonical, offset, digest, &digest_size, EVP_sha256(), NULL) != 1
        || digest_size != 32 || name->name[0] != 0 || name->name[1] != 11
        || memcmp(name->name + 2, digest, 32) != 0)
        return -1;
    offset = 0;
    return Tss2_MU_TPM2B_NV_PUBLIC_Marshal(public, bytes, 16, &offset)
        == TSS2_RC_SUCCESS && offset == 16 ? 0 : -1;
}

static int offline_session(struct offline_context *context)
{
    TPM2B_AUTH hierarchy = { .size = 32 };
    memcpy(hierarchy.buffer, context->authentication + 8, 32);
    TSS2_RC status = Esys_TR_SetAuth(context->floor.esys, ESYS_TR_RH_OWNER, &hierarchy);
    erase(&hierarchy, sizeof(hierarchy));
    if (offline_status(context, status) != 0)
        return -1;
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 }, .mode = { .aes = TPM2_ALG_CFB } };
    OFFLINE_ASYNC(context, Esys_StartAuthSession_Async(context->floor.esys,
        ESYS_TR_NONE, ESYS_TR_RH_OWNER, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        NULL, TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256));
    OFFLINE_FINISH(context, Esys_StartAuthSession_Finish(context->floor.esys,
        &context->floor.session));
    return offline_status(context, session_attributes(&context->floor, 0));
}

static int offline_primary(struct offline_context *context)
{
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    sensitive.sensitive.userAuth.size = 32;
    memcpy(sensitive.sensitive.userAuth.buffer, context->authentication + 8, 32);
    TPM2B_PUBLIC public = offline_template();
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION selection = {0};
    if (offline_status(context, session_attributes(&context->floor,
            TPMA_SESSION_DECRYPT)) != 0) {
        erase(&sensitive, sizeof(sensitive));
        return -1;
    }
    TSS2_RC status = Esys_CreatePrimary_Async(context->floor.esys, ESYS_TR_RH_OWNER,
        context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive,
        &public, &outside, &selection);
    erase(&sensitive, sizeof(sensitive));
    if (offline_status(context, status) != 0)
        return -1;
    OFFLINE_FINISH(context, Esys_CreatePrimary_Finish(context->floor.esys,
        &context->parent, &context->public[0], NULL, NULL, NULL));
    OFFLINE_ASYNC(context, Esys_TR_GetName(context->floor.esys,
        context->parent, &context->name[0]));
    if (offline_public(context->public[0], context->name[0]) != 0)
        return -1;
    TPM2B_AUTH auth = { .size = 32 };
    memcpy(auth.buffer, context->authentication + 8, 32);
    status = Esys_TR_SetAuth(context->floor.esys, context->parent, &auth);
    erase(&auth, sizeof(auth));
    return offline_status(context, status);
}

static int offline_read_salt(struct offline_context *context, ESYS_TR handle,
    size_t public_slot, size_t name_slot)
{
    if (offline_status(context, session_attributes(&context->floor, 0)) != 0)
        return -1;
    OFFLINE_ASYNC(context, Esys_ReadPublic_Async(context->floor.esys, handle,
        context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE));
    OFFLINE_FINISH(context, Esys_ReadPublic_Finish(context->floor.esys,
        &context->public[public_slot], &context->name[name_slot],
        &context->name[name_slot + 1]));
    return offline_public(context->public[public_slot], context->name[name_slot]);
}

static int offline_import(struct offline_context *context, uint32_t handle,
    ESYS_TR *destination, TSS2_RC *absence)
{
    OFFLINE_ASYNC(context, Esys_TR_FromTPMPublic_Async(context->floor.esys, handle,
        context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE));
    TSS2_RC status;
    do {
        if (offline_cut(context) != 0)
            return -1;
        status = Esys_TR_FromTPMPublic_Finish(context->floor.esys, destination);
    } while (status == TSS2_ESYS_RC_TRY_AGAIN);
    if ((status & TSS2_RC_LAYER_MASK) == 0
        && (status & ~TPM2_RC_N_MASK) == TPM2_RC_HANDLE) {
        *absence = status;
        return offline_cut(context);
    }
    return offline_status(context, status);
}

static int offline_observe(struct offline_context *context, size_t *length)
{
    uint8_t *body = context->reply + OFFLINE_HEADER_BYTES;
    if (offline_import(context, context->salt_handle, &context->floor.salt,
            &context->absent_salt) != 0
        || offline_import(context, context->nv_handle, &context->floor.index,
            &context->absent_nv) != 0)
        return -1;
    if (context->absent_salt == 0) {
        if (offline_read_salt(context, context->floor.salt, 0, 0) != 0
            || offline_marshal_public(context->public[0], body + 88) != 0)
            return -1;
        put_u32(body + 8, get_u32(body + 8) | 1U);
        memcpy(body + 12, context->name[0]->name, 34);
        put_u32(body + 80, 284);
    }
    if (context->absent_nv == 0) {
        if (offline_status(context, session_attributes(&context->floor, 0)) != 0)
            return -1;
        OFFLINE_ASYNC(context, Esys_NV_ReadPublic_Async(context->floor.esys,
            context->floor.index, context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE));
        OFFLINE_FINISH(context, Esys_NV_ReadPublic_Finish(context->floor.esys,
            &context->nv_public[0], &context->name[2]));
        if (offline_marshal_nv(context, context->nv_public[0], context->name[2],
                body + 372) != 0)
            return -1;
        put_u32(body + 8, get_u32(body + 8) | 2U);
        memcpy(body + 46, context->name[2]->name, 34);
        put_u32(body + 84, 16);
    }
    *length = 388;
    return offline_cut(context);
}

static int offline_create(struct offline_context *context, size_t *length)
{
    if (offline_primary(context) != 0)
        return -1;
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    sensitive.sensitive.userAuth.size = 32;
    size_t auth_offset = context->header[11] == 1 ? 72 : 136;
    memcpy(sensitive.sensitive.userAuth.buffer, context->authentication + auth_offset, 32);
    TPM2B_PUBLIC public = offline_template();
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION selection = {0};
    if (offline_status(context, session_attributes(&context->floor,
            TPMA_SESSION_DECRYPT)) != 0) {
        erase(&sensitive, sizeof(sensitive));
        return -1;
    }
    TSS2_RC status = Esys_Create_Async(context->floor.esys, context->parent,
        context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive,
        &public, &outside, &selection);
    erase(&sensitive, sizeof(sensitive));
    if (offline_status(context, status) != 0)
        return -1;
    OFFLINE_FINISH(context, Esys_Create_Finish(context->floor.esys,
        &context->private, &context->public[1], NULL, NULL, NULL));
    if (context->private == NULL || context->private->size == 0
        || context->private->size > 1550 || context->public[1] == NULL)
        return -1;
    if (offline_status(context, session_attributes(&context->floor,
            TPMA_SESSION_DECRYPT)) != 0)
        return -1;
    OFFLINE_ASYNC(context, Esys_Load_Async(context->floor.esys, context->parent,
        context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE,
        context->private, context->public[1]));
    OFFLINE_FINISH(context, Esys_Load_Finish(context->floor.esys, &context->loaded));
    OFFLINE_ASYNC(context, Esys_TR_GetName(context->floor.esys,
        context->loaded, &context->name[1]));
    if (offline_public(context->public[1], context->name[1]) != 0)
        return -1;
    uint8_t *body = context->reply + OFFLINE_HEADER_BYTES;
    memcpy(body + 8, context->name[0]->name, 34);
    memcpy(body + 42, context->name[1]->name, 34);
    put_u32(body + 76, 284);
    put_u32(body + 80, 284);
    if (offline_marshal_public(context->public[0], body + 88) != 0
        || offline_marshal_public(context->public[1], body + 372) != 0)
        return -1;
    size_t offset = 0;
    status = Tss2_MU_TPM2B_PRIVATE_Marshal(context->private, body + 656, 1552, &offset);
    if (offline_status(context, status) != 0 || offset < 3 || offset > 1552)
        return -1;
    put_u32(body + 84, (uint32_t)offset);
    *length = 656 + offset;
    return offline_cut(context);
}

static int offline_persist(struct offline_context *context, size_t request_length,
    size_t *length)
{
    const uint8_t *body = context->request + OFFLINE_HEADER_BYTES;
    if (request_length < OFFLINE_HEADER_BYTES + 659
        || get_u32(body + 76) != 284 || get_u32(body + 80) != 284
        || get_u32(body + 84) < 3 || get_u32(body + 84) > 1552
        || request_length != OFFLINE_HEADER_BYTES + 656 + get_u32(body + 84))
        return -1;
    TPM2B_PUBLIC *parent_public = &context->input_public[0];
    TPM2B_PUBLIC *salt_public = &context->input_public[1];
    TPM2B_PRIVATE *private = &context->input_private;
    TPM2B_NAME *parent_name = &context->input_name[0];
    TPM2B_NAME *salt_name = &context->input_name[1];
    parent_name->size = 34;
    salt_name->size = 34;
    memcpy(parent_name->name, body + 8, 34);
    memcpy(salt_name->name, body + 42, 34);
    size_t offset = 0;
    if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(body + 88, 284, &offset, parent_public)
            != TSS2_RC_SUCCESS || offset != 284)
        return -1;
    offset = 0;
    if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(body + 372, 284, &offset, salt_public)
            != TSS2_RC_SUCCESS || offset != 284)
        return -1;
    offset = 0;
    TSS2_RC status = Tss2_MU_TPM2B_PRIVATE_Unmarshal(body + 656,
        get_u32(body + 84), &offset, private);
    if (offline_status(context, status) != 0 || offset != get_u32(body + 84)
        || private->size == 0 || private->size > 1550
        || offline_public(parent_public, parent_name) != 0
        || offline_public(salt_public, salt_name) != 0)
        return -1;
    if (offline_marshal_public(parent_public, context->work) != 0
        || memcmp(context->work, body + 88, 284) != 0
        || offline_marshal_public(salt_public, context->work) != 0
        || memcmp(context->work, body + 372, 284) != 0)
        return -1;
    offset = 0;
    if (Tss2_MU_TPM2B_PRIVATE_Marshal(private, context->work, sizeof(context->work), &offset)
            != TSS2_RC_SUCCESS || offset != get_u32(body + 84)
        || memcmp(context->work, body + 656, offset) != 0)
        return -1;
    if (offline_primary(context) != 0
        || memcmp(context->name[0]->name, parent_name->name, 34) != 0)
        return -1;
    if (offline_status(context, session_attributes(&context->floor,
            TPMA_SESSION_DECRYPT)) != 0)
        return -1;
    OFFLINE_ASYNC(context, Esys_Load_Async(context->floor.esys, context->parent,
        context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE, private, salt_public));
    OFFLINE_FINISH(context, Esys_Load_Finish(context->floor.esys, &context->loaded));
    if (offline_read_salt(context, context->loaded, 1, 1) != 0
        || memcmp(context->name[1]->name, salt_name->name, 34) != 0)
        return -1;
    if (offline_import(context, context->salt_handle, &context->floor.salt,
            &context->absent_salt) != 0 || context->absent_salt == 0)
        return -1;
    if (offline_status(context, session_attributes(&context->floor, 0)) != 0)
        return -1;
    OFFLINE_ASYNC(context, Esys_EvictControl_Async(context->floor.esys,
        ESYS_TR_RH_OWNER, context->loaded, context->floor.session,
        ESYS_TR_NONE, ESYS_TR_NONE, context->salt_handle));
    OFFLINE_FINISH(context, Esys_EvictControl_Finish(context->floor.esys,
        &context->floor.salt));
    if (offline_read_salt(context, context->floor.salt, 2, 3) != 0
        || memcmp(context->name[3]->name, salt_name->name, 34) != 0)
        return -1;
    uint8_t *reply = context->reply + OFFLINE_HEADER_BYTES;
    memcpy(reply + 8, context->name[3]->name, 34);
    put_u32(reply + 42, 284);
    if (offline_marshal_public(context->public[2], reply + 46) != 0)
        return -1;
    *length = 330;
    return offline_cut(context);
}

static int offline_define(struct offline_context *context, size_t *length)
{
    if (offline_import(context, context->nv_handle, &context->floor.index,
            &context->absent_nv) != 0 || context->absent_nv == 0)
        return -1;
    TPM2B_NV_PUBLIC public = {0};
    public.nvPublic.nvIndex = context->nv_handle;
    public.nvPublic.nameAlg = TPM2_ALG_SHA256;
    public.nvPublic.attributes = OFFLINE_NV_ATTRIBUTES;
    public.nvPublic.dataSize = 32;
    TPM2B_AUTH auth = { .size = 32 };
    size_t auth_offset = context->header[11] == 1 ? 40 : 104;
    memcpy(auth.buffer, context->authentication + auth_offset, 32);
    if (offline_status(context, session_attributes(&context->floor,
            TPMA_SESSION_DECRYPT)) != 0) {
        erase(&auth, sizeof(auth));
        return -1;
    }
    TSS2_RC status = Esys_NV_DefineSpace_Async(context->floor.esys,
        ESYS_TR_RH_OWNER, context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE,
        &auth, &public);
    erase(&auth, sizeof(auth));
    if (offline_status(context, status) != 0)
        return -1;
    OFFLINE_FINISH(context, Esys_NV_DefineSpace_Finish(context->floor.esys,
        &context->floor.index));
    if (offline_status(context, session_attributes(&context->floor, 0)) != 0)
        return -1;
    OFFLINE_ASYNC(context, Esys_NV_ReadPublic_Async(context->floor.esys,
        context->floor.index, context->floor.session, ESYS_TR_NONE, ESYS_TR_NONE));
    OFFLINE_FINISH(context, Esys_NV_ReadPublic_Finish(context->floor.esys,
        &context->nv_public[0], &context->name[0]));
    uint8_t *body = context->reply + OFFLINE_HEADER_BYTES;
    if (offline_marshal_nv(context, context->nv_public[0], context->name[0], body + 42) != 0)
        return -1;
    memcpy(body + 8, context->name[0]->name, 34);
    *length = 58;
    return offline_cut(context);
}

static int offline_frame(struct offline_context *context, size_t length,
    uint8_t kind, size_t body_length)
{
    const uint8_t *frame = context->request;
    if (length != OFFLINE_HEADER_BYTES + body_length
        || memcmp(frame, context->header, 10) != 0 || frame[10] != kind
        || memcmp(frame + 11, context->header + 11, 133) != 0
        || get_u32(frame + 144) != body_length || get_u32(frame + 148) != 0
        || get_u64(frame + OFFLINE_HEADER_BYTES) != context->channel.cut)
        return -1;
    return offline_cut(context);
}

static void offline_reply(struct offline_context *context, uint8_t kind,
    size_t body_length, uint32_t status)
{
    memcpy(context->reply, context->header, OFFLINE_HEADER_BYTES);
    context->reply[10] = kind;
    put_u32(context->reply + 144, (uint32_t)body_length);
    put_u32(context->reply + 148, status);
    memcpy(context->reply + OFFLINE_HEADER_BYTES,
        context->request + OFFLINE_HEADER_BYTES, 8);
}

static int offline_terminal_ack(struct offline_context *context, pid_t parent,
    int locks[2], size_t *length)
{
    return receive_frame_on(&context->channel, context->request,
            sizeof(context->request), parent, 0, locks, length) == 0
        && offline_frame(context, *length, 6, 8) == 0 ? 0 : -1;
}

static int offline_hello(struct offline_context *context, size_t length,
    const int locks[2])
{
    const uint8_t *frame = context->request;
    if (length != OFFLINE_HEADER_BYTES + 80
        || memcmp(frame, "AOSNVP05", 8) != 0 || frame[8] != 0 || frame[9] != 5
        || frame[10] != 1 || (frame[11] != 1 && frame[11] != 2)
        || (frame[12] != 1 && frame[12] != 2) || frame[13] == 0 || frame[13] > 10
        || !nonzero(frame + 16, 16) || !nonzero(frame + 32, 16)
        || !nonzero(frame + 48, 32) || !nonzero(frame + 80, 32)
        || !nonzero(frame + 112, 16) || get_u32(frame + 144) != 80
        || get_u32(frame + 148) != 0)
        return -1;
    /* The package embeds the same independently approved contract which the
     * parent retains through its original profile. Check it before dumpability
     * changes, ACK or any device bootstrap; a caller hash is not an admission. */
    static const char hexadecimal[] = "0123456789abcdef";
    const uint8_t *contract = frame + OFFLINE_HEADER_BYTES + 8;
    for (size_t index = 0; index < 32; ++index) {
        if (offline_compiled_contract[index * 2] != hexadecimal[contract[index] >> 4]
            || offline_compiled_contract[index * 2 + 1]
                != hexadecimal[contract[index] & 15U])
            return -1;
    }
    uint8_t slot = frame[13];
    uint8_t purpose = slot == 1 || (slot >= 3 && slot <= 5) || slot == 9 ? 1 : 2;
    uint16_t ordinal = slot >= 3 && slot <= 8 ? slot - 2 : 0;
    if (frame[11] != purpose || frame[14] != 0 || frame[15] != ordinal)
        return -1;
    uint64_t first = get_u64(frame + 128), deadline = get_u64(frame + 136);
    uint64_t cut = get_u64(frame + OFFLINE_HEADER_BYTES);
    if (first == 0 || first > UINT64_MAX - UINT64_C(300000000000)
        || deadline != first + UINT64_C(300000000000) || cut == 0 || cut > deadline)
        return -1;
    struct stat loan[2], inherited[2];
    for (size_t index = 0; index < 2; ++index) {
        const uint8_t *expected = frame + OFFLINE_HEADER_BYTES + 40 + index * 20;
        if (locks[index] < 6 || fstat(locks[index], &loan[index]) != 0
            || fstat(4 + (int)index, &inherited[index]) != 0
            || !S_ISREG(loan[index].st_mode) || loan[index].st_nlink != 1
            || loan[index].st_size != 0 || (loan[index].st_mode & 07777U) != 0600U
            || loan[index].st_uid != 0 || loan[index].st_gid != 0
            || (fcntl(locks[index], F_GETFL) & O_ACCMODE) != O_RDWR
            || loan[index].st_dev != inherited[index].st_dev
            || loan[index].st_ino != inherited[index].st_ino
            || (uint64_t)loan[index].st_dev != get_u64(expected)
            || (uint64_t)loan[index].st_ino != get_u64(expected + 8)
            || get_u32(expected + 16) != 0)
            return -1;
    }
    if (loan[0].st_dev == loan[1].st_dev && loan[0].st_ino == loan[1].st_ino)
        return -1;
    memcpy(context->header, frame, OFFLINE_HEADER_BYTES);
    context->channel.cut = cut;
    context->salt_handle = purpose == 1 ? UINT32_C(0x8100a058) : UINT32_C(0x8100a059);
    context->nv_handle = purpose == 1 ? UINT32_C(0x0180a058) : UINT32_C(0x0180a059);
    return offline_cut(context);
}

static void offline_close(struct offline_context *context)
{
    /* This is orderly application cleanup, not a kernel/device Drain proof.
     * The parent's original cgroup/population fence covers failed or late exits. */
    erase(context->authentication, sizeof(context->authentication));
    erase(context->request, sizeof(context->request));
    erase(context->reply, sizeof(context->reply));
    erase(context->work, sizeof(context->work));
    erase(&context->input_private, sizeof(context->input_private));
    if (context->private != NULL) {
        erase(context->private, sizeof(*context->private));
        Esys_Free(context->private);
    }
    for (size_t index = 0; index < 4; ++index)
        Esys_Free(context->public[index]);
    for (size_t index = 0; index < 6; ++index)
        Esys_Free(context->name[index]);
    for (size_t index = 0; index < 2; ++index)
        Esys_Free(context->nv_public[index]);
    close_context(&context->floor);
}

int aos_nix_offline_provision_run(int argc)
{
    struct offline_context context = {
        .floor = { .salt = ESYS_TR_NONE, .index = ESYS_TR_NONE, .session = ESYS_TR_NONE },
        .channel = { .fd = 3, .cut = 0 },
        .parent = ESYS_TR_NONE,
        .loaded = ESYS_TR_NONE,
    };
    int locks[2] = {-1, -1};
    size_t length = 0;
    int status = EXIT_FAILURE;
    pid_t parent = getppid();
    if (argc != 1 || sizeof(offline_compiled_contract) != 65 || parent <= 1
        || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0
        || getppid() != parent
        || require_fixed_text("/sys/fs/selinux/enforce", SELINUX_MAGIC, "1") != 0
        || require_fixed_text("/proc/self/attr/current", PROC_SUPER_MAGIC,
            "system_u:system_r:aos_nix_offline_tpm_helper_t") != 0
        || receive_frame_on(&context.channel, context.request, sizeof(context.request),
            parent, 2, locks, &length) != 0
        || offline_hello(&context, length, locks) != 0)
        goto finished;
    offline_reply(&context, 2, 8, 0);
    if (prctl(PR_SET_DUMPABLE, 0) != 0 || prctl(PR_GET_DUMPABLE) != 0
        || send_frame_on(&context.channel, context.reply, OFFLINE_HEADER_BYTES + 8) != 0
        || receive_frame_on(&context.channel, context.request, sizeof(context.request),
            parent, 0, locks, &length) != 0
        || offline_frame(&context, length, 3, sizeof(context.authentication)) != 0)
        goto finished;
    memcpy(context.authentication, context.request + OFFLINE_HEADER_BYTES,
        sizeof(context.authentication));
    for (size_t offset = 8; offset < sizeof(context.authentication); offset += 32) {
        if (!nonzero(context.authentication + offset, 32))
            goto finished;
    }
    if (receive_frame_on(&context.channel, context.request, sizeof(context.request),
            parent, 0, locks, &length) != 0 || length < OFFLINE_HEADER_BYTES + 8
        || offline_frame(&context, length, 4, length - OFFLINE_HEADER_BYTES) != 0)
        goto finished;

    context.stage = 1;
    if (offline_cut(&context) != 0 || open_direct_device(&context.floor) != 0
        || offline_cut(&context) != 0
        || offline_status(&context, Esys_SetTimeout(context.floor.esys, 0)) != 0
        || offline_session(&context) != 0)
        goto result;
    erase(context.reply + OFFLINE_HEADER_BYTES, OFFLINE_BODY_BYTES);
    size_t reply_length = 0;
    uint8_t slot = context.header[13];
    context.stage = 2;
    int action;
    if (slot == 1 || slot == 2 || slot == 9 || slot == 10)
        action = length == OFFLINE_HEADER_BYTES + 8 ? offline_observe(&context, &reply_length) : -1;
    else if (slot == 3 || slot == 6)
        action = length == OFFLINE_HEADER_BYTES + 8 ? offline_create(&context, &reply_length) : -1;
    else if (slot == 4 || slot == 7)
        action = offline_persist(&context, length, &reply_length);
    else
        action = length == OFFLINE_HEADER_BYTES + 8 ? offline_define(&context, &reply_length) : -1;
    if (action == 0 && offline_cut(&context) == 0) {
        offline_reply(&context, 5, reply_length, 0);
        if (send_frame_on(&context.channel, context.reply, OFFLINE_HEADER_BYTES + reply_length) != 0
            || offline_terminal_ack(&context, parent, locks, &length) != 0)
            goto finished;
        status = EXIT_SUCCESS;
        goto finished;
    }
result:
    /* An actual original TSS2_RC/errno survives until it has been copied into
     * the negative reply. Sending it is not evidence that the action did not
     * happen; native Pending remains an uncertainty obligation. */
    offline_reply(&context, 5, 16,
        context.floor.failure_rc != 0 ? context.floor.failure_rc : UINT32_MAX);
    put_u32(context.reply + OFFLINE_HEADER_BYTES + 8,
        (uint32_t)context.floor.failure_errno);
    put_u32(context.reply + OFFLINE_HEADER_BYTES + 12, context.stage);
    if (send_frame_on(&context.channel, context.reply, OFFLINE_HEADER_BYTES + 16) == 0)
        (void)offline_terminal_ack(&context, parent, locks, &length);
finished:
    offline_close(&context);
    for (size_t index = 0; index < 2; ++index) {
        if (locks[index] >= 0)
            close(locks[index]);
    }
    close(4);
    close(5);
    return status;
}
