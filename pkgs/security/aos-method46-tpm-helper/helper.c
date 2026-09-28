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
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <tss2_esys.h>
#include <tss2_mu.h>
#include <tss2_tcti_device.h>

#define HELLO_BYTES 160U
#define LOCK_ACK_BYTES 48U
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
};

static void erase(void *pointer, size_t length)
{
    volatile uint8_t *bytes = pointer;
    while (length-- != 0U)
        *bytes++ = 0;
}

static int wait_channel(short events)
{
    struct pollfd descriptor = { .fd = STDIN_FILENO, .events = events };
    for (;;) {
        int ready = poll(&descriptor, 1, -1);
        if (ready < 0 && errno == EINTR)
            continue;
        return ready > 0 && (descriptor.revents & events) != 0 ? 0 : -1;
    }
}

static int receive_frame(uint8_t *bytes, size_t length, pid_t parent,
    size_t expected_locks, int locks[2])
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
        if (wait_channel(POLLIN) != 0)
            return -1;
        message.msg_controllen = sizeof(control.bytes);
        message.msg_flags = 0;
        count = recvmsg(STDIN_FILENO, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        break;
    }
    size_t rights_count = 0;
    size_t credential_count = 0;
    size_t pidfd_count = 0;
    int valid = count == (ssize_t)length
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
    return valid && rights_count == expected_locks && credential_count == 1U
        && pidfd_count == 1U && getppid() == parent ? 0 : -1;
}

static int send_frame(const uint8_t *bytes, size_t length)
{
    for (;;) {
        if (wait_channel(POLLOUT) != 0)
            return -1;
        ssize_t count = send(STDIN_FILENO, bytes, length, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        return count == (ssize_t)length ? 0 : -1;
    }
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
            && memcmp(digest, context->salt_name + 2, sizeof(digest)) == 0;
    }
    return valid ? 0 : -1;
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

static int open_context(struct floor_context *context, const uint8_t hello[HELLO_BYTES])
{
    uint32_t index = get_u32(hello + 44);
    uint32_t salt = get_u32(hello + 48);
    if (!((index == UINT32_C(0x0180a046) && salt == UINT32_C(0x8100a046))
        || (index == UINT32_C(0x0180a047) && salt == UINT32_C(0x8100a047))))
        return -1;
    if (memcmp(hello, "AOSBTH01", 8) != 0 || hello[8] != 0 || hello[9] != 1
        || hello[10] != 0 || hello[11] != 0 || hello[118] != 0 || hello[119] != 0
        || !nonzero(hello + 12, 32) || hello[52] != 0 || hello[53] != 11
        || !nonzero(hello + 54, 32) || !nonzero(hello + 86, 32))
        return -1;
    memcpy(context->salt_name, hello + 52, sizeof(context->salt_name));
    context->index_handle = index;
    if (lstat(FIXED_DEVICE, &context->device_identity) != 0
        || same_device(context) != 0)
        return -1;

    size_t size = 0;
    if (Tss2_Tcti_Device_Init(NULL, &size, FIXED_DEVICE) != TSS2_RC_SUCCESS
        || size == 0 || size > 65536U)
        return -1;
    context->device = calloc(1, size);
    if (context->device == NULL
        || Tss2_Tcti_Device_Init(context->device, &size, FIXED_DEVICE) != TSS2_RC_SUCCESS)
        return -1;
    context->device_ready = true;
    if (same_device(context) != 0
        || Esys_Initialize(&context->esys, context->device, NULL) != TSS2_RC_SUCCESS
        || Esys_SetTimeout(context->esys, 5000) != TSS2_RC_SUCCESS)
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
    memcpy(auth.buffer, hello + 86, 32);
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

int main(int argc, char **argv)
{
    (void)argv;
    struct floor_context context = {
        .salt = ESYS_TR_NONE,
        .index = ESYS_TR_NONE,
        .session = ESYS_TR_NONE,
    };
    uint8_t hello[HELLO_BYTES] = {0};
    uint8_t nonce[32] = {0};
    uint64_t sequence = 1;
    int status = EXIT_FAILURE;
    int locks[2] = {-1, -1};
    pid_t parent = getppid();
    if (argc != 1 || parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0
        || getppid() != parent || close_range(3, ~0U, 0) != 0
        || receive_frame(hello, sizeof(hello), parent, 2U, locks) != 0
        || validate_locks(hello, locks) != 0)
        goto finished;
    memcpy(nonce, hello + 12, sizeof(nonce));
    /* The parent checks the fixed executed image before sending credentials.
     * No later exec or fork occurs; custody is pidfd + the private channel. */
    uint8_t acknowledgment[LOCK_ACK_BYTES] = {0};
    memcpy(acknowledgment, "AOSBTK01", 8);
    acknowledgment[9] = 1;
    memcpy(acknowledgment + 12, nonce, sizeof(nonce));
    acknowledgment[45] = 2;
    if (prctl(PR_SET_DUMPABLE, 0) != 0
        || send_frame(acknowledgment, sizeof(acknowledgment)) != 0
        || open_context(&context, hello) != 0)
        goto finished;
    erase(hello, sizeof(hello));

    for (;;) {
        uint8_t request[REQUEST_BYTES] = {0};
        uint8_t reply[RESPONSE_BYTES] = {0};
        if (receive_frame(request, sizeof(request), parent, 0U, locks) != 0)
            break;
        uint8_t operation = request[10];
        if (memcmp(request, "AOSBTQ01", 8) != 0 || request[8] != 0 || request[9] != 1
            || request[11] != 0 || memcmp(request + 12, nonce, sizeof(nonce)) != 0
            || get_u64(request + 44) != sequence || sequence == UINT64_MAX
            || (operation != 1 && operation != 2)
            || (operation == 1 && nonzero(request + 52, 32))
            || (operation == 2 && !nonzero(request + 52, 32)))
            break;
        if (operation == 2 && extend_index(&context, request + 52) != 0)
            break;
        memcpy(reply, "AOSBTR01", 8);
        reply[9] = 1;
        reply[10] = operation;
        memcpy(reply + 12, nonce, sizeof(nonce));
        memcpy(reply + 44, request + 44, 8);
        if (read_observation(&context, reply) != 0
            || send_frame(reply, sizeof(reply)) != 0)
            break;
        ++sequence;
    }
finished:
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
