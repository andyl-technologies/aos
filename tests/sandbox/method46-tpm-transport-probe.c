/* SPDX-License-Identifier: Apache-2.0 */
/* Executes the production ESYS transport against a guest /dev/tpmrm0.
 * This fixture owns provisioning authority. It does not qualify the helper's
 * carrier, SELinux transition, daemon journals, or public Create admission. */
#include "nv_esys.c"
#include <stdio.h>

struct fixture {
    uint8_t auth[32];
    uint8_t salt_name[34];
    uint8_t checkpoint[32];
    uint8_t pending[32];
};

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "TPM transport fixture failed: %s\n", operation);
        exit(EXIT_FAILURE);
    }
}

static void load_fixture(const char *path, struct fixture *fixture)
{
    FILE *file = fopen(path, "rb");
    require(file != NULL, "open retained fixture");
    require(fread(fixture, sizeof(*fixture), 1, file) == 1,
        "read retained fixture");
    require(fgetc(file) == EOF && !ferror(file), "exact fixture length");
    require(fclose(file) == 0, "close retained fixture");
}

static void save_fixture(const char *path, const struct fixture *fixture)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    require(fd >= 0, "open fixture output");
    require(write(fd, fixture, sizeof(*fixture)) == (ssize_t)sizeof(*fixture),
        "write fixture output");
    require(fsync(fd) == 0 && close(fd) == 0, "persist fixture output");
}

static void provision(struct floor_context *context, unsigned role,
    struct fixture *fixture)
{
    ESYS_TR primary = ESYS_TR_NONE;
    ESYS_TR persistent = ESYS_TR_NONE;
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_PUBLIC template = offline_template();
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION pcrs = {0};
    TPM2B_AUTH auth = {.size = sizeof(fixture->auth)};
    TPM2B_NV_PUBLIC public = {0};
    TPM2B_NAME *name = NULL;

    /* Runtime never has these hierarchy privileges. Generate fresh fixture
     * secrets in the guest rather than placing credentials in the Nix store. */
    FILE *random = fopen("/dev/urandom", "rb");
    require(random != NULL, "open guest entropy");
    require(fread(fixture->auth, sizeof(fixture->auth), 1, random) == 1,
        "generate index credential");
    require(fclose(random) == 0, "close guest entropy");
    memcpy(auth.buffer, fixture->auth, sizeof(fixture->auth));

    require(Esys_CreatePrimary(context->esys, ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template,
        &outside, &pcrs, &primary, NULL, NULL, NULL, NULL) == TSS2_RC_SUCCESS,
        "create restricted salt primary");
    require(Esys_EvictControl(context->esys, ESYS_TR_RH_OWNER, primary,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        UINT32_C(0x8100a046) + role, &persistent) == TSS2_RC_SUCCESS,
        "persist endpoint salt key");
    require(Esys_TR_GetName(context->esys, persistent, &name) == TSS2_RC_SUCCESS
        && name != NULL && name->size == sizeof(fixture->salt_name),
        "retain provisioned salt Name");
    memcpy(fixture->salt_name, name->name, sizeof(fixture->salt_name));
    Esys_Free(name);
    require(Esys_FlushContext(context->esys, primary) == TSS2_RC_SUCCESS,
        "flush transient primary");
    require(Esys_TR_Close(context->esys, &persistent) == TSS2_RC_SUCCESS,
        "close persistent salt reference");

    public.nvPublic.nvIndex = UINT32_C(0x0180a046) + role;
    public.nvPublic.nameAlg = TPM2_ALG_SHA256;
    public.nvPublic.attributes = UINT32_C(0x00040044);
    public.nvPublic.dataSize = 32;
    require(Esys_NV_DefineSpace(context->esys, ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &auth, &public,
        &context->index) == TSS2_RC_SUCCESS, "define exact endpoint index");
    require(Esys_TR_SetAuth(context->esys, context->index, &auth) == TSS2_RC_SUCCESS,
        "set fixture index auth");
    TPM2B_MAX_NV_BUFFER seed = {.size = 32};
    memset(seed.buffer, (int)(role + 1), seed.size);
    require(Esys_NV_Extend(context->esys, context->index, context->index,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &seed) == TSS2_RC_SUCCESS,
        "initialize endpoint index");
    uint8_t input[64] = {0};
    memcpy(input + 32, seed.buffer, 32);
    require(EVP_Digest(input, sizeof(input), fixture->checkpoint, NULL,
        EVP_sha256(), NULL) == 1, "calculate initial checkpoint");
    erase(&auth, sizeof(auth));
}

static int authenticate(struct floor_context *context, unsigned role,
    const struct fixture *fixture)
{
    context->index_handle = UINT32_C(0x0180a046) + role;
    memcpy(context->salt_name, fixture->salt_name, sizeof(context->salt_name));
    if (Esys_TR_FromTPMPublic(context->esys, UINT32_C(0x8100a046) + role,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &context->salt)
            != TSS2_RC_SUCCESS || check_initial_salt(context) != 0)
        return -1;

    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB}};
    if (Esys_StartAuthSession(context->esys, context->salt, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
            &symmetric, TPM2_ALG_SHA256, &context->session) != TSS2_RC_SUCCESS
        || session_attributes(context, 0) != TSS2_RC_SUCCESS
        || check_salt(context, context->session) != 0
        || Esys_TR_FromTPMPublic(context->esys, context->index_handle,
            context->session, ESYS_TR_NONE, ESYS_TR_NONE, &context->index)
            != TSS2_RC_SUCCESS)
        return -1;

    TPM2B_AUTH auth = {.size = sizeof(fixture->auth)};
    memcpy(auth.buffer, fixture->auth, sizeof(fixture->auth));
    TSS2_RC status = Esys_TR_SetAuth(context->esys, context->index, &auth);
    erase(&auth, sizeof(auth));
    return status == TSS2_RC_SUCCESS ? 0 : -1;
}

int main(int argc, char **argv)
{
    require(argc == 4, "usage: probe operation endpoint state-file");
    require(strcmp(argv[2], "0") == 0 || strcmp(argv[2], "1") == 0,
        "fixed endpoint selection");
    unsigned role = (unsigned)(argv[2][0] - '0');
    struct fixture fixture = {0};
    struct floor_context context = {.salt = ESYS_TR_NONE,
        .index = ESYS_TR_NONE, .session = ESYS_TR_NONE};
    require(open_direct_device(&context) == 0, "production device TCTI");

    if (strcmp(argv[1], "provision") == 0) {
        require(access(argv[3], F_OK) != 0 && errno == ENOENT,
            "refuse fixture replacement");
        provision(&context, role, &fixture);
        save_fixture(argv[3], &fixture);
        close_context(&context);
        return EXIT_SUCCESS;
    }

    load_fixture(argv[3], &fixture);
    if (strcmp(argv[1], "wrong-pin") == 0) {
        fixture.salt_name[2] ^= 1;
        require(authenticate(&context, role, &fixture) != 0,
            "reject changed salt pin");
    } else {
        if (strcmp(argv[1], "wrong-auth") == 0)
            fixture.auth[0] ^= 1;
        require(authenticate(&context, role, &fixture) == 0,
            "authenticate pinned salt session");
        uint8_t observation[RESPONSE_BYTES] = {0};
        int result = read_observation(&context, observation);
        if (strcmp(argv[1], "wrong-auth") == 0) {
            require(result != 0, "reject foreign index credential");
        } else {
            require(result == 0, "production authenticated NV read");
            if (strcmp(argv[1], "advance") == 0) {
                require(memcmp(observation + 96, fixture.checkpoint, 32) == 0,
                    "exact predecessor before extend");
                require(!nonzero(fixture.pending, sizeof(fixture.pending)),
                    "no previous pending operation");
                memset(fixture.pending, 0x51, sizeof(fixture.pending));
                save_fixture(argv[3], &fixture);
                require(extend_index(&context, fixture.pending) == 0,
                    "production encrypted NV extend");
                /* Deliberately leave the checkpoint behind the TPM, as when
                 * a process loses its reply after the authenticated command. */
            } else if (strcmp(argv[1], "recover") == 0) {
                require(nonzero(fixture.pending, sizeof(fixture.pending)),
                    "retain exact pending input");
                uint8_t input[64];
                uint8_t expected[32];
                memcpy(input, fixture.checkpoint, 32);
                memcpy(input + 32, fixture.pending, 32);
                require(EVP_Digest(input, sizeof(input), expected, NULL,
                    EVP_sha256(), NULL) == 1, "calculate retained target");
                require(memcmp(observation + 96, expected, 32) == 0,
                    "exact target after lost reply");
                memcpy(fixture.checkpoint, expected, 32);
                memset(fixture.pending, 0, sizeof(fixture.pending));
                save_fixture(argv[3], &fixture);
            } else {
                require(strcmp(argv[1], "read") == 0, "known operation");
                require(memcmp(observation + 96, fixture.checkpoint, 32) == 0,
                    "reject rolled-back checkpoint");
            }
        }
    }

    close_context(&context);
    erase(&fixture, sizeof(fixture));
    return EXIT_SUCCESS;
}
