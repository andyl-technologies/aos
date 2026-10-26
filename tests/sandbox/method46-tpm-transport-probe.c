/* SPDX-License-Identifier: Apache-2.0 */
/* Executes the production ESYS transport against a guest /dev/tpmrm0.
 * This fixture owns provisioning authority. It does not qualify the helper's
 * carrier, SELinux transition, daemon journals, or public Create admission. */
#include "nv_esys.c"
#include <signal.h>
#include <stdio.h>

/* These are test-only fixed endpoint profiles, with no production Source or
 * approval authority. The shared reader still selects its ordinary/initial
 * behavior from the same closed build-time profile used by the real runner. */
static const struct aos_nv_custody_role fixture_roles[] = {
    { UINT32_C(0x0180a046), UINT32_C(0x8100a046), NULL },
    { UINT32_C(0x0180a047), UINT32_C(0x8100a047), NULL },
};
static const struct aos_nv_custody_profile ordinary_fixture_profile = {
    .roles = fixture_roles,
    .role_count = 2,
};
static const struct aos_nv_custody_profile initial_fixture_profiles[] = {
    { .roles = &fixture_roles[0], .role_count = 1,
      .lock_owner = AOS_NV_LOCK_OWNER_INITIAL_CONTROLLER },
    { .roles = &fixture_roles[1], .role_count = 1,
      .lock_owner = AOS_NV_LOCK_OWNER_INITIAL_STORAGE },
};

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
    char *next = NULL;
    char *parent = strdup(path);
    require(parent != NULL && asprintf(&next, "%s.next", path) >= 0,
        "allocate fixture publication paths");
    char *separator = strrchr(parent, '/');
    if (separator == parent)
        separator[1] = '\0';
    else if (separator != NULL)
        *separator = '\0';
    else {
        free(parent);
        parent = strdup(".");
        require(parent != NULL, "allocate fixture parent");
    }

    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(directory >= 0, "open fixture publication directory");
    /* A power cut must leave the complete predecessor or successor, including
     * its index credential. A leftover partial publication fences this fixture. */
    int fd = open(next, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    require(fd >= 0, "open fixture output");
    require(write(fd, fixture, sizeof(*fixture)) == (ssize_t)sizeof(*fixture),
        "write fixture output");
    require(fsync(fd) == 0 && close(fd) == 0, "persist fixture output");
    require(rename(next, path) == 0 && fsync(directory) == 0,
        "publish durable fixture output");
    require(close(directory) == 0, "close fixture publication directory");
    free(parent);
    free(next);
}

static void initialize_index(struct floor_context *context,
    struct fixture *fixture, const uint8_t input[32])
{
    TPM2B_MAX_NV_BUFFER seed = {.size = 32};
    memcpy(seed.buffer, input, seed.size);
    require(Esys_NV_Extend(context->esys, context->index, context->index,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &seed) == TSS2_RC_SUCCESS,
        "initialize endpoint index");

    uint8_t digest_input[64] = {0};
    memcpy(digest_input + 32, input, 32);
    require(EVP_Digest(digest_input, sizeof(digest_input), fixture->checkpoint,
        NULL, EVP_sha256(), NULL) == 1, "calculate initial checkpoint");
}

static void provision(struct floor_context *context, unsigned role,
    struct fixture *fixture, int initialize)
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

    /* The negative-auth matrix deliberately exceeds the manufacturer's default
     * allowance. Only this external fixture holds lockout hierarchy authority;
     * production helpers neither change these parameters nor reset lockout. */
    require(Esys_DictionaryAttackParameters(context->esys, ESYS_TR_RH_LOCKOUT,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, 32, 1000, 1000)
        == TSS2_RC_SUCCESS, "set bounded test dictionary-attack allowance");

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
    if (initialize) {
        uint8_t seed[32];
        memset(seed, (int)(role + 1), sizeof(seed));
        initialize_index(context, fixture, seed);
    }
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
        || session_attributes(context, TPMA_SESSION_ENCRYPT) != TSS2_RC_SUCCESS
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

/* Test-only initial intent recovery. Its durable preimage is not an approved
 * journal cut or funding source; the production provisioner must supply both. */
static void recover_initial(struct floor_context *context, unsigned role,
    const char *path, struct fixture *fixture)
{
    require(!nonzero(fixture->checkpoint, sizeof(fixture->checkpoint))
        && nonzero(fixture->pending, sizeof(fixture->pending)),
        "one retained initial intent without a checkpoint");
    require(authenticate(context, role, fixture) == 0,
        "authenticate initial recovery salt and index");

    uint8_t before[RESPONSE_BYTES] = {0};
    require(read_observation(context, before, &initial_fixture_profiles[role]) == 0,
        "production authenticated unwritten or written initial observation");
    int written = get_u32(before + 88) == WRITTEN_ATTRIBUTES;

    uint8_t input[64] = {0};
    uint8_t expected[32];
    memcpy(input + 32, fixture->pending, sizeof(fixture->pending));
    require(EVP_Digest(input, sizeof(input), expected, NULL,
        EVP_sha256(), NULL) == 1, "calculate retained initial target");
    if (!written)
        require(extend_index(context, fixture->pending) == 0,
            "production encrypted recovered initial extend");

    uint8_t observation[RESPONSE_BYTES] = {0};
    require(read_observation(context, observation, &ordinary_fixture_profile) == 0
        && memcmp(observation + 96, expected, sizeof(expected)) == 0,
        "authenticate exact initial recovery target");
    memcpy(fixture->checkpoint, expected, sizeof(expected));
    memset(fixture->pending, 0, sizeof(fixture->pending));
    save_fixture(path, fixture);
}

int main(int argc, char **argv)
{
    int resumable = argc > 1 && (strcmp(argv[1], "initialize-resumable") == 0
        || strcmp(argv[1], "initialize-resumable-before") == 0
        || strcmp(argv[1], "initialize-resumable-after") == 0);
    int initializing = argc > 1 && (strcmp(argv[1], "initialize") == 0
        || strcmp(argv[1], "initialize-paused") == 0 || resumable);
    require(argc == 4 || (argc == 5 && initializing),
        "usage: probe operation endpoint state-file [initial-cut-input]");
    require(strcmp(argv[2], "0") == 0 || strcmp(argv[2], "1") == 0,
        "fixed endpoint selection");
    unsigned role = (unsigned)(argv[2][0] - '0');
    struct fixture fixture = {0};
    struct floor_context context = {.salt = ESYS_TR_NONE,
        .index = ESYS_TR_NONE, .session = ESYS_TR_NONE};
    require(open_direct_device(&context) == 0, "production device TCTI");

    if (strcmp(argv[1], "provision") == 0 || strcmp(argv[1], "prepare") == 0) {
        require(access(argv[3], F_OK) != 0 && errno == ENOENT,
            "refuse fixture replacement");
        provision(&context, role, &fixture, strcmp(argv[1], "provision") == 0);
        save_fixture(argv[3], &fixture);
        close_context(&context);
        return EXIT_SUCCESS;
    }

    load_fixture(argv[3], &fixture);
    if (strcmp(argv[1], "recover-initial") == 0) {
        recover_initial(&context, role, argv[3], &fixture);
        close_context(&context);
        erase(&fixture, sizeof(fixture));
        return EXIT_SUCCESS;
    }

    if (strcmp(argv[1], "initial-wrong-auth") == 0) {
        fixture.auth[0] ^= 1;
        require(authenticate(&context, role, &fixture) == 0,
            "salted public session does not authenticate index auth");
        uint8_t before[RESPONSE_BYTES] = {0};
        require(read_observation(&context, before, &initial_fixture_profiles[role]) == 0
            && get_u32(before + 88) == DEFINED_ATTRIBUTES,
            "unwritten public observation is not index authorization");
        uint8_t input[32];
        memset(input, 0x61, sizeof(input));
        require(extend_index(&context, input) != 0,
            "first encrypted Extend rejects foreign index auth");
        close_context(&context);
        erase(&fixture, sizeof(fixture));
        return EXIT_SUCCESS;
    }

    if (strcmp(argv[1], "observe-initial") == 0
        || strcmp(argv[1], "observe-initial-crossed") == 0) {
        require(authenticate(&context, role, &fixture) == 0,
            "authenticate fixed initial observation session");
        uint8_t observation[RESPONSE_BYTES];
        memset(observation, 0xa5, sizeof(observation));
        unsigned selected = strcmp(argv[1], "observe-initial-crossed") == 0 ? 1U - role : role;
        require(read_observation(&context, observation, &initial_fixture_profiles[selected]) == 0,
            "production initial public/value observation");
        printf("%08x ", get_u32(observation + 88));
        for (size_t byte = 52; byte < 86; ++byte)
            printf("%02x", observation[byte]);
        putchar(' ');
        for (size_t byte = 96; byte < 128; ++byte)
            printf("%02x", observation[byte]);
        putchar('\n');
        close_context(&context);
        erase(&fixture, sizeof(fixture));
        return EXIT_SUCCESS;
    }

    if (initializing) {
        require(argc == 5, "initial cut input is required");
        require(!nonzero(fixture.checkpoint, sizeof(fixture.checkpoint))
            && !nonzero(fixture.pending, sizeof(fixture.pending)),
            "refuse initialized fixture");
        require(authenticate(&context, role, &fixture) == 0,
            "authenticate prepared salt and index");

        uint8_t before[RESPONSE_BYTES] = {0};
        require(read_observation(&context, before, &initial_fixture_profiles[role]) == 0
            && get_u32(before + 88) == DEFINED_ATTRIBUTES
            && !nonzero(before + 96, 32),
            "production authenticated unwritten initial observation");

        /* Installed-hook callers must derive this preimage with the canonical
         * Rust journal codec after learning the provisioned salt Name. This
         * transport fixture never reconstructs or chooses a runtime cut. */
        uint8_t seed[32];
        FILE *input = fopen(argv[4], "rb");
        require(input != NULL && fread(seed, sizeof(seed), 1, input) == 1
            && fgetc(input) == EOF && !ferror(input), "exact initial cut input");
        require(fclose(input) == 0 && nonzero(seed, sizeof(seed)),
            "nonzero initial cut input");
        if (resumable) {
            memcpy(fixture.pending, seed, sizeof(seed));
            save_fixture(argv[3], &fixture);
            if (strcmp(argv[1], "initialize-resumable-before") == 0)
                require(raise(SIGSTOP) == 0, "pause durable initial intent");
        }
        /* Use the production salted HMAC/encrypted Extend, not the external
         * provisioner's password-authorized command. The first write changes
         * the NV Name, so authenticate its WRITTEN public area and value before
         * publishing the fixture checkpoint. This remains transport evidence;
         * the installed producer must retain its actual paid journal cut. */
        require(extend_index(&context, seed) == 0,
            "production encrypted initial NV extend");
        uint8_t digest_input[64] = {0};
        memcpy(digest_input + 32, seed, sizeof(seed));
        require(EVP_Digest(digest_input, sizeof(digest_input), fixture.checkpoint,
            NULL, EVP_sha256(), NULL) == 1, "calculate initial checkpoint");
        uint8_t observation[RESPONSE_BYTES] = {0};
        require(read_observation(&context, observation, &ordinary_fixture_profile) == 0
            && memcmp(observation + 52, before + 52, 34) != 0
            && memcmp(observation + 96, fixture.checkpoint, 32) == 0,
            "authenticate changed written Name and exact initial value");
        /* Cut power after authenticated physical success, before publishing
         * a checkpoint. Cold recovery needs the separately retained intent;
         * a fresh initializer must refuse the now-written index. */
        if (strcmp(argv[1], "initialize-paused") == 0
            || strcmp(argv[1], "initialize-resumable-after") == 0)
            require(raise(SIGSTOP) == 0, "pause uncheckpointed initial extend");
        memset(fixture.pending, 0, sizeof(fixture.pending));
        save_fixture(argv[3], &fixture);
        close_context(&context);
        erase(&fixture, sizeof(fixture));
        return EXIT_SUCCESS;
    }

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
        int result = read_observation(&context, observation, &ordinary_fixture_profile);
        if (strcmp(argv[1], "wrong-auth") == 0) {
            require(result != 0, "reject foreign index credential");
        } else {
            require(result == 0, "production authenticated NV read");
            if (strcmp(argv[1], "advance") == 0
                || strcmp(argv[1], "advance-paused") == 0) {
                require(memcmp(observation + 96, fixture.checkpoint, 32) == 0,
                    "exact predecessor before extend");
                require(!nonzero(fixture.pending, sizeof(fixture.pending)),
                    "no previous pending operation");
                memset(fixture.pending, 0x51, sizeof(fixture.pending));
                save_fixture(argv[3], &fixture);
                /* The VM harness can suspend the independent TPM after this
                 * durable preparation, then resume this actual ESYS caller
                 * before cutting power to both processes. */
                if (strcmp(argv[1], "advance-paused") == 0)
                    require(raise(SIGSTOP) == 0, "pause prepared extend");
                require(extend_index(&context, fixture.pending) == 0,
                    "production encrypted NV extend");
                /* Deliberately leave the checkpoint behind the TPM, as when
                 * a process loses its reply after the authenticated command.
                 * Skip application cleanup so kernel RM teardown, rather
                 * than close_context, retires this process's device session. */
                _exit(77);
            } else if (strcmp(argv[1], "recover") == 0) {
                require(nonzero(fixture.checkpoint, sizeof(fixture.checkpoint))
                    && nonzero(fixture.pending, sizeof(fixture.pending)),
                    "retain exact successor checkpoint and pending input");
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
            } else if (strcmp(argv[1], "observe") == 0) {
                /* Public comparison DATA only: neither replace the retained
                 * checkpoint nor make this observation a recovery receipt. */
                for (size_t byte = 96; byte < 128; ++byte)
                    printf("%02x", observation[byte]);
                putchar('\n');
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
