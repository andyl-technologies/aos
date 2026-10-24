/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Pinned tpm2-tss 4.2.0 regression for the production initial-salt check.
 * Including the helper with a renamed entry point keeps its actual private
 * validator under test without adding a runtime factory or a second validator.
 * The renamed entry point is never called: only the in-memory TCTI below is
 * supplied to ESYS. No device, session, provisioning or hierarchy command runs.
 */
#define _GNU_SOURCE
#define main unused_method46_helper_entry_point
#include "helper.c"
#undef main
#include "nv_esys.c"

#include <stdio.h>

#define RESPONSE_LIMIT 1024U
#define RESPONSE_COUNT 2U
#define SALT_HANDLE UINT32_C(0x8100a046)
#define REPEAT_COUNT 3U

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static void public_hello_fixture(uint8_t hello[HELLO_BYTES])
{
    memset(hello, 0, HELLO_BYTES);
    memcpy(hello, "AOSBTH02", 8);
    hello[9] = 2;
    memset(hello + 12, 7, 32);
    put_u32(hello + 44, UINT32_C(0x0180a046));
    put_u32(hello + 48, UINT32_C(0x8100a046));
    hello[53] = 11;
    memset(hello + 54, 8, 32);
}

static void public_hello_rejects_secrets_and_old_framing(void)
{
    uint8_t hello[HELLO_BYTES];
    public_hello_fixture(hello);
    REQUIRE(validate_hello(hello, &method46_profile) == 0);
    for (size_t offset = 86; offset < 120; ++offset) {
        hello[offset] = 1;
        REQUIRE(validate_hello(hello, &method46_profile) != 0);
        hello[offset] = 0;
    }
    memcpy(hello, "AOSBTH01", 8);
    hello[9] = 1;
    REQUIRE(validate_hello(hello, &method46_profile) != 0);
    public_hello_fixture(hello);
    put_u32(hello + 48, UINT32_C(0x8100a047));
    REQUIRE(validate_hello(hello, &method46_profile) != 0);
    public_hello_fixture(hello);
    memset(hello + 12, 0, 32);
    REQUIRE(validate_hello(hello, &method46_profile) != 0);

    /* The shared mechanics do not widen this fixed image's endpoint policy. */
    public_hello_fixture(hello);
    put_u32(hello + 44, UINT32_C(0x0180a055));
    put_u32(hello + 48, UINT32_C(0x8100a055));
    REQUIRE(validate_hello(hello, &method46_profile) != 0);
}

static void authentication_is_exact_nonce_role_and_nonzero_secret(void)
{
    uint8_t hello[HELLO_BYTES];
    uint8_t auth[AUTH_BYTES] = {0};
    public_hello_fixture(hello);
    memcpy(auth, "AOSBTA02", 8);
    auth[9] = 2;
    memcpy(auth + 12, hello + 12, 36);
    memset(auth + 48, 9, 32);
    REQUIRE(validate_auth(auth, hello) == 0);

    const size_t changed_offsets[] = {0, 7, 8, 9, 10, 11, 12, 43, 44, 47};
    for (size_t index = 0; index < sizeof(changed_offsets) / sizeof(changed_offsets[0]); ++index) {
        size_t offset = changed_offsets[index];
        auth[offset] ^= 1;
        REQUIRE(validate_auth(auth, hello) != 0);
        auth[offset] ^= 1;
    }
    memset(auth + 48, 0, 32);
    REQUIRE(validate_auth(auth, hello) != 0);
    erase(auth, sizeof(auth));
}

static void lock_shape_requires_empty_rdwr_and_distinct_identity(void)
{
    char paths[2][64] = {"/tmp/aos-tpm-lock-a-XXXXXX", "/tmp/aos-tpm-lock-b-XXXXXX"};
    int locks[2] = {mkstemp(paths[0]), mkstemp(paths[1])};
    uint8_t hello[HELLO_BYTES];
    public_hello_fixture(hello);
    for (size_t index = 0; index < 2; ++index) {
        struct stat observed;
        REQUIRE(locks[index] >= 3 && fstat(locks[index], &observed) == 0);
        REQUIRE(fchmod(locks[index], 0600) == 0);
        uint8_t *expected = hello + 120 + index * 20;
        for (size_t byte = 0; byte < 8; ++byte) {
            expected[7 - byte] = (uint8_t)((uint64_t)observed.st_dev >> (byte * 8));
            expected[15 - byte] = (uint8_t)((uint64_t)observed.st_ino >> (byte * 8));
        }
        put_u32(expected + 16, (uint32_t)observed.st_uid);
    }
    REQUIRE(validate_locks(hello, locks) == 0);
    REQUIRE(ftruncate(locks[0], 1) == 0);
    REQUIRE(validate_locks(hello, locks) != 0);
    REQUIRE(ftruncate(locks[0], 0) == 0);
    int read_only = open(paths[0], O_RDONLY | O_CLOEXEC);
    REQUIRE(read_only >= 3);
    int changed[2] = {read_only, locks[1]};
    REQUIRE(validate_locks(hello, changed) != 0);
    REQUIRE(close(read_only) == 0);
    changed[0] = locks[0];
    changed[1] = locks[0];
    REQUIRE(validate_locks(hello, changed) != 0);
    for (size_t index = 0; index < 2; ++index) {
        REQUIRE(close(locks[index]) == 0);
        REQUIRE(unlink(paths[index]) == 0);
    }
}

/* This test is not linked to Device-TCTI. An accidental production-open call
 * fails instead of opening a physical device; the real helper links normally. */
TSS2_RC Tss2_Tcti_Device_Init(TSS2_TCTI_CONTEXT *context, size_t *size, const char *config)
{
    (void)context;
    (void)size;
    (void)config;
    REQUIRE(false);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

struct response_fixture {
    uint8_t bytes[RESPONSE_LIMIT];
    size_t length;
};

struct mock_tcti {
    TSS2_TCTI_CONTEXT_COMMON_V1 common;
    struct response_fixture responses[RESPONSE_COUNT];
    size_t available;
    size_t transmits;
    size_t size_queries;
    size_t receives;
    bool pending;
};

struct salt_fixture {
    TPM2B_PUBLIC public;
    TPM2B_NAME name;
    TPM2B_NAME qualified;
};

static TSS2_RC mock_transmit(TSS2_TCTI_CONTEXT *opaque, size_t length,
    const uint8_t *command)
{
    struct mock_tcti *mock = (struct mock_tcti *)opaque;
    UINT16 tag = 0;
    UINT32 declared_length = 0;
    UINT32 code = 0;
    UINT32 handle = 0;
    size_t offset = 0;

    if (mock->pending || mock->transmits >= mock->available || length != 14U
        || command == NULL
        || Tss2_MU_UINT16_Unmarshal(command, length, &offset, &tag) != TSS2_RC_SUCCESS
        || Tss2_MU_UINT32_Unmarshal(command, length, &offset, &declared_length) != TSS2_RC_SUCCESS
        || Tss2_MU_UINT32_Unmarshal(command, length, &offset, &code) != TSS2_RC_SUCCESS
        || Tss2_MU_UINT32_Unmarshal(command, length, &offset, &handle) != TSS2_RC_SUCCESS
        || offset != length || tag != TPM2_ST_NO_SESSIONS
        || declared_length != length || code != TPM2_CC_ReadPublic
        || handle != SALT_HANDLE)
        return TSS2_TCTI_RC_BAD_VALUE;

    ++mock->transmits;
    mock->pending = true;
    return TSS2_RC_SUCCESS;
}

static TSS2_RC mock_receive(TSS2_TCTI_CONTEXT *opaque, size_t *length,
    uint8_t *response, int32_t timeout)
{
    struct mock_tcti *mock = (struct mock_tcti *)opaque;
    (void)timeout;
    if (!mock->pending || length == NULL || mock->transmits == 0U)
        return TSS2_TCTI_RC_BAD_SEQUENCE;
    const struct response_fixture *fixture = &mock->responses[mock->transmits - 1U];

    if (response == NULL) {
        *length = fixture->length;
        ++mock->size_queries;
        return TSS2_RC_SUCCESS;
    }
    if (*length < fixture->length) {
        *length = fixture->length;
        return TSS2_TCTI_RC_INSUFFICIENT_BUFFER;
    }

    memcpy(response, fixture->bytes, fixture->length);
    *length = fixture->length;
    ++mock->receives;
    mock->pending = false;
    return TSS2_RC_SUCCESS;
}

static struct mock_tcti mock_context(void)
{
    struct mock_tcti mock = {
        .common = {
            .magic = UINT64_C(0x414f535453533432),
            .version = 1,
            .transmit = mock_transmit,
            .receive = mock_receive,
        },
    };
    return mock;
}

static void compute_name(struct salt_fixture *fixture)
{
    uint8_t public_bytes[RESPONSE_LIMIT] = {0};
    uint8_t digest[32] = {0};
    size_t public_length = 0;
    size_t name_offset = 0;
    unsigned int digest_length = 0;
    REQUIRE(Tss2_MU_TPMT_PUBLIC_Marshal(&fixture->public.publicArea, public_bytes,
        sizeof(public_bytes), &public_length) == TSS2_RC_SUCCESS);
    REQUIRE(EVP_Digest(public_bytes, public_length, digest, &digest_length,
        EVP_sha256(), NULL) == 1 && digest_length == sizeof(digest));

    fixture->name.size = 34;
    REQUIRE(Tss2_MU_UINT16_Marshal(TPM2_ALG_SHA256, fixture->name.name,
        sizeof(fixture->name.name), &name_offset) == TSS2_RC_SUCCESS);
    memcpy(fixture->name.name + name_offset, digest, sizeof(digest));
    fixture->qualified = fixture->name;
    /* A distinct synthetic qualified-Name sentinel catches field confusion;
     * it is not a claim about any real hierarchy or parent chain. */
    fixture->qualified.name[2] ^= 0x40U;
}

static struct salt_fixture synthetic_salt(uint8_t marker)
{
    struct salt_fixture fixture = {
        .public = {
            .publicArea = {
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA256,
                .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                    | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT,
                .parameters = {
                    .rsaDetail = {
                        .symmetric = { .algorithm = TPM2_ALG_AES,
                            .keyBits = { .aes = 128 }, .mode = { .aes = TPM2_ALG_CFB } },
                        .scheme = { .scheme = TPM2_ALG_NULL },
                        .keyBits = 2048,
                        .exponent = 65537,
                    },
                },
                .unique = { .rsa = { .size = 256 } },
            },
        },
    };
    /* Synthetic public fields exercise codecs, not RSA salt encryption or a
     * provisioned key. Distinct markers produce distinct canonical Names. */
    memset(fixture.public.publicArea.unique.rsa.buffer, marker, 256);
    fixture.public.publicArea.unique.rsa.buffer[0] |= 0x80U;
    fixture.public.publicArea.unique.rsa.buffer[255] |= 1U;
    compute_name(&fixture);
    return fixture;
}

static struct response_fixture readpublic_response(const struct salt_fixture *fixture)
{
    struct response_fixture response = {0};
    size_t offset = 0;
    REQUIRE(Tss2_MU_UINT16_Marshal(TPM2_ST_NO_SESSIONS, response.bytes,
        sizeof(response.bytes), &offset) == TSS2_RC_SUCCESS);
    size_t size_offset = offset;
    REQUIRE(Tss2_MU_UINT32_Marshal(0, response.bytes,
        sizeof(response.bytes), &offset) == TSS2_RC_SUCCESS);
    REQUIRE(Tss2_MU_UINT32_Marshal(TPM2_RC_SUCCESS, response.bytes,
        sizeof(response.bytes), &offset) == TSS2_RC_SUCCESS);
    REQUIRE(Tss2_MU_TPM2B_PUBLIC_Marshal(&fixture->public, response.bytes,
        sizeof(response.bytes), &offset) == TSS2_RC_SUCCESS);
    REQUIRE(Tss2_MU_TPM2B_NAME_Marshal(&fixture->name, response.bytes,
        sizeof(response.bytes), &offset) == TSS2_RC_SUCCESS);
    REQUIRE(Tss2_MU_TPM2B_NAME_Marshal(&fixture->qualified, response.bytes,
        sizeof(response.bytes), &offset) == TSS2_RC_SUCCESS);
    REQUIRE(offset <= sizeof(response.bytes));
    response.length = offset;
    REQUIRE(Tss2_MU_UINT32_Marshal((UINT32)response.length, response.bytes,
        sizeof(response.bytes), &size_offset) == TSS2_RC_SUCCESS);
    return response;
}

static void require_public_equal(const TPM2B_PUBLIC *actual, const TPM2B_PUBLIC *expected)
{
    uint8_t actual_bytes[RESPONSE_LIMIT] = {0};
    uint8_t expected_bytes[RESPONSE_LIMIT] = {0};
    size_t actual_length = 0;
    size_t expected_length = 0;
    REQUIRE(Tss2_MU_TPM2B_PUBLIC_Marshal(actual, actual_bytes,
        sizeof(actual_bytes), &actual_length) == TSS2_RC_SUCCESS);
    REQUIRE(Tss2_MU_TPM2B_PUBLIC_Marshal(expected, expected_bytes,
        sizeof(expected_bytes), &expected_length) == TSS2_RC_SUCCESS);
    REQUIRE(actual_length == expected_length);
    REQUIRE(memcmp(actual_bytes, expected_bytes, actual_length) == 0);
}

static void require_name_equal(const TPM2B_NAME *actual, const TPM2B_NAME *expected)
{
    REQUIRE(actual->size == expected->size);
    REQUIRE(memcmp(actual->name, expected->name, expected->size) == 0);
}

static void initialize(struct mock_tcti *mock, struct floor_context *context,
    const TPM2B_NAME *pinned_name)
{
    REQUIRE(pinned_name->size == sizeof(context->salt_name));
    memcpy(context->salt_name, pinned_name->name, sizeof(context->salt_name));
    REQUIRE(Esys_Initialize(&context->esys, (TSS2_TCTI_CONTEXT *)mock, NULL)
        == TSS2_RC_SUCCESS);
    REQUIRE(Esys_SetTimeout(context->esys, 5000) == TSS2_RC_SUCCESS);
}

static TSS2_RC import_initial(struct floor_context *context)
{
    return Esys_TR_FromTPMPublic(context->esys, SALT_HANDLE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &context->salt);
}

static void require_initial_transport(const struct mock_tcti *mock)
{
    REQUIRE(mock->transmits == 1U);
    REQUIRE(mock->size_queries == 1U);
    REQUIRE(mock->receives == 1U);
    REQUIRE(!mock->pending);
}

static void require_completed_fixture(struct floor_context *context,
    const struct salt_fixture *fixture)
{
    TSS2_SYS_CONTEXT *sys = NULL;
    TPM2B_PUBLIC public = {0};
    TPM2B_NAME name = {0};
    TPM2B_NAME qualified = {0};
    REQUIRE(Esys_GetSysContext(context->esys, &sys) == TSS2_RC_SUCCESS);
    REQUIRE(Tss2_Sys_ReadPublic_Complete(sys, &public, &name, &qualified)
        == TSS2_RC_SUCCESS);
    require_public_equal(&public, &fixture->public);
    require_name_equal(&name, &fixture->name);
    require_name_equal(&qualified, &fixture->qualified);
}

static void repeated_complete_observes_initial_response_without_transport(void)
{
    struct salt_fixture first = synthetic_salt(0xa5);
    struct salt_fixture second = synthetic_salt(0xb5);
    struct mock_tcti mock = mock_context();
    mock.responses[0] = readpublic_response(&first);
    mock.responses[1] = readpublic_response(&second);
    mock.available = RESPONSE_COUNT;
    struct floor_context context = {0};
    initialize(&mock, &context, &first.name);

    REQUIRE(import_initial(&context) == TSS2_RC_SUCCESS);
    REQUIRE(check_initial_salt(&context) == 0);
    require_initial_transport(&mock);
    TPM2B_NAME *cached_name = NULL;
    REQUIRE(Esys_TR_GetName(context.esys, context.salt, &cached_name) == TSS2_RC_SUCCESS);
    require_name_equal(cached_name, &first.name);
    Esys_Free(cached_name);
    for (size_t repeat = 0; repeat < REPEAT_COUNT; ++repeat) {
        require_completed_fixture(&context, &first);
        REQUIRE(check_initial_salt(&context) == 0);
        require_initial_transport(&mock);
    }
    Esys_Finalize(&context.esys);
}

static void later_readpublic_is_a_different_observation(void)
{
    struct salt_fixture pinned = synthetic_salt(0xa5);
    struct salt_fixture other = synthetic_salt(0xb5);
    /* Both directions matter: a later good response cannot repair an initially
     * substituted cached RSA public, and a later bad response is not initial. */
    for (size_t direction = 0; direction < 2U; ++direction) {
        struct salt_fixture first = direction == 0U ? pinned : other;
        struct salt_fixture second = direction == 0U ? other : pinned;
        first.name = pinned.name;
        first.qualified = pinned.qualified;
        struct mock_tcti mock = mock_context();
        mock.responses[0] = readpublic_response(&first);
        mock.responses[1] = readpublic_response(&second);
        mock.available = RESPONSE_COUNT;
        struct floor_context context = {0};
        initialize(&mock, &context, &pinned.name);

        REQUIRE(import_initial(&context) == TSS2_RC_SUCCESS);
        REQUIRE((check_initial_salt(&context) == 0) == (direction == 0U));
        require_completed_fixture(&context, &first);
        require_initial_transport(&mock);

        TPM2B_PUBLIC *public = NULL;
        TPM2B_NAME *name = NULL;
        TPM2B_NAME *qualified = NULL;
        REQUIRE(Esys_ReadPublic(context.esys, context.salt, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, &public, &name, &qualified) == TSS2_RC_SUCCESS);
        require_public_equal(public, &second.public);
        require_name_equal(name, &second.name);
        require_name_equal(qualified, &second.qualified);
        Esys_Free(public);
        Esys_Free(name);
        Esys_Free(qualified);
        REQUIRE(mock.transmits == 2U && mock.size_queries == 2U && mock.receives == 2U);
        require_completed_fixture(&context, &second);
        REQUIRE((check_initial_salt(&context) == 0) == (direction != 0U));
        REQUIRE(mock.transmits == 2U && mock.size_queries == 2U && mock.receives == 2U);
        Esys_Finalize(&context.esys);
    }
}

static void require_initial_rejected(struct salt_fixture initial, const TPM2B_NAME *pin)
{
    struct mock_tcti mock = mock_context();
    mock.responses[0] = readpublic_response(&initial);
    mock.available = 1;
    struct floor_context context = {0};
    initialize(&mock, &context, pin);

    REQUIRE(import_initial(&context) == TSS2_RC_SUCCESS);
    REQUIRE(check_initial_salt(&context) != 0);
    require_completed_fixture(&context, &initial);
    require_initial_transport(&mock);
    Esys_Finalize(&context.esys);
}

static void substituted_public_with_asserted_pinned_name_is_rejected(void)
{
    struct salt_fixture pinned = synthetic_salt(0xa5);
    struct salt_fixture substituted = synthetic_salt(0xb5);
    substituted.name = pinned.name;
    substituted.qualified = pinned.qualified;
    require_initial_rejected(substituted, &pinned.name);
}

static void substituted_name_is_rejected(void)
{
    struct salt_fixture pinned = synthetic_salt(0xa5);
    struct salt_fixture substituted = synthetic_salt(0xb5);
    TPM2B_NAME original_pin = pinned.name;
    pinned.name = substituted.name;
    require_initial_rejected(pinned, &original_pin);
}

static void weak_or_signing_salt_shapes_are_rejected(void)
{
    for (size_t variant = 0; variant < 2U; ++variant) {
        struct salt_fixture fixture = synthetic_salt(0xa5);
        if (variant == 0U)
            fixture.public.publicArea.parameters.rsaDetail.keyBits = 1024;
        else
            fixture.public.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        compute_name(&fixture);
        require_initial_rejected(fixture, &fixture.name);
    }
}

static void malformed_initial_response_is_rejected(bool short_header)
{
    struct salt_fixture fixture = synthetic_salt(0xa5);
    struct mock_tcti mock = mock_context();
    mock.responses[0] = readpublic_response(&fixture);
    mock.available = 1;
    if (short_header)
        mock.responses[0].length = 9;
    else {
        /* Corrupt only the official TPM2B_PUBLIC size after the 10-byte header. */
        size_t public_size_offset = 10;
        REQUIRE(Tss2_MU_UINT16_Marshal(UINT16_MAX, mock.responses[0].bytes,
            sizeof(mock.responses[0].bytes), &public_size_offset) == TSS2_RC_SUCCESS);
    }
    struct floor_context context = {0};
    initialize(&mock, &context, &fixture.name);

    REQUIRE(import_initial(&context) != TSS2_RC_SUCCESS);
    REQUIRE(check_initial_salt(&context) != 0);
    REQUIRE(mock.transmits == 1U && mock.size_queries == 1U);
    REQUIRE(mock.receives == (short_header ? 0U : 1U));
    Esys_Finalize(&context.esys);
}

static void truncated_initial_header_is_rejected(void)
{
    malformed_initial_response_is_rejected(true);
}

static void oversized_initial_public_is_rejected(void)
{
    malformed_initial_response_is_rejected(false);
}

int main(void)
{
    const struct {
        const char *name;
        void (*run)(void);
    } cases[] = {
        {"public HELLO excludes auth and rejects old framing", public_hello_rejects_secrets_and_old_framing},
        {"separate auth binds nonce, role and nonzero secret", authentication_is_exact_nonce_role_and_nonzero_secret},
        {"lock custody is empty RDWR and nonaliasing", lock_shape_requires_empty_rdwr_and_distinct_identity},
        {
            "repeated Complete preserves exact initial cached response",
            repeated_complete_observes_initial_response_without_transport,
        },
        {
            "later ReadPublic is not the initial observation",
            later_readpublic_is_a_different_observation,
        },
        {
            "substituted RSA public with pinned asserted Name rejected",
            substituted_public_with_asserted_pinned_name_is_rejected,
        },
        {
            "substituted Name rejected",
            substituted_name_is_rejected,
        },
        {
            "weak/signing RSA shapes rejected",
            weak_or_signing_salt_shapes_are_rejected,
        },
        {
            "truncated initial header rejected",
            truncated_initial_header_is_rejected,
        },
        {
            "oversized initial public rejected",
            oversized_initial_public_is_rejected,
        },
    };
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        cases[index].run();
        REQUIRE(printf("passed: %s\n", cases[index].name) > 0);
    }
    REQUIRE(puts("tpm2-tss 4.2.0 cache and private-custody regression: 10 tests passed") >= 0);
    REQUIRE(fflush(stdout) == 0);
    return EXIT_SUCCESS;
}
