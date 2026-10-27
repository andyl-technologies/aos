/* SPDX-License-Identifier: Apache-2.0 */
/* Host-only setup for the two installed initial-floor purposes. This fixture
 * defines unwritten indices; only the production initial owner may Extend them.
 * The explicit swtpm TCTI is never compiled into a production helper. */
#include "nv_esys.c"
#include <stdio.h>
#include <sys/random.h>
#include <tss2_tcti_swtpm.h>

struct preparation {
    uint8_t auth[32];
    uint8_t salt_name[34];
    uint8_t checkpoint[32];
    uint8_t pending[32];
};

_Static_assert(sizeof(struct preparation) == 130,
    "external setup must match the transport fixture's retained record");

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "external METHOD46 preparation failed: %s\n", operation);
        exit(EXIT_FAILURE);
    }
}

static void require_vacant(ESYS_CONTEXT *esys, uint32_t handle)
{
    TPMS_CAPABILITY_DATA *capability = NULL;
    TPMI_YES_NO more = TPM2_NO;
    require(Esys_GetCapability(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        TPM2_CAP_HANDLES, handle, 1, &more, &capability) == TSS2_RC_SUCCESS,
        "read occupied handles before mutation");
    require(capability != NULL && capability->capability == TPM2_CAP_HANDLES
        && (capability->data.handles.count == 0
            || capability->data.handles.handle[0] != handle),
        "refuse an occupied fixed handle");
    Esys_Free(capability);
}

static void random_auth(uint8_t auth[32])
{
    size_t offset = 0;
    while (offset < 32) {
        ssize_t count = getrandom(auth + offset, 32 - offset, 0);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "generate external index authentication");
        offset += (size_t)count;
    }
}

static void prepare_endpoint(struct floor_context *context, unsigned role,
    int directory)
{
    struct preparation prepared = {0};
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_PUBLIC template = offline_template();
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION pcrs = {0};
    ESYS_TR primary = ESYS_TR_NONE;
    ESYS_TR persistent = ESYS_TR_NONE;
    TPM2B_NAME *salt_name = NULL;
    TPM2B_AUTH auth = {.size = sizeof(prepared.auth)};
    TPM2B_NV_PUBLIC public = {0};
    TPM2B_NV_PUBLIC *observed = NULL;
    TPM2B_NAME *index_name = NULL;

    random_auth(prepared.auth);
    memcpy(auth.buffer, prepared.auth, sizeof(prepared.auth));

    require(Esys_CreatePrimary(context->esys, ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template,
        &outside, &pcrs, &primary, NULL, NULL, NULL, NULL) == TSS2_RC_SUCCESS,
        "create production-template salt primary");
    require(Esys_EvictControl(context->esys, ESYS_TR_RH_OWNER, primary,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        UINT32_C(0x8100a046) + role, &persistent) == TSS2_RC_SUCCESS,
        "persist fixed salt key");
    require(Esys_TR_GetName(context->esys, persistent, &salt_name)
        == TSS2_RC_SUCCESS && salt_name != NULL && salt_name->size == 34,
        "retain exact salt Name");
    memcpy(prepared.salt_name, salt_name->name, sizeof(prepared.salt_name));
    Esys_Free(salt_name);
    require(Esys_FlushContext(context->esys, primary) == TSS2_RC_SUCCESS,
        "flush transient primary");
    require(Esys_TR_Close(context->esys, &persistent) == TSS2_RC_SUCCESS,
        "close persistent salt reference");

    public.nvPublic.nvIndex = UINT32_C(0x0180a046) + role;
    public.nvPublic.nameAlg = TPM2_ALG_SHA256;
    public.nvPublic.attributes = DEFINED_ATTRIBUTES;
    public.nvPublic.dataSize = 32;
    require(Esys_NV_DefineSpace(context->esys, ESYS_TR_RH_OWNER,
        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &auth, &public,
        &context->index) == TSS2_RC_SUCCESS, "define unwritten fixed index");
    erase(&auth, sizeof(auth));

    require(Esys_NV_ReadPublic(context->esys, context->index, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &observed, &index_name) == TSS2_RC_SUCCESS,
        "observe newly defined index");
    require(observed != NULL && index_name != NULL && index_name->size == 34
        && observed->nvPublic.nvIndex == public.nvPublic.nvIndex
        && observed->nvPublic.nameAlg == TPM2_ALG_SHA256
        && observed->nvPublic.attributes == DEFINED_ATTRIBUTES
        && observed->nvPublic.authPolicy.size == 0
        && observed->nvPublic.dataSize == 32,
        "require exact NVUnwritten public area");
    Esys_Free(observed);
    Esys_Free(index_name);

    const char *name = role == 0 ? "endpoint-0" : "endpoint-1";
    int file = openat(directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    require(file >= 0, "create external credential record without replacement");
    require(write(file, &prepared, sizeof(prepared)) == (ssize_t)sizeof(prepared),
        "write complete external credential record");
    require(fsync(file) == 0 && close(file) == 0 && fsync(directory) == 0,
        "persist external credential record");
    erase(&prepared, sizeof(prepared));
    require(Esys_TR_Close(context->esys, &context->index) == TSS2_RC_SUCCESS,
        "close prepared index reference");
}

int main(int argc, char **argv)
{
    require(argc == 3, "expected explicit swtpm socket and fresh output directory");
    require(mkdir(argv[2], 0700) == 0, "refuse existing output directory");
    int directory = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(directory >= 0, "open external output directory");

    char *configuration = NULL;
    require(asprintf(&configuration, "path=%s", argv[1]) >= 0,
        "form explicit software TPM endpoint");
    struct floor_context context = {.salt = ESYS_TR_NONE,
        .index = ESYS_TR_NONE, .session = ESYS_TR_NONE};
    size_t size = 0;
    require(Tss2_Tcti_Swtpm_Init(NULL, &size, configuration) == TSS2_RC_SUCCESS,
        "measure external swtpm TCTI");
    context.device = calloc(1, size);
    require(context.device != NULL, "allocate external TCTI");
    require(Tss2_Tcti_Swtpm_Init(context.device, &size, configuration)
        == TSS2_RC_SUCCESS, "open external swtpm TCTI");
    context.device_ready = true;
    free(configuration);
    require(Esys_Initialize(&context.esys, context.device, NULL) == TSS2_RC_SUCCESS,
        "initialize external ESYS");

    /* Check all four slots before creating either purpose. Existing state is
     * never evicted, cleared, adopted or extended by this setup operation. */
    for (unsigned role = 0; role < 2; ++role) {
        require_vacant(context.esys, UINT32_C(0x0180a046) + role);
        require_vacant(context.esys, UINT32_C(0x8100a046) + role);
    }
    for (unsigned role = 0; role < 2; ++role)
        prepare_endpoint(&context, role, directory);

    close_context(&context);
    require(close(directory) == 0, "close external output directory");
    puts("fixed METHOD46 external preparation PASS; both indices remain unwritten");
    return EXIT_SUCCESS;
}
