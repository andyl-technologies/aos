/* SPDX-License-Identifier: Apache-2.0 */
/* Compiles the actual selected entry and shared private lock validator. No
 * production entry or TPM operation is called. Device-TCTI is a failing stub. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define main unused_initial_method46_entry
#include "initial_method46.c"
#undef main
#include "nv_esys.c"

#include <stdio.h>
#include <sys/file.h>

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

TSS2_RC Tss2_Tcti_Device_Init(TSS2_TCTI_CONTEXT *context, size_t *size, const char *config)
{
    (void)context;
    (void)size;
    (void)config;
    REQUIRE(false);
    return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static void hello_for_profile(uint8_t hello[HELLO_BYTES])
{
    memset(hello, 0, HELLO_BYTES);
    memcpy(hello, "AOSBTH02", 8);
    hello[9] = 2;
    memset(hello + 12, 7, 32);
    put_u32(hello + 44, initial_role.index);
    put_u32(hello + 48, initial_role.salt);
    hello[53] = 11;
    memset(hello + 54, 8, 32);
}

static void fixed_policy_cases(void)
{
    uint8_t hello[HELLO_BYTES];
    hello_for_profile(hello);
    REQUIRE(validate_hello(hello, &initial_profile) == 0);
    REQUIRE(initial_profile_matches(&initial_profile));

    uint32_t opposite = initial_role.index == UINT32_C(0x0180a046)
        ? UINT32_C(0x0180a047) : UINT32_C(0x0180a046);
    put_u32(hello + 44, opposite);
    put_u32(hello + 48, opposite + UINT32_C(0x7f800000));
    REQUIRE(validate_hello(hello, &initial_profile) != 0);

    /* These UID scalars exercise only the comparison rule. The VM cases below
     * use actual fchown, geteuid, fstat and fcntl through validate_locks. */
    struct aos_nv_custody_profile normal = initial_profile;
    normal.lock_owner = AOS_NV_LOCK_OWNER_SELF;
    REQUIRE(!initial_profile_matches(&normal));
    REQUIRE(!initial_profile_matches(NULL));
    const uint32_t identities[] = {0, 1000, 1001, UINT32_MAX};
    for (size_t owner = 0; owner < 4; ++owner) {
        for (size_t helper = 0; helper < 4; ++helper) {
            REQUIRE(lock_owner_matches(&normal, identities[owner], identities[helper])
                == (identities[owner] == identities[helper]));
            int initial_expected = identities[helper] == 0
                && (initial_profile.lock_owner == AOS_NV_LOCK_OWNER_INITIAL_CONTROLLER
                    ? identities[owner] != 0 : identities[owner] == 0);
            REQUIRE(lock_owner_matches(&initial_profile, identities[owner], identities[helper])
                == initial_expected);
        }
    }
    struct aos_nv_custody_profile changed = initial_profile;
    changed.lock_owner = (enum aos_nv_lock_owner_policy)99;
    REQUIRE(!lock_owner_matches(&changed, 1000, 0));
    REQUIRE(!initial_profile_matches(&changed));
    changed = initial_profile;
    changed.role_count = 2;
    REQUIRE(!lock_owner_matches(&changed, 1000, 0));
    REQUIRE(!initial_profile_matches(&changed));
    changed = initial_profile;
    changed.roles = NULL;
    REQUIRE(!lock_owner_matches(&changed, 1000, 0));
    REQUIRE(!initial_profile_matches(&changed));
    struct aos_nv_custody_role foreign_role = initial_role;
    foreign_role.index = UINT32_C(0x0180a055);
    foreign_role.salt = UINT32_C(0x8100a055);
    changed = initial_profile;
    changed.roles = &foreign_role;
    REQUIRE(!lock_owner_matches(&changed, 0, 0));
    REQUIRE(!lock_owner_matches(&changed, 1000, 0));
    REQUIRE(!initial_profile_matches(&changed));
}

static void bind_lock_identity(uint8_t hello[HELLO_BYTES], size_t index, int file)
{
    struct stat metadata;
    REQUIRE(fstat(file, &metadata) == 0);
    uint8_t *expected = hello + 120 + index * 20;
    for (size_t byte = 0; byte < 8; ++byte) {
        expected[7 - byte] = (uint8_t)((uint64_t)metadata.st_dev >> (byte * 8));
        expected[15 - byte] = (uint8_t)((uint64_t)metadata.st_ino >> (byte * 8));
    }
    put_u32(expected + 16, (uint32_t)metadata.st_uid);
}

static void require_foreign_flock_refused(const char *path)
{
    int foreign = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(foreign >= 3);
    errno = 0;
    REQUIRE(flock(foreign, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK);
    REQUIRE(close(foreign) == 0);
}

static void native_lock_cases(void)
{
    char directory[] = "/tmp/aos-method46-initial-lock-owner-XXXXXX";
    REQUIRE(mkdtemp(directory) != NULL);
    char paths[2][128];
    int locks[2];
    uint8_t hello[HELLO_BYTES];
    hello_for_profile(hello);

    for (size_t index = 0; index < 2; ++index) {
        REQUIRE(snprintf(paths[index], sizeof(paths[index]), "%s/lock-%zu", directory, index) > 0);
        locks[index] = open(paths[index], O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        REQUIRE(locks[index] >= 3);
        REQUIRE(flock(locks[index], LOCK_EX | LOCK_NB) == 0);
        bind_lock_identity(hello, index, locks[index]);
    }
    struct aos_nv_custody_profile normal = initial_profile;
    normal.lock_owner = AOS_NV_LOCK_OWNER_SELF;
    REQUIRE(validate_locks(hello, locks, &normal) == 0);

    if (geteuid() == 0) {
        uid_t owner = initial_profile.lock_owner == AOS_NV_LOCK_OWNER_INITIAL_CONTROLLER ? 1000 : 0;
        for (size_t index = 0; index < 2; ++index) {
            REQUIRE(fchown(locks[index], owner, 0) == 0);
            bind_lock_identity(hello, index, locks[index]);
        }
        REQUIRE(validate_locks(hello, locks, &initial_profile) == 0);
        REQUIRE((validate_locks(hello, locks, &normal) == 0) == (owner == 0));
        for (size_t index = 0; index < 2; ++index)
            require_foreign_flock_refused(paths[index]);

        /* A native owner mismatch refuses even when HELLO repeats that new
         * owner accurately. Both actual descriptions remain held on refusal. */
        REQUIRE(fchown(locks[1], 1001, 0) == 0);
        bind_lock_identity(hello, 1, locks[1]);
        REQUIRE(validate_locks(hello, locks, &initial_profile) != 0);
        REQUIRE(fchown(locks[1], owner, 0) == 0);
        bind_lock_identity(hello, 1, locks[1]);

        REQUIRE(ftruncate(locks[0], 1) == 0);
        REQUIRE(validate_locks(hello, locks, &initial_profile) != 0);
        REQUIRE(ftruncate(locks[0], 0) == 0);
        int alias[2] = {locks[0], locks[0]};
        bind_lock_identity(hello, 1, locks[0]);
        REQUIRE(validate_locks(hello, alias, &initial_profile) != 0);
        bind_lock_identity(hello, 1, locks[1]);
        REQUIRE(fchmod(locks[0], 0640) == 0);
        REQUIRE(validate_locks(hello, locks, &initial_profile) != 0);
        REQUIRE(fchmod(locks[0], 0600) == 0);
        int read_only = open(paths[0], O_RDONLY | O_CLOEXEC);
        REQUIRE(read_only >= 3);
        int wrong_access[2] = {read_only, locks[1]};
        REQUIRE(validate_locks(hello, wrong_access, &initial_profile) != 0);
        REQUIRE(close(read_only) == 0);
        REQUIRE(validate_locks(hello, locks, &initial_profile) == 0);
        for (size_t index = 0; index < 2; ++index)
            require_foreign_flock_refused(paths[index]);
        REQUIRE(puts("native root-owned helper / fixed journal-owner lock custody PASS") >= 0);
    } else {
#ifdef AOS_METHOD46_LOCK_OWNER_REQUIRE_ROOT
        REQUIRE(geteuid() == 0);
#else
        REQUIRE(puts("root ownership-transfer cases NOT RUN; QEMU root execution required") >= 0);
#endif
    }

    for (size_t index = 0; index < 2; ++index) {
        REQUIRE(close(locks[index]) == 0);
        REQUIRE(unlink(paths[index]) == 0);
    }
    REQUIRE(rmdir(directory) == 0);
}

int main(void)
{
    fixed_policy_cases();
    native_lock_cases();
    REQUIRE(puts("fixed initial METHOD46 helper lock-owner checks PASS") >= 0);
    return EXIT_SUCCESS;
}
