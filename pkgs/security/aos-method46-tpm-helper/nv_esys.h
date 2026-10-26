/* SPDX-License-Identifier: Apache-2.0 */
/* Private build-time policy, never a caller-selected TPM endpoint. Each fixed
 * main supplies its own closed roles; the shared runner preserves v2 framing,
 * two OFD loans, authenticated ESYS, and ambiguity fencing. */
#ifndef AOS_NV_ESYS_H
#define AOS_NV_ESYS_H
#include <stddef.h>
#include <stdint.h>

struct aos_nv_custody_role {
    uint32_t index;
    uint32_t salt;
    const char *context;
};

/* Zero preserves every existing runtime purpose's self-owned lock rule.
 * Initial producers are separate fixed images: their root helper can borrow
 * Controller-owned locks without changing either writer's UID or capabilities. */
enum aos_nv_lock_owner_policy {
    AOS_NV_LOCK_OWNER_SELF = 0,
    AOS_NV_LOCK_OWNER_INITIAL_CONTROLLER,
    AOS_NV_LOCK_OWNER_INITIAL_STORAGE,
};

struct aos_nv_custody_profile {
    const struct aos_nv_custody_role *roles;
    size_t role_count;
    enum aos_nv_lock_owner_policy lock_owner;
};

int aos_nv_custody_run(int argc, const struct aos_nv_custody_profile *profile);

/* The independent offline entry admits only the fixed paired 058/059 job.
 * It never implements a runtime floor, NV seeding, or another profile role. */
int aos_nix_offline_provision_run(int argc);
#endif
