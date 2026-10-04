/* SPDX-License-Identifier: Apache-2.0 */
/* Existing-only ONLINE058/059 consumers; no hierarchy auth or provisioning. */
#include "nv_esys.h"

#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(AOS_NIX_CONTROLLER_HELPER)
static const struct aos_nv_custody_role online_role = {
    UINT32_C(0x0180a058), UINT32_C(0x8100a058),
    "system_u:system_r:aos_nix_controller_floor_helper_t"
};
#elif defined(AOS_NIX_OWNER_HELPER)
static const struct aos_nv_custody_role online_role = {
    UINT32_C(0x0180a059), UINT32_C(0x8100a059),
    "system_u:system_r:aos_nix_owner_floor_helper_t"
};
#else
#error "A fixed ONLINE helper role must be selected at build time"
#endif

static const struct aos_nv_custody_profile online_profile = {
    .roles = &online_role,
    .role_count = 1,
};

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1)
        return 1;

    /* The root control owner has only credential-drop capabilities. Its
     * existing PATH spawn preserves that ambient launch behavior; the fixed
     * child drops all effective/permitted/inheritable capabilities before the
     * parent's genuine helper checks and the shared HELLO/AUTH engine. This
     * does not alter the inherited bounding set or grant any capability. */
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct empty[2] = {{0}, {0}};
    if (syscall(SYS_capset, &header, empty) != 0)
        return 1;

    return aos_nv_custody_run(argc, &online_profile);
}
