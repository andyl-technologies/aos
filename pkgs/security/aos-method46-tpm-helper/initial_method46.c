/* SPDX-License-Identifier: Apache-2.0 */
/* One fixed manual initial purpose per image; no role argument or UID change. */
#include "nv_esys.h"

#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(AOS_METHOD46_INITIAL_CONTROLLER_HELPER) && defined(AOS_METHOD46_INITIAL_STORAGE_HELPER)
#error "Select exactly one fixed initial METHOD46 helper role"
#elif defined(AOS_METHOD46_INITIAL_CONTROLLER_HELPER)
static const struct aos_nv_custody_role initial_role = {
    UINT32_C(0x0180a046), UINT32_C(0x8100a046),
    "system_u:system_r:aos_method46_initial_controller_helper_t",
};
static const struct aos_nv_custody_profile initial_profile = {
    .roles = &initial_role,
    .role_count = 1,
    .lock_owner = AOS_NV_LOCK_OWNER_INITIAL_CONTROLLER,
};
#elif defined(AOS_METHOD46_INITIAL_STORAGE_HELPER)
static const struct aos_nv_custody_role initial_role = {
    UINT32_C(0x0180a047), UINT32_C(0x8100a047),
    "system_u:system_r:aos_method46_initial_storage_helper_t",
};
static const struct aos_nv_custody_profile initial_profile = {
    .roles = &initial_role,
    .role_count = 1,
    .lock_owner = AOS_NV_LOCK_OWNER_INITIAL_STORAGE,
};
#else
#error "Select one fixed initial METHOD46 helper role at build time"
#endif

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || getuid() != 0 || geteuid() != 0
        || getgid() != 0 || getegid() != 0)
        return 1;

    /* The parent's CHOWN/DAC_OVERRIDE custody is not needed by this private
     * child. Clear all effective/permitted/inheritable capabilities before
     * HELLO; neither changing UIDs nor acquiring capabilities is permitted. */
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct empty[2] = {{0}, {0}};
    if (syscall(SYS_capset, &header, empty) != 0)
        return 1;

    return aos_nv_custody_run(argc, &initial_profile);
}
