/* SPDX-License-Identifier: Apache-2.0 */
/* Method 46 retains its exact fixed endpoint, salt and helper-domain policy. */
#include "nv_esys.h"

static const struct aos_nv_custody_role method46_roles[] = {
    { UINT32_C(0x0180a046), UINT32_C(0x8100a046),
      "system_u:system_r:aos_method46_controller_helper_t" },
    { UINT32_C(0x0180a047), UINT32_C(0x8100a047),
      "system_u:system_r:aos_method46_storage_helper_t" },
};
static const struct aos_nv_custody_profile method46_profile = {
    .roles = method46_roles,
    .role_count = sizeof(method46_roles) / sizeof(method46_roles[0]),
};

int main(int argc, char **argv)
{
    (void)argv;
    return aos_nv_custody_run(argc, &method46_profile);
}
