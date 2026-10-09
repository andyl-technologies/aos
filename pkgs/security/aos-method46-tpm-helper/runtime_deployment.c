/* SPDX-License-Identifier: Apache-2.0 */
/* Independently provisioned deployment-only purpose. No runtime/output/Root or
 * method-46 endpoint is accepted by this separately installed fixed image. */
#include "nv_esys.h"

int main(int argc, char **argv)
{
    (void)argv;
    static const struct aos_nv_custody_role role = {
        UINT32_C(0x0180a055), UINT32_C(0x8100a055),
        "system_u:system_r:aos_runtime_deployment_helper_t",
    };
    const struct aos_nv_custody_profile profile = {
        .roles = &role,
        .role_count = 1,
    };
    return aos_nv_custody_run(argc, &profile);
}
