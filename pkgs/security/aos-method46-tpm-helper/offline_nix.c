/* SPDX-License-Identifier: Apache-2.0 */
/* Fixed descriptor-launched offline entry. Parent cap0x3/securebits0x0c is
 * distinct from the legacy helper's 0x0f launch. No option selects a role. */
#define _GNU_SOURCE
#include "nv_esys.h"
#include <errno.h>
#include <linux/capability.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

static int require_closed_recipe(void)
{
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;
    struct rlimit descriptors, address_space;
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct capabilities[2] = {{0}, {0}};

    if (getresuid(&real_uid, &effective_uid, &saved_uid) != 0
        || getresgid(&real_gid, &effective_gid, &saved_gid) != 0
        || real_uid != 0 || effective_uid != 0 || saved_uid != 0
        || real_gid != 0 || effective_gid != 0 || saved_gid != 0
        || prctl(PR_GET_SECUREBITS) != 0x0c
        || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
        || syscall(SYS_capset, &header, capabilities) != 0
        || syscall(SYS_capget, &header, capabilities) != 0)
        return -1;
    for (size_t index = 0; index < 2; ++index) {
        if (capabilities[index].effective != 0
            || capabilities[index].permitted != 0
            || capabilities[index].inheritable != 0)
            return -1;
    }
    for (int capability = 0; capability <= CAP_LAST_CAP; ++capability) {
        if (prctl(PR_CAPBSET_READ, capability) != (capability < 2))
            return -1;
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0) != 0)
            return -1;
    }

    if (getrlimit(RLIMIT_NOFILE, &descriptors) != 0
        || descriptors.rlim_cur != 4096 || descriptors.rlim_max != 4096
        || getrlimit(RLIMIT_AS, &address_space) != 0
        || address_space.rlim_cur != 1073741824
        || address_space.rlim_max != 1073741824)
        return -1;
    descriptors.rlim_cur = 64;
    descriptors.rlim_max = 64;
    if (setrlimit(RLIMIT_NOFILE, &descriptors) != 0
        || close_range(6, ~0U, 0) != 0)
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || require_closed_recipe() != 0)
        return EXIT_FAILURE;
    return aos_nix_offline_provision_run(argc);
}
