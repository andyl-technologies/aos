/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <assert.h>

#include "aos-resource-unit-name.h"

int main(void) {
        const char *const enrolled[] = {
                "aos-sandboxd.service",
                "aos-sandboxd-publisher.socket",
                "aos-storaged.service",
                "aos-storaged-existing-output.socket",
                "aos-storaged-provision-output.service",
                "aos-netd.service",
                "aos-netd.socket",
                "aos-view-publisher.service",
                "aos-sandbox-source-signerd.service",
                "aos-sandbox-cache-signerd.socket",
                "aos-sandbox-zfs-worker@instance.service",
                "aos-sandbox-network-worker@instance.service",
                "aos-sandbox-hostd.service",
                "aos-sandbox-guardian@instance.service",
        };
        const char *const ordinary[] = {
                "aos-test-agent.service",
                "aos-attest.service",
                "aos-registry-sync.service",
                "aos-nix-db.service",
                "systemd-journald.service",
                "multi-user.target",
                "aos-sandboxed.service",
                "aos-storagedata.service",
                "aos-netdb.service",
                "aos-view-publishers.service",
                "aos-sandbox",
                "",
        };

        for (size_t i = 0; i < sizeof(enrolled) / sizeof(enrolled[0]); i++)
                assert(aos_resource_enrolled_name(enrolled[i]));

        for (size_t i = 0; i < sizeof(ordinary) / sizeof(ordinary[0]); i++)
                assert(!aos_resource_enrolled_name(ordinary[i]));

        assert(!aos_resource_enrolled_name(NULL));
        return 0;
}
