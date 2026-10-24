/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Missing enrollment refuses Sandbox owners and their sockets, helpers,
 * instances and aliases. The general aos-* namespace also contains ordinary
 * host services; their names do not select the Sandbox resource bank. Once a
 * bank is admitted, job acquisition still charges every competing manager job.
 */
static inline bool aos_resource_enrolled_name(const char *name) {
        static const char *const owners[] = {
                "aos-sandbox",
                "aos-sandboxd",
                "aos-storaged",
                "aos-netd",
                "aos-view-publisher",
        };

        if (!name)
                return false;

        for (size_t i = 0; i < sizeof(owners) / sizeof(owners[0]); i++) {
                size_t length = strlen(owners[i]);

                if (strncmp(name, owners[i], length) == 0 &&
                    (name[length] == '.' || name[length] == '-' || name[length] == '@'))
                        return true;
        }

        return false;
}
