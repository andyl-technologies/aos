/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct AosManualPublicOutput {
        const char *unit;
        const char *context;
        const char *output;
} AosManualPublicOutput;

/* These fixed manual units share the existing output socket owner. Neither
 * a caller-supplied label nor a unit prefix selects another creation context. */
static const AosManualPublicOutput *aos_manual_public_output(const char *unit) {
        static const AosManualPublicOutput purposes[] = {
                {
                        "aos-sandbox-nix-floor-provision.service",
                        "system_u:system_r:aos_nix_offline_prepare_t",
                        "system_u:object_r:aos_nix_offline_public_output_t",
                },
                {
                        "aos-sandbox-controller-floor-initialize.service",
                        "system_u:system_r:aos_method46_controller_initial_t",
                        "system_u:object_r:aos_method46_controller_initial_output_t",
                },
                {
                        "aos-sandbox-storage-floor-initialize.service",
                        "system_u:system_r:aos_method46_storage_initial_t",
                        "system_u:object_r:aos_method46_storage_initial_output_t",
                },
        };

        if (unit)
                for (size_t index = 0; index < sizeof(purposes) / sizeof(purposes[0]); ++index)
                        if (strcmp(unit, purposes[index].unit) == 0)
                                return &purposes[index];

        return NULL;
}

static bool aos_offline_public_output_selected(const char *unit) {
        return aos_manual_public_output(unit) != NULL;
}

/* Linux revalidates both socket file modes at exec, including SHUT_RD streams.
 * Label this existing public-output socket separately from PID 1's private IPC.
 * No helper process, additional descriptor or generic init_t read is introduced.
 *
 * Failed label custody terminates this executor without logging or unwinding:
 * no later socket may be created under an unknown creation context. */
static int aos_offline_public_output_socket(const char *unit, const char *context, bool ignore_context) {
        const AosManualPublicOutput *purpose = aos_manual_public_output(unit);
        int fd;

        if (!purpose) {
                fd = socket(AF_UNIX, SOCK_STREAM, 0);
                return fd < 0 ? -errno : fd;
        }

        if (ignore_context || !context || strcmp(context, purpose->context) != 0)
                _exit(EXIT_SELINUX_CONTEXT);

#if HAVE_SELINUX
        char *previous = NULL, *restored = NULL;

        if (dlopen_libselinux(LOG_DEBUG) < 0 || sym_is_selinux_enabled() <= 0)
                _exit(EXIT_SELINUX_CONTEXT);
        if (sym_getsockcreatecon_raw(&previous) < 0 || previous)
                _exit(EXIT_SELINUX_CONTEXT);
        /* The authenticated AOS policy is non-MLS; an s0 suffix is invalid. */
        if (sym_setsockcreatecon_raw(purpose->output) < 0)
                _exit(EXIT_SELINUX_CONTEXT);

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        int reset = sym_setsockcreatecon_raw(NULL);
        int readback = sym_getsockcreatecon_raw(&restored);

        if (reset < 0 || readback < 0 || restored || fd < 0)
                _exit(EXIT_SELINUX_CONTEXT);
        return fd;
#else
        _exit(EXIT_SELINUX_CONTEXT);
#endif
}
