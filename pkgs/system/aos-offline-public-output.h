/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* This selects one existing manual unit, never a prefix or a new IPC owner. */
static bool aos_offline_public_output_selected(const char *unit) {
        return unit && strcmp(unit, "aos-sandbox-nix-floor-provision.service") == 0;
}

/* Linux revalidates both socket file modes at exec, including SHUT_RD streams.
 * Label this existing public-output socket separately from PID 1's private IPC.
 * No helper process, additional descriptor or generic init_t read is introduced.
 *
 * Failed label custody terminates this executor without logging or unwinding:
 * no later socket may be created under an unknown creation context. */
static int aos_offline_public_output_socket(const char *unit, const char *context, bool ignore_context) {
        int fd;

        if (!aos_offline_public_output_selected(unit)) {
                fd = socket(AF_UNIX, SOCK_STREAM, 0);
                return fd < 0 ? -errno : fd;
        }

        if (ignore_context || !context || strcmp(context, "system_u:system_r:aos_nix_offline_prepare_t") != 0)
                _exit(EXIT_SELINUX_CONTEXT);

#if HAVE_SELINUX
        char *previous = NULL, *restored = NULL;

        if (dlopen_libselinux(LOG_DEBUG) < 0 || sym_is_selinux_enabled() <= 0)
                _exit(EXIT_SELINUX_CONTEXT);
        if (sym_getsockcreatecon_raw(&previous) < 0 || previous)
                _exit(EXIT_SELINUX_CONTEXT);
        if (sym_setsockcreatecon_raw("system_u:object_r:aos_nix_offline_public_output_t:s0") < 0)
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
