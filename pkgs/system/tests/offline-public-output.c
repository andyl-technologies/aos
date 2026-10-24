/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Exercises the production socket-label owner, including refusal before any
 * caller can fall back to logging under an unconfirmed creation context. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

enum { EXIT_SELINUX_CONTEXT = 229, LOG_DEBUG = 7 };

static unsigned socket_calls;

#if HAVE_SELINUX
enum failure {
        NONE,
        LOAD,
        DISABLED,
        INITIAL_READ,
        FOREIGN_INITIAL,
        SET,
        SOCKET,
        RESET,
        RESTORED_READ,
        FOREIGN_RESTORED,
};

static enum failure failure;
static unsigned load_calls, read_calls, set_calls;
static bool labelled;

static int test_load(int level) {
        assert(level == LOG_DEBUG);
        ++load_calls;
        return failure == LOAD ? -ENOENT : 0;
}

static int test_enabled(void) {
        assert(load_calls == 1);
        return failure == DISABLED ? 0 : 1;
}

static int test_read(char **label) {
        ++read_calls;
        if ((read_calls == 1 && failure == INITIAL_READ) ||
            (read_calls == 2 && failure == RESTORED_READ)) {
                errno = EIO;
                return -1;
        }
        if (read_calls == 1) {
                assert(set_calls == 0 && socket_calls == 0);
                *label = failure == FOREIGN_INITIAL ? (char *) "foreign" : NULL;
        } else {
                assert(read_calls == 2 && set_calls == 2 && socket_calls == 1);
                *label = failure == FOREIGN_RESTORED ? (char *) "foreign" : NULL;
        }
        return 0;
}

static int test_set(const char *label) {
        ++set_calls;
        if (label) {
                assert(set_calls == 1 && read_calls == 1 && socket_calls == 0);
                assert(strcmp(label, "system_u:object_r:aos_nix_offline_public_output_t") == 0);
                if (failure == SET) {
                        errno = EACCES;
                        return -1;
                }
                labelled = true;
        } else {
                assert(set_calls == 2 && socket_calls == 1);
                if (failure == RESET) {
                        errno = EACCES;
                        return -1;
                }
                labelled = false;
        }
        return 0;
}
#endif

static int test_socket(int domain, int type, int protocol) {
        assert(domain == AF_UNIX && type == SOCK_STREAM && protocol == 0);
        ++socket_calls;
#if HAVE_SELINUX
        if (load_calls) {
                assert(labelled && set_calls == 1 && read_calls == 1);
                if (failure == SOCKET) {
                        errno = EMFILE;
                        return -1;
                }
        }
#endif
        return 17;
}

#define socket test_socket
#if HAVE_SELINUX
#define dlopen_libselinux test_load
#define sym_is_selinux_enabled test_enabled
#define sym_getsockcreatecon_raw test_read
#define sym_setsockcreatecon_raw test_set
#endif
#include "aos-offline-public-output.h"
#undef socket

static const char unit[] = "aos-sandbox-nix-floor-provision.service";
static const char context[] = "system_u:system_r:aos_nix_offline_prepare_t";

static void expect_refusal(const char *selected_context, bool ignore) {
        pid_t child = fork();
        assert(child >= 0);
        if (child == 0) {
                (void) aos_offline_public_output_socket(unit, selected_context, ignore);
                _exit(0);
        }

        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SELINUX_CONTEXT);
}

int main(void) {
        const char *ordinary[] = {
                NULL,
                "other.service",
                "aos-sandbox-nix-floor-provision@foreign.service",
                "aos-sandbox-nix-floor-provision.service.extra",
        };
        for (size_t index = 0; index < sizeof(ordinary) / sizeof(ordinary[0]); ++index) {
                assert(!aos_offline_public_output_selected(ordinary[index]));
                assert(aos_offline_public_output_socket(ordinary[index], context, false) == 17);
        }
        assert(socket_calls == 4);
        assert(aos_offline_public_output_selected(unit));
        socket_calls = 0;

        expect_refusal(NULL, false);
        expect_refusal("system_u:system_r:init_t", false);
        expect_refusal(context, true);

#if HAVE_SELINUX
        assert(load_calls == 0 && read_calls == 0 && set_calls == 0);
        for (enum failure selected = LOAD; selected <= FOREIGN_RESTORED; ++selected) {
                failure = selected;
                expect_refusal(context, false);
        }
        failure = NONE;

        assert(aos_offline_public_output_socket(unit, context, false) == 17);
        assert(socket_calls == 1 && load_calls == 1 && read_calls == 2 && set_calls == 2);
        assert(!labelled);
#else
        expect_refusal(context, false);
#endif
        return 0;
}
