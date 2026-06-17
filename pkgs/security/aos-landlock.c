#define _GNU_SOURCE

#include <errno.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif

#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

#if !defined(__NR_landlock_create_ruleset) || !defined(__NR_landlock_add_rule) || !defined(__NR_landlock_restrict_self)
#error "missing Landlock syscall numbers in Linux headers"
#endif

struct port_list {
    uint16_t *items;
    size_t len;
    size_t cap;
};

static void usage(FILE *stream)
{
    fprintf(stream,
        "usage: aos-landlock [--require-abi N] [--tcp-bind PORT] "
        "[--tcp-connect PORT] -- COMMAND [ARG...]\n");
}

static int parse_u32(const char *text, unsigned int *out)
{
    char *end = NULL;
    unsigned long value;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > UINT32_MAX) {
        return -1;
    }
    *out = (unsigned int)value;
    return 0;
}

static int parse_port(const char *text, uint16_t *out)
{
    unsigned int value;

    if (parse_u32(text, &value) != 0 || value == 0 || value > UINT16_MAX) {
        return -1;
    }
    *out = (uint16_t)value;
    return 0;
}

static int add_port(struct port_list *ports, uint16_t port)
{
    size_t i;
    uint16_t *new_items;
    size_t new_cap;

    for (i = 0; i < ports->len; i++) {
        if (ports->items[i] == port) {
            fprintf(stderr, "aos-landlock: duplicate TCP port %u\n", port);
            return -1;
        }
    }

    if (ports->len == ports->cap) {
        new_cap = ports->cap == 0 ? 4 : ports->cap * 2;
        new_items = realloc(ports->items, new_cap * sizeof(*ports->items));
        if (new_items == NULL) {
            perror("aos-landlock: realloc");
            return -1;
        }
        ports->items = new_items;
        ports->cap = new_cap;
    }

    ports->items[ports->len++] = port;
    return 0;
}

static long landlock_create_ruleset_raw(const struct landlock_ruleset_attr *attr,
    size_t size, __u32 flags)
{
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int landlock_add_rule_raw(int ruleset_fd, enum landlock_rule_type type,
    const void *attr, __u32 flags)
{
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}

static int landlock_restrict_self_raw(int ruleset_fd, __u32 flags)
{
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

static int add_net_rules(int ruleset_fd, const struct port_list *ports,
    __u64 access)
{
    size_t i;

    for (i = 0; i < ports->len; i++) {
        struct landlock_net_port_attr rule = {
            .allowed_access = access,
            .port = ports->items[i],
        };

        if (landlock_add_rule_raw(ruleset_fd, LANDLOCK_RULE_NET_PORT, &rule, 0)
            != 0) {
            fprintf(stderr, "aos-landlock: failed to add TCP port %u rule: %s\n",
                ports->items[i], strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int apply_landlock(unsigned int require_abi, const struct port_list *bind_ports,
    const struct port_list *connect_ports)
{
    long abi;
    int ruleset_fd;
    struct landlock_ruleset_attr ruleset = {
        .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP
            | LANDLOCK_ACCESS_NET_CONNECT_TCP,
    };

    abi = landlock_create_ruleset_raw(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        fprintf(stderr, "aos-landlock: Landlock ABI probe failed: %s\n",
            strerror(errno));
        return -1;
    }
    if ((unsigned long)abi < require_abi) {
        fprintf(stderr,
            "aos-landlock: Landlock ABI %ld is below required ABI %u\n", abi,
            require_abi);
        return -1;
    }

    ruleset_fd = (int)landlock_create_ruleset_raw(&ruleset, sizeof(ruleset), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "aos-landlock: failed to create ruleset: %s\n",
            strerror(errno));
        return -1;
    }

    if (add_net_rules(ruleset_fd, bind_ports, LANDLOCK_ACCESS_NET_BIND_TCP) != 0
        || add_net_rules(ruleset_fd, connect_ports,
               LANDLOCK_ACCESS_NET_CONNECT_TCP)
            != 0) {
        close(ruleset_fd);
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "aos-landlock: failed to set no_new_privs: %s\n",
            strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    if (landlock_restrict_self_raw(ruleset_fd, 0) != 0) {
        fprintf(stderr, "aos-landlock: failed to restrict process: %s\n",
            strerror(errno));
        close(ruleset_fd);
        return -1;
    }

    close(ruleset_fd);
    return 0;
}

int main(int argc, char **argv)
{
    struct port_list bind_ports = {0};
    struct port_list connect_ports = {0};
    unsigned int require_abi = 4;
    int command_index = -1;
    int i;

    for (i = 1; i < argc; i++) {
        uint16_t port;

        if (strcmp(argv[i], "--") == 0) {
            command_index = i + 1;
            break;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else if (strcmp(argv[i], "--require-abi") == 0) {
            if (++i >= argc || parse_u32(argv[i], &require_abi) != 0
                || require_abi == 0) {
                fprintf(stderr, "aos-landlock: invalid --require-abi value\n");
                usage(stderr);
                return 2;
            }
        } else if (strcmp(argv[i], "--tcp-bind") == 0) {
            if (++i >= argc || parse_port(argv[i], &port) != 0
                || add_port(&bind_ports, port) != 0) {
                fprintf(stderr, "aos-landlock: invalid --tcp-bind value\n");
                usage(stderr);
                return 2;
            }
        } else if (strcmp(argv[i], "--tcp-connect") == 0) {
            if (++i >= argc || parse_port(argv[i], &port) != 0
                || add_port(&connect_ports, port) != 0) {
                fprintf(stderr, "aos-landlock: invalid --tcp-connect value\n");
                usage(stderr);
                return 2;
            }
        } else {
            fprintf(stderr, "aos-landlock: unknown argument '%s'\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }

    if (command_index < 0 || command_index >= argc) {
        fprintf(stderr, "aos-landlock: missing command after --\n");
        usage(stderr);
        return 2;
    }

    if (apply_landlock(require_abi, &bind_ports, &connect_ports) != 0) {
        return 1;
    }

    execvp(argv[command_index], &argv[command_index]);
    fprintf(stderr, "aos-landlock: failed to exec '%s': %s\n",
        argv[command_index], strerror(errno));
    return 127;
}
