#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#endif

#ifndef LANDLOCK_ACCESS_FS_WRITE_FILE
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#endif

#ifndef LANDLOCK_ACCESS_FS_READ_FILE
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#endif

#ifndef LANDLOCK_ACCESS_FS_READ_DIR
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#endif

#ifndef LANDLOCK_ACCESS_FS_REMOVE_DIR
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#endif

#ifndef LANDLOCK_ACCESS_FS_REMOVE_FILE
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_CHAR
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_DIR
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_REG
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_SOCK
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_FIFO
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_BLOCK
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#endif

#ifndef LANDLOCK_ACCESS_FS_MAKE_SYM
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif

#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
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

struct path_rule {
    char *path;
    __u64 access;
};

struct path_list {
    struct path_rule *items;
    size_t len;
    size_t cap;
};

static const __u64 FS_READ_ACCESS = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

static const __u64 FS_WRITE_ACCESS = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

static void usage(FILE *stream)
{
    fprintf(stream,
        "usage: aos-landlock --print-abi\n"
        "       aos-landlock [--require-abi N] [--fs-ro PATH] [--fs-rw PATH] "
        "[--network-unrestricted | --tcp-bind PORT | --tcp-connect PORT] "
        "-- COMMAND [ARG...]\n");
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

static int add_path(struct path_list *paths, const char *path, __u64 access)
{
    size_t i;
    struct path_rule *new_items;
    size_t new_cap;
    char *copy;

    if (path[0] != '/') {
        fprintf(stderr, "aos-landlock: path must be absolute: %s\n", path);
        return -1;
    }

    for (i = 0; i < paths->len; i++) {
        if (strcmp(paths->items[i].path, path) == 0) {
            fprintf(stderr, "aos-landlock: duplicate filesystem path %s\n",
                path);
            return -1;
        }
    }

    if (paths->len == paths->cap) {
        new_cap = paths->cap == 0 ? 4 : paths->cap * 2;
        new_items = realloc(paths->items, new_cap * sizeof(*paths->items));
        if (new_items == NULL) {
            perror("aos-landlock: realloc");
            return -1;
        }
        paths->items = new_items;
        paths->cap = new_cap;
    }

    copy = strdup(path);
    if (copy == NULL) {
        perror("aos-landlock: strdup");
        return -1;
    }

    paths->items[paths->len].path = copy;
    paths->items[paths->len].access = access;
    paths->len++;
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

static long probe_landlock_abi(void)
{
    return landlock_create_ruleset_raw(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
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

static int add_path_rules(int ruleset_fd, const struct path_list *paths)
{
    size_t i;

    for (i = 0; i < paths->len; i++) {
        int path_fd;
        struct stat path_stat;
        struct landlock_path_beneath_attr rule = {
            .allowed_access = paths->items[i].access,
        };

        path_fd = open(paths->items[i].path, O_PATH | O_CLOEXEC);
        if (path_fd < 0) {
            fprintf(stderr, "aos-landlock: failed to open %s: %s\n",
                paths->items[i].path, strerror(errno));
            return -1;
        }

        if (fstat(path_fd, &path_stat) != 0) {
            fprintf(stderr, "aos-landlock: failed to stat %s: %s\n",
                paths->items[i].path, strerror(errno));
            close(path_fd);
            return -1;
        }

        /* Landlock rejects directory-only access rights on non-directories.
         * Keep exact file grants narrow instead of requiring callers to grant
         * the containing directory. */
        if (!S_ISDIR(path_stat.st_mode)) {
            rule.allowed_access &= LANDLOCK_ACCESS_FS_EXECUTE
                | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE
                | LANDLOCK_ACCESS_FS_TRUNCATE;
        }

        rule.parent_fd = path_fd;
        if (landlock_add_rule_raw(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule,
                0)
            != 0) {
            fprintf(stderr, "aos-landlock: failed to add path rule %s: %s\n",
                paths->items[i].path, strerror(errno));
            close(path_fd);
            return -1;
        }
        close(path_fd);
    }
    return 0;
}

static int apply_landlock(unsigned int require_abi, int restrict_network,
    const struct port_list *bind_ports, const struct port_list *connect_ports,
    const struct path_list *paths)
{
    long abi;
    int ruleset_fd;
    struct landlock_ruleset_attr ruleset = {0};

    abi = probe_landlock_abi();
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

    if (paths->len > 0) {
        ruleset.handled_access_fs = FS_READ_ACCESS | FS_WRITE_ACCESS;
    }
    if (restrict_network) {
        ruleset.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP
            | LANDLOCK_ACCESS_NET_CONNECT_TCP;
    }

    ruleset_fd = (int)landlock_create_ruleset_raw(&ruleset, sizeof(ruleset), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "aos-landlock: failed to create ruleset: %s\n",
            strerror(errno));
        return -1;
    }

    if ((restrict_network
            && (add_net_rules(ruleset_fd, bind_ports,
                    LANDLOCK_ACCESS_NET_BIND_TCP)
                    != 0
                || add_net_rules(ruleset_fd, connect_ports,
                       LANDLOCK_ACCESS_NET_CONNECT_TCP)
                    != 0))
        || add_path_rules(ruleset_fd, paths)
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
    struct path_list paths = {0};
    unsigned int require_abi = 4;
    int restrict_network = 1;
    int network_unrestricted_seen = 0;
    int command_index = -1;
    int i;

    if (argc == 2 && strcmp(argv[1], "--print-abi") == 0) {
        long abi = probe_landlock_abi();
        if (abi < 0) {
            fprintf(stderr, "aos-landlock: Landlock ABI probe failed: %s\n",
                strerror(errno));
            return 1;
        }
        printf("%ld\n", abi);
        return 0;
    }

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
        } else if (strcmp(argv[i], "--fs-ro") == 0) {
            if (++i >= argc
                || add_path(&paths, argv[i], FS_READ_ACCESS) != 0) {
                fprintf(stderr, "aos-landlock: invalid --fs-ro value\n");
                usage(stderr);
                return 2;
            }
        } else if (strcmp(argv[i], "--fs-rw") == 0) {
            if (++i >= argc
                || add_path(&paths, argv[i], FS_READ_ACCESS | FS_WRITE_ACCESS)
                    != 0) {
                fprintf(stderr, "aos-landlock: invalid --fs-rw value\n");
                usage(stderr);
                return 2;
            }
        } else if (strcmp(argv[i], "--network-unrestricted") == 0) {
            if (network_unrestricted_seen) {
                fprintf(stderr,
                    "aos-landlock: duplicate --network-unrestricted\n");
                usage(stderr);
                return 2;
            }
            network_unrestricted_seen = 1;
            restrict_network = 0;
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

    if (!restrict_network && (bind_ports.len != 0 || connect_ports.len != 0)) {
        fprintf(stderr,
            "aos-landlock: --network-unrestricted cannot be combined with TCP rules\n");
        usage(stderr);
        return 2;
    }

    if (apply_landlock(require_abi, restrict_network, &bind_ports, &connect_ports,
            &paths)
        != 0) {
        return 1;
    }

    execvp(argv[command_index], &argv[command_index]);
    fprintf(stderr, "aos-landlock: failed to exec '%s': %s\n",
        argv[command_index], strerror(errno));
    return 127;
}
