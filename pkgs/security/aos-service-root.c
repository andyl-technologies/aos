/* SPDX-License-Identifier: MIT */
/* Prepare trusted, per-unit overlay roots without modifying package payloads. */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define ROOT_PATH "/run/aos/service-roots"

static void errorf(const char *format, ...) {
        va_list ap;

        fputs("aos-service-root: ", stderr);
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
        fputc('\n', stderr);
}

static bool token_valid(const char *token) {
        size_t length;

        if (!token || token[0] == '\0' || token[0] == '.' || token[0] == '-')
                return false;

        length = strlen(token);
        if (length > NAME_MAX)
                return false;

        for (size_t i = 0; i < length; i++) {
                char c = token[i];

                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '@' || c == '-')
                        continue;
                return false;
        }

        return true;
}

static int check_safe_directory_fd(int fd, const char *path) {
        struct stat st;

        if (fstat(fd, &st) < 0) {
                errorf("cannot inspect '%s': %s", path, strerror(errno));
                return -1;
        }
        if (!S_ISDIR(st.st_mode)) {
                errorf("unsafe component '%s' is not a directory", path);
                errno = ENOTDIR;
                return -1;
        }
        if (st.st_uid != 0 || (st.st_mode & 0022) != 0) {
                errorf("unsafe component '%s' must be root-owned and not group/world writable", path);
                errno = EPERM;
                return -1;
        }

        return 0;
}

static int open_safe_child(int parent_fd, const char *name, const char *path, mode_t mode,
                           bool create, bool *created) {
        int fd;

        if (created)
                *created = false;

        fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 && errno == ENOENT && create) {
                if (mkdirat(parent_fd, name, mode) < 0 && errno != EEXIST) {
                        errorf("cannot create '%s': %s", path, strerror(errno));
                        return -1;
                }
                if (created)
                        *created = true;
                fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (fd < 0) {
                if (errno != ENOENT || create)
                        errorf("cannot open safe directory '%s': %s", path, strerror(errno));
                return -1;
        }
        if (check_safe_directory_fd(fd, path) < 0) {
                close(fd);
                return -1;
        }

        return fd;
}

static int open_root(bool create) {
        int run_fd = -1, aos_fd = -1, root_fd = -1;
        struct stat run_st;

        run_fd = open("/run", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (run_fd < 0 || fstat(run_fd, &run_st) < 0 || !S_ISDIR(run_st.st_mode) ||
            run_st.st_uid != 0 || ((run_st.st_mode & 0022) != 0 &&
                                   (run_st.st_mode & S_ISVTX) == 0)) {
                errorf("unsafe /run must be a root-owned directory and writable only when sticky");
                errno = EPERM;
                goto fail;
        }

        aos_fd = open_safe_child(run_fd, "aos", "/run/aos", 0755, create, NULL);
        if (aos_fd < 0)
                goto fail;

        root_fd = open_safe_child(aos_fd, "service-roots", ROOT_PATH, 0755, create, NULL);
        if (root_fd < 0)
                goto fail;

        close(aos_fd);
        close(run_fd);
        return root_fd;

fail:
        if (aos_fd >= 0)
                close(aos_fd);
        if (run_fd >= 0)
                close(run_fd);
        return -1;
}

static int payload_valid(const char *payload) {
        static const char prefix[] = "/nix/store/";
        struct stat st;
        char resolved[PATH_MAX];
        const char *name;

        if (!payload || strncmp(payload, prefix, sizeof(prefix) - 1) != 0) {
                errorf("payload must be an exact /nix/store directory");
                return -1;
        }

        name = payload + sizeof(prefix) - 1;
        if (name[0] == '\0' || strchr(name, '/') || strchr(name, ',') || strchr(name, ':') ||
            strchr(name, '\\')) {
                errorf("payload must name one overlay-safe direct child of /nix/store");
                return -1;
        }
        if (lstat(payload, &st) < 0) {
                errorf("cannot inspect payload '%s': %s", payload, strerror(errno));
                return -1;
        }
        if (!S_ISDIR(st.st_mode)) {
                errorf("payload '%s' is not a non-symlink directory", payload);
                return -1;
        }
        if (!realpath(payload, resolved) || strcmp(payload, resolved) != 0) {
                errorf("payload '%s' is not its exact canonical store path", payload);
                return -1;
        }

        return 0;
}

static int directory_empty(int fd, const char *path) {
        DIR *dir;
        struct dirent *entry;
        int duplicate = dup(fd);

        if (duplicate < 0) {
                errorf("cannot inspect '%s': %s", path, strerror(errno));
                return -1;
        }
        dir = fdopendir(duplicate);
        if (!dir) {
                close(duplicate);
                errorf("cannot inspect '%s': %s", path, strerror(errno));
                return -1;
        }

        errno = 0;
        while ((entry = readdir(dir))) {
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                        closedir(dir);
                        return 0;
                }
        }
        if (errno != 0) {
                int saved = errno;
                closedir(dir);
                errorf("cannot inspect '%s': %s", path, strerror(saved));
                errno = saved;
                return -1;
        }
        closedir(dir);
        return 1;
}

static bool comma_option_has(const char *options, const char *expected) {
        size_t expected_length = strlen(expected);
        const char *cursor = options;

        while (cursor && *cursor) {
                const char *end = strchr(cursor, ',');
                size_t length = end ? (size_t) (end - cursor) : strlen(cursor);

                if (length == expected_length && strncmp(cursor, expected, length) == 0)
                        return true;
                cursor = end ? end + 1 : NULL;
        }

        return false;
}

/* Returns 0 for unmounted, 1 for the exact expected overlay, and -1 for unsafe/malformed. */
static int overlay_mount_state(const char *merged, const char *payload, const char *upper,
                               const char *work) {
        FILE *mountinfo;
        char *line = NULL;
        size_t capacity = 0;
        int result = 0;

        mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!mountinfo) {
                errorf("cannot read mount table: %s", strerror(errno));
                return -1;
        }

        while (getline(&line, &capacity, mountinfo) >= 0) {
                char *save = NULL, *token, *mountpoint = NULL, *mount_options = NULL;
                char *filesystem = NULL, *super_options = NULL;
                unsigned field = 0;

                for (token = strtok_r(line, " \n", &save); token;
                     token = strtok_r(NULL, " \n", &save)) {
                        field++;
                        if (field == 5)
                                mountpoint = token;
                        else if (field == 6)
                                mount_options = token;
                        if (strcmp(token, "-") == 0) {
                                filesystem = strtok_r(NULL, " \n", &save);
                                (void) strtok_r(NULL, " \n", &save);
                                super_options = strtok_r(NULL, " \n", &save);
                                break;
                        }
                }

                if (!mountpoint || strcmp(mountpoint, merged) != 0)
                        continue;

                char lower_option[PATH_MAX + 10];
                char upper_option[PATH_MAX + 10];
                char work_option[PATH_MAX + 10];
                if (snprintf(lower_option, sizeof(lower_option), "lowerdir=%s", payload) < 0 ||
                    snprintf(upper_option, sizeof(upper_option), "upperdir=%s", upper) < 0 ||
                    snprintf(work_option, sizeof(work_option), "workdir=%s", work) < 0 ||
                    !filesystem || strcmp(filesystem, "overlay") != 0 || !mount_options ||
                    !comma_option_has(mount_options, "nodev") ||
                    !comma_option_has(mount_options, "nosuid") || !super_options ||
                    !comma_option_has(super_options, lower_option) ||
                    !comma_option_has(super_options, upper_option) ||
                    !comma_option_has(super_options, work_option)) {
                        errorf("existing mount at '%s' is not the exact trusted overlay", merged);
                        result = -1;
                } else
                        result = 1;
                goto finish;
        }

        if (ferror(mountinfo)) {
                errorf("cannot read mount table: %s", strerror(errno));
                result = -1;
        }

finish:
        free(line);
        fclose(mountinfo);
        return result;
}

static int remove_contents(int fd, const char *path) {
        DIR *dir;
        struct dirent *entry;
        int duplicate = dup(fd);

        if (duplicate < 0)
                return -1;
        dir = fdopendir(duplicate);
        if (!dir) {
                close(duplicate);
                return -1;
        }

        for (;;) {
                struct stat st;
                char child_path[PATH_MAX];

                errno = 0;
                entry = readdir(dir);
                if (!entry) {
                        if (errno != 0) {
                                int saved = errno;
                                closedir(dir);
                                errno = saved;
                                return -1;
                        }
                        break;
                }
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                        continue;
                if (snprintf(child_path, sizeof(child_path), "%s/%s", path, entry->d_name) >=
                    (int) sizeof(child_path)) {
                        errorf("cleanup path below '%s' is too long", path);
                        closedir(dir);
                        errno = ENAMETOOLONG;
                        return -1;
                }
                if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        errorf("cannot inspect cleanup entry '%s': %s", child_path, strerror(errno));
                        closedir(dir);
                        return -1;
                }
                if (S_ISDIR(st.st_mode)) {
                        int child_fd = openat(fd, entry->d_name,
                                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                        if (child_fd < 0 || remove_contents(child_fd, child_path) < 0) {
                                if (child_fd >= 0)
                                        close(child_fd);
                                closedir(dir);
                                return -1;
                        }
                        close(child_fd);
                        if (unlinkat(fd, entry->d_name, AT_REMOVEDIR) < 0) {
                                errorf("cannot remove directory '%s': %s", child_path, strerror(errno));
                                closedir(dir);
                                return -1;
                        }
                } else if (unlinkat(fd, entry->d_name, 0) < 0) {
                        errorf("cannot remove entry '%s': %s", child_path, strerror(errno));
                        closedir(dir);
                        return -1;
                }
        }

        closedir(dir);
        return 0;
}

static int unit_has_only_known_entries(int unit_fd, const char *unit_path) {
        DIR *dir;
        struct dirent *entry;
        int duplicate = dup(unit_fd);

        if (duplicate < 0)
                return -1;
        dir = fdopendir(duplicate);
        if (!dir) {
                close(duplicate);
                return -1;
        }
        while ((entry = readdir(dir))) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
                    strcmp(entry->d_name, "upper") == 0 || strcmp(entry->d_name, "work") == 0 ||
                    strcmp(entry->d_name, "merged") == 0)
                        continue;
                errorf("unsafe unexpected entry '%s/%s'", unit_path, entry->d_name);
                closedir(dir);
                return -1;
        }
        closedir(dir);
        return 0;
}

static int cleanup_unit(int package_fd, const char *package, const char *payload,
                        const char *unit) {
        static const char *children[] = {"merged", "work", "upper"};
        char unit_path[PATH_MAX], upper[PATH_MAX], work[PATH_MAX], merged[PATH_MAX];
        int child_fds[3] = {-1, -1, -1};
        int unit_fd, state, result = -1;

        if (snprintf(unit_path, sizeof(unit_path), ROOT_PATH "/%s/%s", package, unit) >=
                (int) sizeof(unit_path) ||
            snprintf(upper, sizeof(upper), "%s/upper", unit_path) >= (int) sizeof(upper) ||
            snprintf(work, sizeof(work), "%s/work", unit_path) >= (int) sizeof(work) ||
            snprintf(merged, sizeof(merged), "%s/merged", unit_path) >= (int) sizeof(merged)) {
                errorf("service root path is too long");
                return -1;
        }

        unit_fd = open_safe_child(package_fd, unit, unit_path, 0700, false, NULL);
        if (unit_fd < 0)
                return errno == ENOENT ? 0 : -1;
        if (unit_has_only_known_entries(unit_fd, unit_path) < 0) {
                close(unit_fd);
                return -1;
        }

        for (size_t i = 0; i < sizeof(children) / sizeof(children[0]); i++) {
                char child_path[PATH_MAX];

                if (snprintf(child_path, sizeof(child_path), "%s/%s", unit_path, children[i]) >=
                    (int) sizeof(child_path))
                        goto finish;
                child_fds[i] = open_safe_child(unit_fd, children[i], child_path, 0700, false, NULL);
                if (child_fds[i] < 0 && errno != ENOENT)
                        goto finish;
        }

        state = overlay_mount_state(merged, payload, upper, work);
        if (state < 0)
                goto finish;
        if (state > 0) {
                if (child_fds[0] < 0 || child_fds[1] < 0 || child_fds[2] < 0) {
                        errorf("trusted overlay '%s' has missing backing components", merged);
                        goto finish;
                }
                close(child_fds[0]);
                child_fds[0] = -1;
                if (umount2(merged, 0) < 0) {
                        errorf("cannot unmount exact trusted overlay '%s': %s", merged, strerror(errno));
                        goto finish;
                }
                child_fds[0] = open_safe_child(unit_fd, "merged", merged, 0700, false, NULL);
                if (child_fds[0] < 0)
                        goto finish;
        }

        for (size_t i = 0; i < sizeof(children) / sizeof(children[0]); i++) {
                char child_path[PATH_MAX];

                if (snprintf(child_path, sizeof(child_path), "%s/%s", unit_path, children[i]) >=
                    (int) sizeof(child_path))
                        goto finish;
                if (child_fds[i] < 0)
                        continue;
                if (remove_contents(child_fds[i], child_path) < 0)
                        goto finish;
                close(child_fds[i]);
                child_fds[i] = -1;
                if (unlinkat(unit_fd, children[i], AT_REMOVEDIR) < 0) {
                        errorf("cannot remove '%s': %s", child_path, strerror(errno));
                        goto finish;
                }
        }

        if (unlinkat(package_fd, unit, AT_REMOVEDIR) < 0) {
                errorf("cannot remove '%s': %s", unit_path, strerror(errno));
                goto finish;
        }
        result = 0;

finish:
        for (size_t i = 0; i < sizeof(child_fds) / sizeof(child_fds[0]); i++)
                if (child_fds[i] >= 0)
                        close(child_fds[i]);
        close(unit_fd);
        return result;
}

static int prepare_unit(int package_fd, const char *package, const char *payload,
                        const char *unit, bool *mounted) {
        char unit_path[PATH_MAX], upper[PATH_MAX], work[PATH_MAX], merged[PATH_MAX];
        char options[PATH_MAX * 3];
        int unit_fd = -1, upper_fd = -1, work_fd = -1, merged_fd = -1;
        bool unit_created = false, upper_created = false, work_created = false;
        bool merged_created = false;
        int state;

        *mounted = false;
        if (snprintf(unit_path, sizeof(unit_path), ROOT_PATH "/%s/%s", package, unit) >=
                (int) sizeof(unit_path) ||
            snprintf(upper, sizeof(upper), "%s/upper", unit_path) >= (int) sizeof(upper) ||
            snprintf(work, sizeof(work), "%s/work", unit_path) >= (int) sizeof(work) ||
            snprintf(merged, sizeof(merged), "%s/merged", unit_path) >= (int) sizeof(merged)) {
                errorf("service root path is too long");
                return -1;
        }

        unit_fd = open_safe_child(package_fd, unit, unit_path, 0700, true, &unit_created);
        if (unit_fd < 0 || unit_has_only_known_entries(unit_fd, unit_path) < 0)
                goto fail;
        upper_fd = open_safe_child(unit_fd, "upper", upper, 0700, true, &upper_created);
        work_fd = open_safe_child(unit_fd, "work", work, 0700, true, &work_created);
        merged_fd = open_safe_child(unit_fd, "merged", merged, 0700, true, &merged_created);
        if (upper_fd < 0 || work_fd < 0 || merged_fd < 0)
                goto fail;

        state = overlay_mount_state(merged, payload, upper, work);
        if (state < 0)
                goto fail;
        if (state > 0) {
                close(merged_fd);
                close(work_fd);
                close(upper_fd);
                close(unit_fd);
                return 0;
        }

        if (directory_empty(upper_fd, upper) != 1 || directory_empty(work_fd, work) != 1 ||
            directory_empty(merged_fd, merged) != 1) {
                errorf("unmounted service root '%s' is not empty", unit_path);
                goto fail;
        }
        if (snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s", payload,
                     upper, work) >= (int) sizeof(options)) {
                errorf("overlay options are too long");
                goto fail;
        }
        if (mount("overlay", merged, "overlay", MS_NODEV | MS_NOSUID, options) < 0) {
                errorf("cannot mount trusted overlay at '%s': %s", merged, strerror(errno));
                goto fail;
        }
        *mounted = true;
        if (overlay_mount_state(merged, payload, upper, work) != 1) {
                (void) umount2(merged, 0);
                *mounted = false;
                goto fail;
        }

        close(merged_fd);
        close(work_fd);
        close(upper_fd);
        close(unit_fd);
        return 0;

fail:
        if (*mounted) {
                (void) umount2(merged, 0);
                *mounted = false;
        }
        if (merged_fd >= 0)
                close(merged_fd);
        if (work_fd >= 0)
                close(work_fd);
        if (upper_fd >= 0)
                close(upper_fd);
        if (unit_fd >= 0)
                close(unit_fd);
        if (unit_created)
                (void) cleanup_unit(package_fd, package, payload, unit);
        else {
                struct {
                        const char *name;
                        bool created;
                } created_children[] = {
                    {"merged", merged_created},
                    {"work", work_created},
                    {"upper", upper_created},
                };

                unit_fd = open_safe_child(package_fd, unit, unit_path, 0700, false, NULL);
                if (unit_fd >= 0) {
                        for (size_t i = 0;
                             i < sizeof(created_children) / sizeof(created_children[0]); i++)
                                if (created_children[i].created)
                                        (void) unlinkat(unit_fd, created_children[i].name, AT_REMOVEDIR);
                        close(unit_fd);
                }
        }
        return -1;
}

static int command_prepare(int argc, char **argv) {
        const char *package = argv[2], *payload = argv[3];
        bool *mounted = NULL;
        int root_fd = -1, package_fd = -1;
        int result = 1;

        if (!token_valid(package)) {
                errorf("invalid package token '%s'", package);
                return 1;
        }
        if (payload_valid(payload) < 0)
                return 1;
        for (int i = 4; i < argc; i++) {
                if (!token_valid(argv[i])) {
                        errorf("invalid unit token '%s'", argv[i]);
                        return 1;
                }
                for (int j = 4; j < i; j++)
                        if (strcmp(argv[i], argv[j]) == 0) {
                                errorf("duplicate unit token '%s'", argv[i]);
                                return 1;
                        }
        }

        mounted = calloc((size_t) argc, sizeof(*mounted));
        if (!mounted) {
                errorf("out of memory");
                return 1;
        }
        root_fd = open_root(true);
        if (root_fd < 0)
                goto finish;
        char package_path[PATH_MAX];
        if (snprintf(package_path, sizeof(package_path), ROOT_PATH "/%s", package) >=
            (int) sizeof(package_path))
                goto finish;
        package_fd = open_safe_child(root_fd, package, package_path, 0700, true, NULL);
        if (package_fd < 0)
                goto finish;

        for (int i = 4; i < argc; i++) {
                if (prepare_unit(package_fd, package, payload, argv[i], &mounted[i]) < 0) {
                        for (int j = i - 1; j >= 4; j--)
                                if (mounted[j])
                                        (void) cleanup_unit(package_fd, package, payload, argv[j]);
                        goto finish;
                }
        }
        result = 0;

finish:
        if (package_fd >= 0)
                close(package_fd);
        if (root_fd >= 0)
                close(root_fd);
        free(mounted);
        return result;
}

static bool requested_unit(int argc, char **argv, const char *unit) {
        for (int i = 4; i < argc; i++)
                if (strcmp(argv[i], unit) == 0)
                        return true;
        return false;
}

static int package_has_only_requested_units(int package_fd, const char *package_path,
                                            int argc, char **argv) {
        DIR *dir;
        struct dirent *entry;
        int duplicate = dup(package_fd);

        if (duplicate < 0)
                return -1;
        dir = fdopendir(duplicate);
        if (!dir) {
                close(duplicate);
                return -1;
        }
        for (;;) {
                errno = 0;
                entry = readdir(dir);
                if (!entry) {
                        int saved = errno;
                        closedir(dir);
                        errno = saved;
                        return saved == 0 ? 0 : -1;
                }
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                        continue;
                if (!token_valid(entry->d_name) ||
                    !requested_unit(argc, argv, entry->d_name)) {
                        errorf("unexpected unit entry '%s/%s' is outside cleanup authority",
                               package_path, entry->d_name);
                        closedir(dir);
                        return -1;
                }
        }
}

static int command_cleanup(int argc, char **argv) {
        const char *package = argv[2], *payload = argv[3];
        int root_fd, package_fd;
        char package_path[PATH_MAX];
        int result = 1;

        if (!token_valid(package)) {
                errorf("invalid package token '%s'", package);
                return 1;
        }
        if (payload_valid(payload) < 0)
                return 1;
        for (int i = 4; i < argc; i++) {
                if (!token_valid(argv[i])) {
                        errorf("invalid unit token '%s'", argv[i]);
                        return 1;
                }
                for (int j = 4; j < i; j++)
                        if (strcmp(argv[i], argv[j]) == 0) {
                                errorf("duplicate unit token '%s'", argv[i]);
                                return 1;
                        }
        }
        root_fd = open_root(false);
        if (root_fd < 0)
                return errno == ENOENT ? 0 : 1;
        if (snprintf(package_path, sizeof(package_path), ROOT_PATH "/%s", package) >=
            (int) sizeof(package_path)) {
                close(root_fd);
                return 1;
        }
        package_fd = open_safe_child(root_fd, package, package_path, 0700, false, NULL);
        if (package_fd < 0) {
                int saved = errno;
                close(root_fd);
                return saved == ENOENT ? 0 : 1;
        }

        if (package_has_only_requested_units(package_fd, package_path, argc, argv) < 0)
                goto finish;
        for (int i = 4; i < argc; i++)
                if (cleanup_unit(package_fd, package, payload, argv[i]) < 0)
                        goto finish;
        if (unlinkat(root_fd, package, AT_REMOVEDIR) < 0 && errno != ENOENT) {
                errorf("cannot remove '%s': %s", package_path, strerror(errno));
                goto finish;
        }
        result = 0;

finish:
        close(package_fd);
        close(root_fd);
        return result;
}

static void usage(void) {
        fputs("usage: aos-service-root prepare PACKAGE PAYLOAD UNIT...\n"
              "       aos-service-root cleanup PACKAGE PAYLOAD UNIT...\n",
              stderr);
}

int main(int argc, char **argv) {
        if (geteuid() != 0) {
                errorf("must run as root");
                return 1;
        }
        if (argc >= 5 && strcmp(argv[1], "prepare") == 0)
                return command_prepare(argc, argv);
        if (argc >= 5 && strcmp(argv[1], "cleanup") == 0)
                return command_cleanup(argc, argv);

        usage();
        return 2;
}
