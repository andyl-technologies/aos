/* SPDX-License-Identifier: Apache-2.0 */
#define main nspawn_host_observer_entry_point
#include "nspawn-host-observer.c"
#undef main

static int expect_retry(const char *operation, const char *path, int error_number,
                        int old_alive, int supervisor_is_alive, bool expected) {
        const char *cgroup =
                "/aos.slice/aos-sandboxes.slice/aos-nspawn-platform-proof.service/payload";
        struct scan_failure failure = {
                .operation = operation,
                .pid = 0,
                .error_number = error_number,
        };
        bool observed;

        if (snprintf(failure.path, sizeof(failure.path), "%s", path) < 0)
                return 1;
        observed = can_retry_discovery_failure(cgroup, &failure, old_alive,
                                               supervisor_is_alive);
        if (observed != expected) {
                fprintf(stderr,
                        "retry policy mismatch: operation=%s path=%s errno=%d "
                        "old_alive=%d supervisor_alive=%d observed=%d expected=%d\n",
                        operation, path, error_number, old_alive,
                        supervisor_is_alive, observed, expected);
                return 1;
        }
        return 0;
}

int main(void) {
        const char *root =
                "/sys/fs/cgroup/aos.slice/aos-sandboxes.slice/"
                "aos-nspawn-platform-proof.service/payload";
        const char *interior =
                "/sys/fs/cgroup/aos.slice/aos-sandboxes.slice/"
                "aos-nspawn-platform-proof.service/payload/aos-stale-empty/memory.min";
        const char *prefix_collision =
                "/sys/fs/cgroup/aos.slice/aos-sandboxes.slice/"
                "aos-nspawn-platform-proof.service/payload-other/memory.min";
        const char *operations[] = {
                "open-cgroup-directory",
                "read-cgroup-directory",
                "stat-cgroup-entry",
                "open-cgroup-procs",
                "read-cgroup-procs",
                "read-candidate-status",
        };
        size_t index;

        for (index = 0; index < sizeof(operations) / sizeof(operations[0]); index++)
                if (expect_retry(operations[index], interior, ENOENT, 1, 1, true) != 0)
                        return EXIT_FAILURE;

        if (expect_retry("open-cgroup-directory", root, ENOENT, 1, 1, false) != 0 ||
            expect_retry("open-cgroup-directory", root, ENOENT, 0, 1, true) != 0 ||
            expect_retry("read-cgroup-directory", root, ENOENT, 0, 1, true) != 0 ||
            expect_retry("stat-cgroup-entry", root, ENOENT, 0, 1, false) != 0 ||
            expect_retry("stat-cgroup-entry", prefix_collision, ENOENT, 0, 1, false) != 0 ||
            expect_retry("parse-cgroup-procs", interior, ENOENT, 0, 1, false) != 0 ||
            expect_retry("stat-cgroup-entry", interior, EACCES, 1, 1, false) != 0 ||
            expect_retry("stat-cgroup-entry", interior, ENOENT, 1, 0, false) != 0 ||
            discovered_new_candidate(-1, 200, 100) ||
            discovered_new_candidate(1, 100, 100) ||
            !discovered_new_candidate(1, 200, 100))
                return EXIT_FAILURE;

        puts("nspawn host observer scan retry regression: PASS");
        return EXIT_SUCCESS;
}
