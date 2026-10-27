/* Closed same-PID pure-worker profile. Included after the ordinary Landlock
 * helpers so their established filesystem rules are reused without changing
 * the ordinary command modes. No worker/untrusted input is read until every
 * control below is installed. The trusted launcher/loader startup is a
 * separately admitted fixed artifact, not claimed to start inside the cgroup. */
#include <limits.h>
#include <linux/capability.h>
#include <seccomp.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/statfs.h>
#include <grp.h>

_Static_assert(ULLONG_MAX == UINT64_MAX, "pure-worker requires 64-bit unsigned long long");

#define PURE_WORKER_MAX_PATHS 128
#define PURE_WORKER_CGROUP2_MAGIC 0x63677270

static int worker_reject(const char *stage)
{
    /* Never disclose the original request, private paths or arbitrary bytes. */
    fprintf(stderr, "aos-landlock: pure-worker-v1 %s failed\n", stage);
    return 125;
}

static int worker_u64(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (text[0] < '0' || text[0] > '9') {
        return -1;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno || end == text || *end) {
        return -1;
    }
    *out = (uint64_t)value;
    return 0;
}

static int worker_limit(int resource, uint64_t value)
{
    struct rlimit limit = {.rlim_cur = (rlim_t)value, .rlim_max = (rlim_t)value};

    if ((uint64_t)limit.rlim_cur != value || value == RLIM_INFINITY) {
        return -1;
    }
    return setrlimit(resource, &limit);
}

static int worker_control_matches(int group, const char *name, const char *expected)
{
    char buffer[96];
    int fd = openat(group, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t count;

    if (fd < 0) {
        return -1;
    }
    count = read(fd, buffer, sizeof(buffer));
    close(fd);
    return count >= 0 && (size_t)count == strlen(expected)
            && memcmp(buffer, expected, (size_t)count) == 0 ? 0 : -1;
}

static int worker_attach(const char *path, uint64_t device, uint64_t inode,
    uint64_t memory)
{
    struct stat metadata;
    struct statfs filesystem;
    char memory_text[32];
    int group = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    int control;
    ssize_t written;

    if (group < 0) {
        return -1;
    }
    if (fstat(group, &metadata) || fstatfs(group, &filesystem)
        || (uint64_t)metadata.st_dev != device || (uint64_t)metadata.st_ino != inode
        || filesystem.f_type != PURE_WORKER_CGROUP2_MAGIC) {
        close(group);
        return -1;
    }
    snprintf(memory_text, sizeof(memory_text), "%llu\n", (unsigned long long)memory);
    if (worker_control_matches(group, "cpu.max", "100000 100000\n")
        || worker_control_matches(group, "memory.max", memory_text)
        || worker_control_matches(group, "memory.swap.max", "0\n")
        || worker_control_matches(group, "pids.max", "1\n")) {
        close(group);
        return -1;
    }
    control = openat(group, "cgroup.procs", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    close(group);
    if (control < 0) {
        return -1;
    }
    written = write(control, "0\n", 2);
    close(control);
    return written == 2 ? 0 : -1;
}

static int worker_syscalls(int worker_fd)
{
    /* Native-only default-deny profile for the measured ordinary ELF loader,
     * allocator and pure stdio algorithm. In particular no socket/io_uring,
     * clone/fork, ptrace, process-vm, mount, namespace, signal-other or ioctl
     * syscall is admitted. Initial exec remains allowed only within Landlock's
     * read/execute closure; this does not claim a one-exec-only property. */
    static const char *const calls[] = {
        "read", "write", "readv", "writev", "close", "fstat", "newfstatat",
        "statx", "lseek", "pread64", "preadv", "preadv2", "open", "openat",
        "openat2", "access", "faccessat", "faccessat2", "readlink", "readlinkat",
        "getdents64", "mprotect", "munmap", "mremap", "madvise",
        "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack",
        "futex", "futex_time64", "set_tid_address", "set_robust_list", "rseq",
        "arch_prctl", "clock_gettime", "clock_gettime64", "clock_getres",
        "nanosleep", "clock_nanosleep", "clock_nanosleep_time64", "getpid", "gettid",
        "getuid", "geteuid", "getgid", "getegid", "getresuid", "getresgid",
        "prlimit64", "getrlimit", "getrusage", "uname", "sched_getaffinity",
        "sched_yield", "fcntl", "fcntl64", "getrandom", "execve", "exit",
        "exit_group", "restart_syscall"
    };
    scmp_filter_ctx filter = seccomp_init(SCMP_ACT_ERRNO(EPERM));
    size_t i;
    int result = -1;

    if (!filter) {
        return -1;
    }
    for (i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
        int number = seccomp_syscall_resolve_name(calls[i]);
        /* An absent syscall on the selected native architecture cannot run.
         * No extra architecture is added to the filter. */
        if (number == __NR_SCMP_ERROR) {
            continue;
        }
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, number, 0)) {
            goto done;
        }
    }
    /* Rust checks its three inherited standard descriptors before main. Admit
     * that nonblocking census without allowing a worker-selected wait. The
     * closed profile already requires all three descriptors to be disk files. */
    {
        int number = seccomp_syscall_resolve_name("poll");
        if (number != __NR_SCMP_ERROR && seccomp_rule_add(filter, SCMP_ACT_ALLOW,
                number, 2, SCMP_A1(SCMP_CMP_LE, 3), SCMP_A2(SCMP_CMP_EQ, 0))) {
            goto done;
        }
    }
    /* HugeTLB uses accounting outside memory.max. Refuse that alternate
     * allocation population without relying on the host's hugetlb group. */
    for (i = 0; i < 2; i++) {
        int number = seccomp_syscall_resolve_name(i == 0 ? "mmap" : "mmap2");
        if (number != __NR_SCMP_ERROR && seccomp_rule_add(filter, SCMP_ACT_ALLOW,
                number, 1, SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_HUGETLB, 0))) {
            goto done;
        }
    }
    if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 2,
            SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)worker_fd),
            SCMP_A4(SCMP_CMP_EQ, AT_EMPTY_PATH))) {
        goto done;
    }
    result = seccomp_load(filter);
done:
    seccomp_release(filter);
    return result;
}

static int run_pure_worker(int argc, char **argv)
{
    /* 0 helper,1 mode,2 group,3 dev,4 ino,5 uid,6 gid,7 cpu,8 memory,
     * 9 address-space,10 nofile,11 fsize,12 worker,13 worker-dev,14 worker-ino,
     * 15 input,16 elements,17 banks,18 diagnostic,19 worker-digest,20 algorithm-digest,21 --,
     * 22.. readonly roots. */
    uint64_t values[9];
    uint64_t request_limits[4];
    struct path_list paths = {0};
    struct port_list no_ports = {0};
    struct stat input, output, diagnostic;
    char *worker_argv[14];
    int i;
    int worker_fd;
    struct stat worker_stat;
    uint64_t worker_dev, worker_ino;
    char *const empty_environment[] = {NULL};
    struct __user_cap_header_struct cap_header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct capabilities[2] = {{0}, {0}};
    uid_t real_uid, effective_uid, saved_uid;
    gid_t real_gid, effective_gid, saved_gid;

    if (argc < 23 || argc > 22 + PURE_WORKER_MAX_PATHS || strcmp(argv[21], "--")) {
        return worker_reject("arguments");
    }
    for (i = 19; i <= 20; i++) {
        size_t digit;
        if (strlen(argv[i]) != 64) {
            return worker_reject("identity claims");
        }
        for (digit = 0; digit < 64; digit++) {
            if (!((argv[i][digit] >= '0' && argv[i][digit] <= '9')
                || (argv[i][digit] >= 'a' && argv[i][digit] <= 'f'))) {
                return worker_reject("identity claims");
            }
        }
    }
    for (i = 0; i < 9; i++) {
        if (worker_u64(argv[i + 3], &values[i])) {
            return worker_reject("limits");
        }
    }
    for (i = 0; i < 4; i++) {
        if (worker_u64(argv[i + 15], &request_limits[i]) || !request_limits[i]) {
            return worker_reject("request limits");
        }
    }
    if (getresuid(&real_uid, &effective_uid, &saved_uid)
        || getresgid(&real_gid, &effective_gid, &saved_gid)) {
        return worker_reject("supervisor credentials");
    }
    if (values[2] == real_uid || values[2] == effective_uid || values[2] == saved_uid
        || values[3] == real_gid || values[3] == effective_gid || values[3] == saved_gid
        || !values[2] || !values[3] || (uid_t)values[2] != values[2]
        || (gid_t)values[3] != values[3] || !values[4] || !values[5]
        || !values[6] || values[7] < 16 || !values[8] || argv[12][0] != '/'
        || worker_u64(argv[13], &worker_dev) || worker_u64(argv[14], &worker_ino)) {
        return worker_reject("limits");
    }
    if (fstat(STDIN_FILENO, &input) || !S_ISREG(input.st_mode)
        || input.st_size < 0 || (uint64_t)input.st_size > request_limits[0]
        || (fcntl(STDIN_FILENO, F_GETFL) & O_ACCMODE) != O_RDONLY) {
        return worker_reject("independent readonly input");
    }
    if (fstat(STDOUT_FILENO, &output) || fstat(STDERR_FILENO, &diagnostic)
        || !S_ISREG(output.st_mode) || !S_ISREG(diagnostic.st_mode)
        || output.st_size != 0 || diagnostic.st_size != 0
        || input.st_dev != output.st_dev || input.st_dev != diagnostic.st_dev
        || input.st_ino == output.st_ino || input.st_ino == diagnostic.st_ino
        || output.st_ino == diagnostic.st_ino
        || (fcntl(STDOUT_FILENO, F_GETFL) & O_ACCMODE) == O_RDONLY
        || (fcntl(STDERR_FILENO, F_GETFL) & O_ACCMODE) == O_RDONLY) {
        return worker_reject("independent disk output");
    }
    if (syscall(__NR_close_range, 3U, UINT_MAX, 0U) || clearenv()
        || chdir("/") || worker_attach(argv[2], values[0], values[1], values[5])) {
        return worker_reject("cgroup or descriptor setup");
    }
    if (worker_limit(RLIMIT_CPU, values[4]) || worker_limit(RLIMIT_AS, values[6])
        || worker_limit(RLIMIT_NOFILE, values[7]) || worker_limit(RLIMIT_FSIZE, values[8])
        || worker_limit(RLIMIT_CORE, 0)) {
        return worker_reject("hard limits");
    }
    worker_fd = open(argv[12], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (worker_fd < 0 || fstat(worker_fd, &worker_stat)
        || !S_ISREG(worker_stat.st_mode) || (uint64_t)worker_stat.st_dev != worker_dev
        || (uint64_t)worker_stat.st_ino != worker_ino) {
        return worker_reject("opened worker identity");
    }
    for (i = 22; i < argc; i++) {
        if (strlen(argv[i]) > 4096 || add_path(&paths, argv[i], FS_READ_ACCESS)) {
            return worker_reject("readonly runtime closure");
        }
    }
    if (setgroups(0, NULL) || setresgid((gid_t)values[3], (gid_t)values[3], (gid_t)values[3])
        || setresuid((uid_t)values[2], (uid_t)values[2], (uid_t)values[2])) {
        return worker_reject("credentials");
    }
    /* Explicitly clear inherited capability state rather than depending on
     * the supervisor's securebits/keepcaps configuration. NNP and Landlock are
     * then installed before the first worker instruction. */
    if (syscall(__NR_capset, &cap_header, capabilities)
        || prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        || apply_landlock(4, 1, &no_ports, &no_ports, &paths) || worker_syscalls(worker_fd)) {
        return worker_reject("filesystem or syscall confinement");
    }
    worker_argv[0] = argv[12];
    worker_argv[1] = "--worker-digest";
    worker_argv[2] = argv[19];
    worker_argv[3] = "--algorithm-digest";
    worker_argv[4] = argv[20];
    worker_argv[5] = "--maximum-input-bytes";
    worker_argv[6] = argv[15];
    worker_argv[7] = "--maximum-elements";
    worker_argv[8] = argv[16];
    worker_argv[9] = "--maximum-output-bytes";
    worker_argv[10] = argv[17];
    worker_argv[11] = "--maximum-diagnostic-bytes";
    worker_argv[12] = argv[18];
    worker_argv[13] = NULL;
    syscall(__NR_execveat, worker_fd, "", worker_argv, empty_environment, AT_EMPTY_PATH);
    return worker_reject("worker exec");
}
