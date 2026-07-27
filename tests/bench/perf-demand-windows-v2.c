#define _GNU_SOURCE

#include <errno.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * External Linux PMU owner for AOS demand-window protocol version 2.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -Werror -std=c11 \
 *     tests/bench/perf-demand-windows-v2.c -o /tmp/aos-perf-demand-v2
 *
 * Run:
 *   /tmp/aos-perf-demand-v2 COMMAND [ARG...]
 *
 * The child receives AOS_NIX_DEMAND_EPOCH_{CONTROL,ACK}_FD and
 * AOS_NIX_DEMAND_EPOCH_PROTOCOL=2. This controller accepts any number of
 * sequential sessions and N/B/E packets. It attaches an inherited perf group
 * to the stopped child, excludes kernel/hypervisor work, and returns exact
 * grouped user instructions and cycles in every C response. Counts are
 * monotone end-minus-start deltas; no reset ioctl is used, because reset
 * semantics for already-aggregated inherited tasks are not an authority
 * boundary.
 */

enum {
    PROTOCOL_VERSION = 2,
    HEADER_BYTES = 20,
    COUNT_REPLY_BYTES = 36,
    KIND_AUTO_CALL_4 = 1,
    KIND_FINAL_FORCE_5 = 2,
};

_Static_assert(sizeof(uint64_t) == 8, "protocol requires 64-bit uint64_t");
_Static_assert(HEADER_BYTES == 4 + 2 * (int)sizeof(uint64_t),
               "protocol header layout changed");
_Static_assert(COUNT_REPLY_BYTES == HEADER_BYTES + 2 * (int)sizeof(uint64_t),
               "protocol count reply layout changed");

struct packet {
    uint8_t opcode;
    uint8_t version;
    uint8_t kind;
    uint64_t session;
    uint64_t window;
};

struct counts {
    uint64_t instructions;
    uint64_t cycles;
};

struct totals {
    uint64_t windows;
    uint64_t instructions;
    uint64_t cycles;
};

static int send_counter_fds(int socket_fd, int instructions, int cycles) {
    char payload = 'P';
    struct iovec io = {.iov_base = &payload, .iov_len = sizeof(payload)};
    char control[CMSG_SPACE(2 * sizeof(int))];
    struct msghdr message;
    struct cmsghdr *header;
    int descriptors[2] = {instructions, cycles};
    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(descriptors));
    memcpy(CMSG_DATA(header), descriptors, sizeof(descriptors));
    message.msg_controllen = header->cmsg_len;
    if (sendmsg(socket_fd, &message, 0) != (ssize_t)sizeof(payload)) {
        fprintf(stderr, "aos-perf-demand-v2: send counter descriptors: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int receive_counter_fds(int socket_fd, int descriptors[2]) {
    char payload = 0;
    struct iovec io = {.iov_base = &payload, .iov_len = sizeof(payload)};
    char control[CMSG_SPACE(2 * sizeof(int))];
    struct msghdr message;
    struct cmsghdr *header;
    memset(&message, 0, sizeof(message));
    memset(control, 0, sizeof(control));
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    if (recvmsg(socket_fd, &message, 0) != (ssize_t)sizeof(payload)
        || payload != 'P') {
        fprintf(stderr, "aos-perf-demand-v2: receive counter descriptors: %s\n",
                strerror(errno));
        return -1;
    }
    header = CMSG_FIRSTHDR(&message);
    if (header == NULL || header->cmsg_level != SOL_SOCKET
        || header->cmsg_type != SCM_RIGHTS
        || header->cmsg_len != CMSG_LEN(2 * sizeof(int))) {
        fprintf(stderr,
                "aos-perf-demand-v2: malformed counter descriptor message\n");
        return -1;
    }
    memcpy(descriptors, CMSG_DATA(header), 2 * sizeof(int));
    return 0;
}

static uint64_t load_u64_le(const uint8_t *bytes) {
    uint64_t value = 0;
    unsigned int index;
    for (index = 0; index < 8; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8);
    }
    return value;
}

static void store_u64_le(uint8_t *bytes, uint64_t value) {
    unsigned int index;
    for (index = 0; index < 8; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8));
    }
}

static int decode_packet(const uint8_t bytes[HEADER_BYTES], struct packet *packet) {
    if (bytes[1] != PROTOCOL_VERSION || bytes[3] != 0) {
        return -1;
    }
    packet->opcode = bytes[0];
    packet->version = bytes[1];
    packet->kind = bytes[2];
    packet->session = load_u64_le(bytes + 4);
    packet->window = load_u64_le(bytes + 12);
    if (packet->session == 0
        || (packet->kind != KIND_AUTO_CALL_4
            && packet->kind != KIND_FINAL_FORCE_5)) {
        return -1;
    }
    return 0;
}

static void encode_header(uint8_t bytes[HEADER_BYTES], uint8_t opcode,
                          const struct packet *packet) {
    memset(bytes, 0, HEADER_BYTES);
    bytes[0] = opcode;
    bytes[1] = PROTOCOL_VERSION;
    bytes[2] = packet->kind;
    store_u64_le(bytes + 4, packet->session);
    store_u64_le(bytes + 12, packet->window);
}

static int read_full(int fd, void *buffer, size_t length, int allow_initial_eof) {
    uint8_t *bytes = buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t amount = read(fd, bytes + offset, length - offset);
        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount == 0 && allow_initial_eof && offset == 0) {
            return 0;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        if (amount == 0) {
            fprintf(stderr, "aos-perf-demand-v2: short read after %zu/%zu bytes\n",
                    offset, length);
            if (offset > 0 && length == HEADER_BYTES) {
                fprintf(stderr,
                        "aos-perf-demand-v2: truncated header prefix opcode=0x%02x"
                        " version=0x%02x kind=0x%02x reserved=0x%02x\n",
                        bytes[0], offset > 1 ? bytes[1] : 0,
                        offset > 2 ? bytes[2] : 0,
                        offset > 3 ? bytes[3] : 0);
            }
        } else {
            fprintf(stderr, "aos-perf-demand-v2: read: %s\n", strerror(errno));
        }
        return -1;
    }
    return 1;
}

static int write_full(int fd, const void *buffer, size_t length) {
    const uint8_t *bytes = buffer;
    size_t offset = 0;
    while (offset < length) {
        ssize_t amount = write(fd, bytes + offset, length - offset);
        if (amount > 0) {
            offset += (size_t)amount;
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        fprintf(stderr, "aos-perf-demand-v2: write: %s\n",
                amount == 0 ? "zero-length write" : strerror(errno));
        return -1;
    }
    return 0;
}

static int send_ack(int fd, const struct packet *packet) {
    uint8_t response[HEADER_BYTES];
    encode_header(response, 'A', packet);
    return write_full(fd, response, sizeof(response));
}

static int send_counts(int fd, const struct packet *packet,
                       const struct counts *counts) {
    uint8_t response[COUNT_REPLY_BYTES];
    encode_header(response, 'C', packet);
    store_u64_le(response + HEADER_BYTES, counts->instructions);
    store_u64_le(response + HEADER_BYTES + 8, counts->cycles);
    return write_full(fd, response, sizeof(response));
}

static int open_counter(pid_t pid, uint64_t config, int group_fd,
                        int inherit_tasks) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = group_fd == -1;
    attr.inherit = inherit_tasks;
    attr.inherit_stat = inherit_tasks;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    return (int)syscall(SYS_perf_event_open, &attr, pid, -1, group_fd, 0);
}

static int enable_group(int leader) {
    if (ioctl(leader, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) < 0) {
        fprintf(stderr, "aos-perf-demand-v2: PERF_EVENT_IOC_ENABLE: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int disable_group(int leader) {
    if (ioctl(leader, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP) < 0) {
        fprintf(stderr, "aos-perf-demand-v2: PERF_EVENT_IOC_DISABLE: %s\n",
                strerror(errno));
        return -1;
    }
    return 0;
}

static int read_group(int leader, int member, struct counts *counts) {
    if (read_full(leader, &counts->cycles, sizeof(counts->cycles), 0) != 1
        || read_full(member, &counts->instructions,
                     sizeof(counts->instructions), 0)
               != 1) {
        fprintf(stderr, "aos-perf-demand-v2: counter-group member read failed\n");
        return -1;
    }
    return 0;
}

static int subtract_counts(const struct counts *end, const struct counts *start,
                           struct counts *difference) {
    if (end->instructions < start->instructions || end->cycles < start->cycles) {
        fprintf(stderr, "aos-perf-demand-v2: non-monotone grouped counters\n");
        return -1;
    }
    difference->instructions = end->instructions - start->instructions;
    difference->cycles = end->cycles - start->cycles;
    return 0;
}

static int monotonic_ns(uint64_t *value) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &time) < 0) {
        fprintf(stderr, "aos-perf-demand-v2: clock_gettime: %s\n",
                strerror(errno));
        return -1;
    }
    *value = (uint64_t)time.tv_sec * UINT64_C(1000000000)
             + (uint64_t)time.tv_nsec;
    return 0;
}

static int add_totals(struct totals *totals, const struct counts *counts) {
    if (totals->windows == UINT64_MAX
        || UINT64_MAX - totals->instructions < counts->instructions
        || UINT64_MAX - totals->cycles < counts->cycles) {
        fprintf(stderr, "aos-perf-demand-v2: aggregate counter overflow\n");
        return -1;
    }
    totals->windows += 1;
    totals->instructions += counts->instructions;
    totals->cycles += counts->cycles;
    return 0;
}

static int packet_equal(const struct packet *left, const struct packet *right) {
    return left->version == right->version && left->kind == right->kind
           && left->session == right->session && left->window == right->window;
}

static int reap_after_kill(pid_t child) {
    int status;
    if (kill(child, SIGKILL) < 0 && errno != ESRCH) {
        fprintf(stderr, "aos-perf-demand-v2: kill child: %s\n", strerror(errno));
    }
    for (;;) {
        pid_t result = waitpid(child, &status, 0);
        if (result == child) {
            return 0;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0 && errno == ECHILD) {
            return 0;
        }
        fprintf(stderr, "aos-perf-demand-v2: reap child: %s\n", strerror(errno));
        return -1;
    }
}

static int wait_for_stop(pid_t child) {
    int status;
    for (;;) {
        pid_t result = waitpid(child, &status, WUNTRACED);
        if (result == child) {
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
                return 0;
            }
            fprintf(stderr, "aos-perf-demand-v2: child did not stop as requested\n");
            return -1;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        fprintf(stderr, "aos-perf-demand-v2: wait for child stop: %s\n",
                strerror(errno));
        return -1;
    }
}

static int wait_for_exit(pid_t child, int *status, struct rusage *usage) {
    for (;;) {
        pid_t result = wait4(child, status, 0, usage);
        if (result == child) {
            return 0;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        fprintf(stderr, "aos-perf-demand-v2: wait4 child: %s\n", strerror(errno));
        return -1;
    }
}

static int self_test(void) {
    uint8_t encoded[HEADER_BYTES];
    struct packet input;
    struct packet output;
    struct counts start = {100, 200};
    struct counts end = {130, 250};
    struct counts difference;
    input.opcode = 'B';
    input.version = PROTOCOL_VERSION;
    input.kind = KIND_FINAL_FORCE_5;
    input.session = UINT64_C(0x0102030405060708);
    input.window = UINT64_C(0x1112131415161718);
    encode_header(encoded, input.opcode, &input);
    if (decode_packet(encoded, &output) < 0 || !packet_equal(&input, &output)
        || encoded[4] != 0x08 || encoded[11] != 0x01 || encoded[12] != 0x18
        || encoded[19] != 0x11) {
        fprintf(stderr, "aos-perf-demand-v2: protocol layout self-test failed\n");
        return 2;
    }
    if (subtract_counts(&end, &start, &difference) < 0
        || difference.instructions != 30 || difference.cycles != 50) {
        fprintf(stderr, "aos-perf-demand-v2: monotone delta self-test failed\n");
        return 2;
    }
    fprintf(stderr, "aos-perf-demand-v2: protocol layout self-test passed\n");
    return 0;
}

int main(int argc, char **argv) {
    int control[2] = {-1, -1};
    int acknowledgement[2] = {-1, -1};
    int counter_socket[2] = {-1, -1};
    int leader = -1;
    int member = -1;
    int status = 0;
    int controller_failed = 0;
    int inherit_tasks = 1;
    int whole_only = 0;
    int leaf_attribution = 0;
    pid_t child;
    uint64_t session = 0;
    uint64_t next_window = 0;
    uint64_t null_elapsed_ns = 0;
    uint64_t null_max_elapsed_ns = 0;
    int active = 0;
    struct packet active_packet;
    struct counts active_baseline = {0, 0};
    struct counts last_null_baseline = {0, 0};
    struct counts whole_counts = {0, 0};
    struct totals auto_totals = {0, 0, 0};
    struct totals final_totals = {0, 0, 0};
    struct totals null_totals = {0, 0, 0};
    struct rusage usage;

    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return self_test();
    }
    if (argc < 2) {
        fprintf(stderr,
                "usage: perf-demand-windows-v2 COMMAND [ARG...]\n"
                "       perf-demand-windows-v2 --self-test\n");
        return 2;
    }
    if (getenv("AOS_PERF_DEMAND_INHERIT") != NULL
        && strcmp(getenv("AOS_PERF_DEMAND_INHERIT"), "0") == 0) {
        inherit_tasks = 0;
    }
    if (getenv("AOS_PERF_DEMAND_WHOLE_ONLY") != NULL
        && strcmp(getenv("AOS_PERF_DEMAND_WHOLE_ONLY"), "1") == 0) {
        whole_only = 1;
    }
    if (getenv("AOS_PERF_DEMAND_LEAF_ATTRIBUTION") != NULL
        && strcmp(getenv("AOS_PERF_DEMAND_LEAF_ATTRIBUTION"), "1") == 0) {
        leaf_attribution = 1;
    }
    if (leaf_attribution && whole_only) {
        fprintf(stderr,
                "aos-perf-demand-v2: leaf attribution requires demand windows\n");
        return 2;
    }
    if (pipe(control) < 0 || pipe(acknowledgement) < 0) {
        fprintf(stderr, "aos-perf-demand-v2: pipe: %s\n", strerror(errno));
        return 2;
    }
    if (leaf_attribution
        && socketpair(AF_UNIX, SOCK_DGRAM, 0, counter_socket) < 0) {
        fprintf(stderr, "aos-perf-demand-v2: counter socketpair: %s\n",
                strerror(errno));
        return 2;
    }
    child = fork();
    if (child < 0) {
        fprintf(stderr, "aos-perf-demand-v2: fork: %s\n", strerror(errno));
        return 2;
    }
    if (child == 0) {
        char control_fd[32];
        char acknowledgement_fd[32];
        close(control[0]);
        close(acknowledgement[1]);
        if (leaf_attribution) {
            close(counter_socket[0]);
        }
        if (!whole_only
            && (snprintf(control_fd, sizeof(control_fd), "%d", control[1]) < 0
                || snprintf(acknowledgement_fd, sizeof(acknowledgement_fd), "%d",
                            acknowledgement[0])
                       < 0
                || setenv("AOS_NIX_DEMAND_EPOCH_CONTROL_FD", control_fd, 1) < 0
                || setenv("AOS_NIX_DEMAND_EPOCH_ACK_FD", acknowledgement_fd, 1)
                       < 0
                || setenv("AOS_NIX_DEMAND_EPOCH_PROTOCOL", "2", 1) < 0)) {
            fprintf(stderr, "aos-perf-demand-v2: child environment: %s\n",
                    strerror(errno));
            _exit(126);
        }
        if (raise(SIGSTOP) != 0) {
            fprintf(stderr, "aos-perf-demand-v2: child SIGSTOP: %s\n",
                    strerror(errno));
            _exit(126);
        }
        if (leaf_attribution) {
            int descriptors[2] = {-1, -1};
            char instructions_fd[32];
            char cycles_fd[32];
            if (receive_counter_fds(counter_socket[1], descriptors) < 0
                || snprintf(instructions_fd, sizeof(instructions_fd), "%d",
                            descriptors[0])
                       < 0
                || snprintf(cycles_fd, sizeof(cycles_fd), "%d", descriptors[1])
                       < 0
                || setenv("AOS_NIX_FINAL_FORCE_LEAF_PMU", "1", 1) < 0
                || setenv("AOS_NIX_FINAL_FORCE_LEAF_INSTRUCTIONS_FD",
                          instructions_fd, 1)
                       < 0
                || setenv("AOS_NIX_FINAL_FORCE_LEAF_CYCLES_FD", cycles_fd, 1)
                       < 0) {
                fprintf(stderr,
                        "aos-perf-demand-v2: leaf counter environment: %s\n",
                        strerror(errno));
                _exit(126);
            }
            {
                long page_size = sysconf(_SC_PAGESIZE);
                void *metadata =
                    page_size > 0
                        ? mmap(NULL, (size_t)page_size, PROT_READ, MAP_SHARED,
                               descriptors[1], 0)
                        : MAP_FAILED;
                if (metadata == MAP_FAILED) {
                    fprintf(stderr,
                            "aos-perf-demand-v2: leaf metadata mmap: %s\n",
                            strerror(errno));
                } else {
                    const uint64_t *capabilities =
                        (const uint64_t *)((const uint8_t *)metadata + 40);
                    fprintf(stderr,
                            "aos-perf-demand-v2: leaf metadata capabilities=0x%llx\n",
                            (unsigned long long)*capabilities);
                    munmap(metadata, (size_t)page_size);
                }
            }
            close(counter_socket[1]);
        }
        execvp(argv[1], &argv[1]);
        fprintf(stderr, "aos-perf-demand-v2: execvp: %s\n", strerror(errno));
        _exit(127);
    }

    close(control[1]);
    control[1] = -1;
    close(acknowledgement[0]);
    acknowledgement[0] = -1;
    if (leaf_attribution) {
        close(counter_socket[1]);
        counter_socket[1] = -1;
    }
    if (wait_for_stop(child) < 0) {
        controller_failed = 1;
        goto done;
    }
    /*
     * Leaf-profile mode shares one process-local group between wrapper reads
     * and evaluator RDPMC snapshots. Inherited events cannot be mmapped, and a
     * second identical group would contend with the authoritative group.
     */
    leader = open_counter(child, PERF_COUNT_HW_CPU_CYCLES, -1,
                          leaf_attribution ? 0 : inherit_tasks);
    if (leader < 0) {
        fprintf(stderr, "aos-perf-demand-v2: perf_event_open cycles: %s\n",
                strerror(errno));
        controller_failed = 1;
        goto done;
    }
    member =
        open_counter(child, PERF_COUNT_HW_INSTRUCTIONS, leader,
                     leaf_attribution ? 0 : inherit_tasks);
    if (member < 0) {
        fprintf(stderr,
                "aos-perf-demand-v2: perf_event_open instructions: %s\n",
                strerror(errno));
        controller_failed = 1;
        goto done;
    }
    if (leaf_attribution) {
        if (send_counter_fds(counter_socket[0], member, leader) < 0) {
            controller_failed = 1;
            goto done;
        }
    }
    if (whole_only && enable_group(leader) < 0) {
        controller_failed = 1;
        goto done;
    }
    if (kill(child, SIGCONT) < 0) {
        fprintf(stderr, "aos-perf-demand-v2: continue child: %s\n",
                strerror(errno));
        controller_failed = 1;
        goto done;
    }

    for (;;) {
        uint8_t encoded[HEADER_BYTES];
        struct packet packet;
        struct counts counts;
        int read_result = read_full(control[0], encoded, sizeof(encoded), 1);
        if (read_result == 0) {
            break;
        }
        if (read_result < 0 || decode_packet(encoded, &packet) < 0) {
            fprintf(stderr, "aos-perf-demand-v2: malformed request packet\n");
            controller_failed = 1;
            break;
        }
        if (packet.opcode == 'N') {
            struct counts baseline;
            struct counts end;
            uint64_t started;
            uint64_t finished;
            uint64_t elapsed;
            if (active || packet.window != 0) {
                fprintf(stderr,
                        "aos-perf-demand-v2: unbalanced or nonzero null window\n");
                controller_failed = 1;
                break;
            }
            session = packet.session;
            next_window = 1;
            if (read_group(leader, member, &baseline) < 0
                || monotonic_ns(&started) < 0
                || enable_group(leader) < 0
                || disable_group(leader) < 0
                || monotonic_ns(&finished) < 0
                || read_group(leader, member, &end) < 0
                || subtract_counts(&end, &baseline, &counts) < 0
                || add_totals(&null_totals, &counts) < 0
                || send_counts(acknowledgement[1], &packet, &counts) < 0) {
                controller_failed = 1;
                break;
            }
            last_null_baseline = baseline;
            elapsed = finished - started;
            if (UINT64_MAX - null_elapsed_ns < elapsed) {
                fprintf(stderr, "aos-perf-demand-v2: null elapsed overflow\n");
                controller_failed = 1;
                break;
            }
            null_elapsed_ns += elapsed;
            if (elapsed > null_max_elapsed_ns) {
                null_max_elapsed_ns = elapsed;
            }
            continue;
        }
        if (packet.opcode == 'B') {
            if (active || session == 0 || packet.session != session
                || packet.window != next_window) {
                fprintf(stderr,
                        "aos-perf-demand-v2: begin identity/state mismatch\n");
                controller_failed = 1;
                break;
            }
            if (read_group(leader, member, &active_baseline) < 0
                || enable_group(leader) < 0
                || send_ack(acknowledgement[1], &packet) < 0) {
                controller_failed = 1;
                break;
            }
            active_packet = packet;
            active = 1;
            continue;
        }
        if (packet.opcode == 'E') {
            struct counts end;
            struct totals *target;
            if (!active || !packet_equal(&packet, &active_packet)) {
                fprintf(stderr, "aos-perf-demand-v2: end identity/state mismatch\n");
                controller_failed = 1;
                break;
            }
            if (disable_group(leader) < 0
                || read_group(leader, member, &end) < 0
                || subtract_counts(&end, &active_baseline, &counts) < 0) {
                controller_failed = 1;
                break;
            }
            target = packet.kind == KIND_AUTO_CALL_4 ? &auto_totals : &final_totals;
            if (add_totals(target, &counts) < 0
                || send_counts(acknowledgement[1], &packet, &counts) < 0) {
                controller_failed = 1;
                break;
            }
            active = 0;
            if (next_window == UINT64_MAX) {
                fprintf(stderr, "aos-perf-demand-v2: window id overflow\n");
                controller_failed = 1;
                break;
            }
            next_window += 1;
            continue;
        }
        fprintf(stderr, "aos-perf-demand-v2: unsupported opcode 0x%02x\n",
                packet.opcode);
        controller_failed = 1;
        break;
    }
    if (active) {
        fprintf(stderr, "aos-perf-demand-v2: child closed pipe with active window\n");
        controller_failed = 1;
    }

done:
    if (controller_failed) {
        reap_after_kill(child);
        status = 2 << 8;
        memset(&usage, 0, sizeof(usage));
    } else {
        memset(&usage, 0, sizeof(usage));
        if (wait_for_exit(child, &status, &usage) < 0) {
            controller_failed = 1;
            status = 2 << 8;
        } else if (whole_only
                   && read_group(leader, member, &whole_counts) < 0) {
            controller_failed = 1;
            status = 2 << 8;
        }
    }
    if (leader >= 0) {
        close(leader);
    }
    if (member >= 0) {
        close(member);
    }
    if (control[0] >= 0) {
        close(control[0]);
    }
    if (acknowledgement[1] >= 0) {
        close(acknowledgement[1]);
    }
    if (counter_socket[0] >= 0) {
        close(counter_socket[0]);
    }
    if (counter_socket[1] >= 0) {
        close(counter_socket[1]);
    }

    fprintf(stderr,
            "aos_perf_demand_v2 null_windows=%llu null_instructions=%llu "
            "null_cycles=%llu null_elapsed_ns=%llu null_max_elapsed_ns=%llu "
            "last_null_baseline_instructions=%llu "
            "last_null_baseline_cycles=%llu "
            "counter_mode=monotone_delta_individual_read_no_reset inherit_tasks=%s "
            "whole_only=%s leaf_attribution=%s whole_instructions=%llu "
            "whole_cycles=%llu "
            "auto_call_4_windows=%llu "
            "auto_call_4_instructions=%llu auto_call_4_cycles=%llu "
            "final_force_5_windows=%llu final_force_5_instructions=%llu "
            "final_force_5_cycles=%llu maxrss_kib=%ld controller_failed=%s\n",
            (unsigned long long)null_totals.windows,
            (unsigned long long)null_totals.instructions,
            (unsigned long long)null_totals.cycles,
            (unsigned long long)null_elapsed_ns,
            (unsigned long long)null_max_elapsed_ns,
            (unsigned long long)last_null_baseline.instructions,
            (unsigned long long)last_null_baseline.cycles,
            (inherit_tasks && !leaf_attribution) ? "true" : "false",
            whole_only ? "true" : "false",
            leaf_attribution ? "true" : "false",
            (unsigned long long)whole_counts.instructions,
            (unsigned long long)whole_counts.cycles,
            (unsigned long long)auto_totals.windows,
            (unsigned long long)auto_totals.instructions,
            (unsigned long long)auto_totals.cycles,
            (unsigned long long)final_totals.windows,
            (unsigned long long)final_totals.instructions,
            (unsigned long long)final_totals.cycles, usage.ru_maxrss,
            controller_failed ? "true" : "false");

    if (controller_failed) {
        return 2;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    fprintf(stderr, "aos-perf-demand-v2: child has unexpected wait status\n");
    return 2;
}
