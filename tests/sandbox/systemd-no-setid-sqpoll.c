/* SPDX-License-Identifier: Apache-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <linux/openat2.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PR_SET_AOS_NO_SETID
#define PR_SET_AOS_NO_SETID 82
#endif

#ifndef PR_GET_AOS_NO_SETID
#define PR_GET_AOS_NO_SETID 83
#endif

#if PR_SET_AOS_NO_SETID != 82 || PR_GET_AOS_NO_SETID != 83
#error "AOS no-set-ID prctl values do not match the pinned kernel ABI"
#endif

static int guard_value(void) {
        return prctl(PR_GET_AOS_NO_SETID, 0UL, 0UL, 0UL, 0UL);
}

struct shared_request {
        struct open_how how;
        char name[64];
};

static int wait_for_completion(struct io_uring *ring, int *completion_result) {
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000000};

        /* Poll the shared CQ directly: io_uring_enter is denied in this unit. */
        for (int attempt = 0; attempt < 5000; attempt++) {
                unsigned head = __atomic_load_n(ring->cq.khead, __ATOMIC_RELAXED);
                unsigned tail = __atomic_load_n(ring->cq.ktail, __ATOMIC_ACQUIRE);

                if (tail != head) {
                        struct io_uring_cqe *cqe = &ring->cq.cqes[head & ring->cq.ring_mask];
                        *completion_result = cqe->res;
                        __atomic_store_n(ring->cq.khead, head + 1, __ATOMIC_RELEASE);
                        return 0;
                }

                if (nanosleep(&pause, NULL) < 0 && errno != EINTR) {
                        perror("nanosleep CQ poll");
                        return -1;
                }
        }

        fprintf(stderr, "SQPOLL request did not complete within five seconds\n");
        return -1;
}

static int ring_create(struct io_uring *ring, struct shared_request *request,
                       int directory, const char *name, mode_t mode,
                       int *completion_result) {
        struct io_uring_sqe *sqe;
        unsigned tail;
        int name_length;

        name_length = snprintf(request->name, sizeof(request->name), "%s", name);
        if (name_length < 0 || (size_t)name_length >= sizeof(request->name)) {
                fprintf(stderr, "SQPOLL request name is too long\n");
                return -1;
        }
        request->how = (struct open_how) {
                .flags = O_WRONLY | O_CREAT | O_EXCL,
                .mode = mode,
                .resolve = RESOLVE_BENEATH,
        };

        sqe = io_uring_get_sqe(ring);
        if (!sqe) {
                fprintf(stderr, "SQPOLL submission queue is full\n");
                return -1;
        }

        io_uring_prep_openat2(sqe, directory, request->name, &request->how);
        tail = ring->sq.sqe_tail;
        if (ring->sq.sqe_head + 1 != tail ||
            __atomic_load_n(ring->sq.kflags, __ATOMIC_ACQUIRE) & IORING_SQ_NEED_WAKEUP) {
                fprintf(stderr, "SQPOLL thread is asleep or queue state changed\n");
                return -1;
        }

        /* NO_SQARRAY lets the borrower publish directly. liburing's submit
         * path may call the intentionally denied io_uring_enter syscall. */
        ring->sq.sqe_head = tail;
        __atomic_store_n(ring->sq.ktail, tail, __ATOMIC_RELEASE);

        return wait_for_completion(ring, completion_result);
}

static int verify_denied_and_absent(struct io_uring *ring, struct shared_request *request,
                                    int directory, const char *name) {
        struct stat file_stat;
        int completion_result;

        if (ring_create(ring, request, directory, name, 04700, &completion_result) < 0)
                return -1;
        if (completion_result != -EPERM) {
                fprintf(stderr, "SQPOLL set-ID creation returned %d, expected -EPERM\n",
                        completion_result);
                if (completion_result >= 0)
                        close(completion_result);
                return -1;
        }
        if (fstatat(directory, name, &file_stat, AT_SYMLINK_NOFOLLOW) != -1 || errno != ENOENT) {
                fprintf(stderr, "SQPOLL set-ID denial left a file behind\n");
                return -1;
        }

        return 0;
}

static int check_borrowed_ring(struct io_uring *ring, struct shared_request *request, int directory) {
        struct stat file_stat;
        int completion_result;

        if (prctl(PR_SET_AOS_NO_SETID, 1UL, 0UL, 0UL, 0UL) < 0 || guard_value() != 1) {
                perror("enable guard in ring borrower");
                return -1;
        }

        if (ring_create(ring, request, directory, "borrowed-ordinary", 0600, &completion_result) < 0)
                return -1;
        if (completion_result < 0 ||
            fstatat(directory, "borrowed-ordinary", &file_stat, AT_SYMLINK_NOFOLLOW) < 0 ||
            (file_stat.st_mode & (S_ISUID | S_ISGID))) {
                fprintf(stderr, "borrowed SQPOLL ordinary creation failed: %d\n", completion_result);
                return -1;
        }

        /* The returned descriptor may belong to the ring creator's files table. */
        return verify_denied_and_absent(ring, request, directory, "borrowed-suid");
}

int main(void) {
        char directory_path[] = "/tmp/aos-no-setid-sqpoll-XXXXXX";
        struct io_uring_params params = {
                .flags = IORING_SETUP_SQPOLL | IORING_SETUP_NO_SQARRAY | IORING_SETUP_NO_MMAP,
                .sq_thread_idle = 60000,
        };
        struct io_uring ring;
        struct open_how direct_how = {
                .flags = O_WRONLY | O_CREAT | O_EXCL,
                .mode = 04700,
                .resolve = RESOLVE_BENEATH,
        };
        struct stat file_stat;
        long page_size;
        ssize_t memory_needed;
        size_t mapping_size;
        void *ring_memory;
        struct shared_request *request;
        pid_t borrower;
        int directory, descriptor, initialized, status;

        if (guard_value() != 0) {
                fprintf(stderr, "SQPOLL owner unexpectedly began guarded\n");
                return EXIT_FAILURE;
        }
        if (syscall(SYS_io_uring_enter, -1, 0, 0, 0, NULL, 0) != -1 || errno != EPERM) {
                fprintf(stderr, "io_uring_enter is not blocked by the probe unit\n");
                return EXIT_FAILURE;
        }
        if (!mkdtemp(directory_path)) {
                perror("mkdtemp SQPOLL");
                return EXIT_FAILURE;
        }
        directory = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (directory < 0) {
                perror("open SQPOLL directory");
                return EXIT_FAILURE;
        }

        /* The same requested mode succeeds through a direct, unguarded syscall. */
        descriptor = syscall(SYS_openat2, directory, "direct-suid", &direct_how, sizeof(direct_how));
        if (descriptor < 0 || fstat(descriptor, &file_stat) < 0 || !(file_stat.st_mode & S_ISUID)) {
                perror("direct SUID creation control");
                return EXIT_FAILURE;
        }
        close(descriptor);

        memory_needed = io_uring_memory_size_params(8, &params);
        page_size = sysconf(_SC_PAGESIZE);
        if (memory_needed <= 0 || page_size <= 0) {
                fprintf(stderr, "invalid SQPOLL shared-memory sizing\n");
                return EXIT_FAILURE;
        }
        mapping_size = ((size_t)memory_needed + (size_t)page_size - 1) / (size_t)page_size * (size_t)page_size;
        ring_memory = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (ring_memory == MAP_FAILED) {
                perror("mmap SQPOLL shared memory");
                return EXIT_FAILURE;
        }
        request = mmap(NULL, sizeof(*request), PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (request == MAP_FAILED) {
                perror("mmap SQPOLL shared request");
                return EXIT_FAILURE;
        }

        initialized = io_uring_queue_init_mem(8, &ring, &params, ring_memory, mapping_size);
        if (initialized <= 0 || !(ring.flags & IORING_SETUP_NO_MMAP) ||
            !(ring.flags & IORING_SETUP_SQPOLL)) {
                fprintf(stderr, "SQPOLL NO_MMAP ring setup failed: %d\n", initialized);
                return EXIT_FAILURE;
        }

        if (ring_create(&ring, request, directory, "owner-ordinary", 0600, &descriptor) < 0)
                return EXIT_FAILURE;
        if (descriptor < 0) {
                fprintf(stderr, "owner SQPOLL ordinary creation failed: %d\n", descriptor);
                return EXIT_FAILURE;
        }
        close(descriptor);

        /* PF_IO_WORKER must deny this even before the owner sets its task bit. */
        if (verify_denied_and_absent(&ring, request, directory, "owner-suid") < 0 || guard_value() != 0)
                return EXIT_FAILURE;

        borrower = fork();
        if (borrower < 0) {
                perror("fork SQPOLL borrower");
                return EXIT_FAILURE;
        }
        if (borrower == 0)
                _exit(check_borrowed_ring(&ring, request, directory) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);

        if (waitpid(borrower, &status, 0) != borrower ||
            !WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS) {
                fprintf(stderr, "guarded SQPOLL borrower failed\n");
                return EXIT_FAILURE;
        }

        io_uring_queue_exit(&ring);
        munmap(request, sizeof(*request));
        munmap(ring_memory, mapping_size);
        close(directory);
        printf("AOS_NO_SETID_SQPOLL_OK\n");
        return EXIT_SUCCESS;
}
