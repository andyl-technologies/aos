/* SPDX-License-Identifier: Apache-2.0 */
/* Disposable-kernel credential and full-kernel device registration checks. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Fixed disposable runner identity; this is device access, not execution credit. */
#define RUNNER_UID 65534
#define RUNNER_GID 29000
#define WRONG_GID 65534
#define PAGE_BYTES 4096

/* Actual host-instruction component cases borrow the negotiated device fd. */
int userfaultfd_progress_cases(int descriptor);

static int failed(const char *operation) {
    perror(operation);
    return 1;
}

static int verify_closed_syscall(void) {
    int descriptor = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (descriptor >= 0) {
        close(descriptor);
        fprintf(stderr, "full-kernel syscall unexpectedly accepted without device access\n");
        return 1;
    }
    if (errno != EPERM && errno != EACCES) {
        return failed("full-kernel syscall refusal");
    }
    return 0;
}

struct kernel_writer {
    int input;
    unsigned char *destination;
    ssize_t result;
};

static void *read_into_registered_page(void *argument) {
    struct kernel_writer *writer = argument;
    writer->result = read(writer->input, writer->destination, 1);
    return NULL;
}

static int kernel_write_fault(int descriptor, unsigned char *page, int write_protected) {
    int pipe_descriptors[2];
    if (pipe2(pipe_descriptors, O_CLOEXEC) != 0) {
        return failed("kernel write pipe");
    }
    unsigned char expected = write_protected ? 0x52 : 0x31;
    int result = 1;
    if (write(pipe_descriptors[1], &expected, 1) != 1) {
        goto close_pipe;
    }
    struct kernel_writer writer = {pipe_descriptors[0], page, -1};
    pthread_attr_t attributes;
    pthread_t thread;
    int status = pthread_attr_init(&attributes);
    if (status != 0) {
        errno = status;
        goto close_pipe;
    }
    status = pthread_attr_setstacksize(&attributes, 64 * 1024);
    if (status == 0) {
        status = pthread_create(&thread, &attributes, read_into_registered_page, &writer);
    }
    pthread_attr_destroy(&attributes);
    if (status != 0) {
        errno = status;
        goto close_pipe;
    }

    /* The existing outer VM timeout bounds a blocked kernel operation. */
    struct pollfd event = {descriptor, POLLIN, 0};
    struct uffd_msg message;
    if (poll(&event, 1, -1) != 1 || event.revents != POLLIN ||
        read(descriptor, &message, sizeof(message)) != (ssize_t)sizeof(message) ||
        message.event != UFFD_EVENT_PAGEFAULT ||
        (message.arg.pagefault.address & ~(uint64_t)(PAGE_BYTES - 1)) != (uintptr_t)page ||
        !(message.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) ||
        !!(message.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) != write_protected ||
        message.arg.pagefault.feat.ptid == 0) {
        /* Terminate the whole child instead of returning past an unresolved writer. */
        fprintf(stderr, "unexpected full-kernel fault; process termination closes the blocked writer\n");
        _exit(1);
    }
    if (write_protected) {
        struct uffdio_writeprotect release = {{(uintptr_t)page, PAGE_BYTES}, 0};
        if (ioctl(descriptor, UFFDIO_WRITEPROTECT, &release) != 0) {
            _exit(1);
        }
    } else {
        unsigned char contents[PAGE_BYTES] = {0};
        struct uffdio_copy install = {
            .dst = (uintptr_t)page, .src = (uintptr_t)contents, .len = PAGE_BYTES,
        };
        if (ioctl(descriptor, UFFDIO_COPY, &install) != 0 || install.copy != PAGE_BYTES) {
            _exit(1);
        }
    }
    status = pthread_join(thread, NULL);
    if (status == 0 && writer.result == 1 && page[0] == expected) {
        result = 0;
    }
close_pipe:
    close(pipe_descriptors[0]);
    close(pipe_descriptors[1]);
    return result;
}

static int device_registration(void) {
    int device = open("/dev/userfaultfd", O_RDWR | O_CLOEXEC);
    if (device < 0) {
        return failed("scoped userfaultfd device");
    }
    int descriptor = ioctl(device, USERFAULTFD_IOC_NEW, O_CLOEXEC | O_NONBLOCK);
    close(device);
    if (descriptor < 0) {
        return failed("full-kernel USERFAULTFD_IOC_NEW");
    }
    int result = 1;
    struct uffdio_api api = {
        .api = UFFD_API,
        .features = UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID,
    };
    if (ioctl(descriptor, UFFDIO_API, &api) != 0 || api.api != UFFD_API ||
        (api.features & (UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID)) !=
        (UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID)) {
        goto close_descriptor;
    }
    unsigned char *page = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        goto close_descriptor;
    }
    struct uffdio_register registration = {
        .range = {(uintptr_t)page, PAGE_BYTES},
        .mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
    };
    if (ioctl(descriptor, UFFDIO_REGISTER, &registration) == 0 &&
        (registration.ioctls & ((1ULL << _UFFDIO_COPY) | (1ULL << _UFFDIO_WRITEPROTECT))) ==
        ((1ULL << _UFFDIO_COPY) | (1ULL << _UFFDIO_WRITEPROTECT)) &&
        kernel_write_fault(descriptor, page, 0) == 0) {
        struct uffdio_writeprotect protect = {
            .range = {(uintptr_t)page, PAGE_BYTES}, .mode = UFFDIO_WRITEPROTECT_MODE_WP,
        };
        if (ioctl(descriptor, UFFDIO_WRITEPROTECT, &protect) == 0 &&
            kernel_write_fault(descriptor, page, 1) == 0) {
            result = userfaultfd_progress_cases(descriptor);
        }
    }
    munmap(page, PAGE_BYTES);
close_descriptor:
    close(descriptor);
    return result;
}

static int credential_case(gid_t group, int allowed) {
    pid_t child = fork();
    if (child < 0) {
        return failed("credential probe fork");
    }
    if (child == 0) {
        if (setgroups(0, NULL) != 0 || setresgid(group, group, group) != 0 ||
            setresuid(RUNNER_UID, RUNNER_UID, RUNNER_UID) != 0 ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || verify_closed_syscall() != 0) {
            _exit(1);
        }
        if (allowed) {
            _exit(device_registration());
        }
        int descriptor = open("/dev/userfaultfd", O_RDWR | O_CLOEXEC);
        if (descriptor >= 0) {
            close(descriptor);
            _exit(1);
        }
        _exit(errno == EACCES ? 0 : 1);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "scoped credential case refused or failed\n");
        return 1;
    }
    return 0;
}

int main(void) {
    struct stat device;
    if (geteuid() != 0 || sysconf(_SC_PAGESIZE) != PAGE_BYTES ||
        stat("/dev/userfaultfd", &device) != 0 || !S_ISCHR(device.st_mode)) {
        return failed("disposable kernel prerequisites");
    }
    if (chown("/dev/userfaultfd", 0, RUNNER_GID) != 0 ||
        chmod("/dev/userfaultfd", 0660) != 0 || credential_case(WRONG_GID, 0) != 0 ||
        chmod("/dev/userfaultfd", 0600) != 0 || credential_case(RUNNER_GID, 0) != 0 ||
        chmod("/dev/userfaultfd", 0660) != 0 || credential_case(RUNNER_GID, 1) != 0) {
        return 1;
    }
    puts("userfaultfd_device_wrong_group=refused");
    puts("userfaultfd_device_wrong_mode=refused");
    puts("userfaultfd_device_full_kernel_missing=passed");
    puts("userfaultfd_device_full_kernel_wp=passed");
    puts("userfaultfd_device_runner_gid=29000");
    return 0;
}
