/* SPDX-License-Identifier: Apache-2.0 */
/* Actual host-instruction progress under controlled anonymous-page residency.
 * These component cases issue no Source, guest-execution, or capacity grant.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "The userfaultfd progress probe requires the qualified x86-64 MOVDQU case"
#endif

#define PAGE_BYTES 4096
#define DOMAIN_PAGES 2
#define MAX_ACTORS 2
#define RESULT_BYTES 16
#define NEGATIVE_ALTERNATIONS 8

struct load_actor {
    const unsigned char *address;
    unsigned char result[RESULT_BYTES];
    atomic_uint completed;
    pthread_t thread;
    pthread_barrier_t *start;
    pid_t thread_id;
    int completion_output;
    unsigned char index;
};

struct page_domain {
    unsigned char *address;
    struct uffd_msg pending;
    unsigned int resident_mask;
    bool pending_held;
};

struct progress_case {
    int descriptor;
    int completion_pipe[2];
    unsigned char *mapping;
    size_t mapping_bytes;
    unsigned int actor_count;
    pthread_barrier_t start;
    struct load_actor actors[MAX_ACTORS];
    struct page_domain domains[MAX_ACTORS];
};

static void system_failure(const char *operation)
{
    perror(operation);
    /* No error may return into unregister/unmap while an actor could run. */
    _exit(EXIT_FAILURE);
}

static void protocol_failure(const char *message)
{
    fprintf(stderr, "userfaultfd progress: %s\n", message);
    _exit(EXIT_FAILURE);
}

static void check_thread_status(int status, const char *operation)
{
    if (status != 0) {
        errno = status;
        system_failure(operation);
    }
}

static void start_barrier(pthread_barrier_t *barrier)
{
    int status = pthread_barrier_wait(barrier);

    if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD) {
        check_thread_status(status, "progress start barrier");
    }
}

static void *cross_page_load(void *argument)
{
    struct load_actor *actor = argument;

    actor->thread_id = (pid_t)syscall(SYS_gettid);
    if (actor->thread_id <= 0) {
        system_failure("progress actor gettid");
    }
    start_barrier(actor->start);

    /* The load is ONE actual instruction spanning both registered pages.
     * The result store and completion publication occur only after that load.
     */
    __asm__ volatile(
        "movdqu (%[address]), %%xmm0\n\t"
        "movdqu %%xmm0, %[result]"
        : [result] "=m" (actor->result)
        : [address] "r" (actor->address)
        : "xmm0", "memory");

    atomic_store_explicit(&actor->completed, 1, memory_order_release);
    if (write(actor->completion_output, &actor->index, sizeof(actor->index)) !=
        (ssize_t)sizeof(actor->index)) {
        system_failure("progress completion notification");
    }
    return NULL;
}

static unsigned char pattern_byte(unsigned int actor, unsigned int page,
                                  size_t offset)
{
    return (unsigned char)(0x21 + actor * 0x40 + page * 0x20 + (offset & 0x1f));
}

static void require_incomplete(const struct progress_case *probe)
{
    for (unsigned int index = 0; index < probe->actor_count; index++) {
        if (atomic_load_explicit(&probe->actors[index].completed,
                                 memory_order_acquire) != 0) {
            protocol_failure("instruction retired during one-page policy");
        }
    }
}

static void verify_residency(const struct page_domain *domain,
                             unsigned int expected_mask)
{
    unsigned char residency[DOMAIN_PAGES];
    unsigned int observed_mask = 0;

    /* mincore observes these private anonymous pages without touching their
     * bytes. The controller never reads through the registered mapping.
     */
    if (mincore(domain->address, DOMAIN_PAGES * PAGE_BYTES, residency) != 0) {
        system_failure("progress mincore");
    }
    for (unsigned int page = 0; page < DOMAIN_PAGES; page++) {
        if (residency[page] & 1) {
            observed_mask |= 1U << page;
        }
    }
    if (observed_mask != expected_mask || domain->resident_mask != expected_mask) {
        protocol_failure("actual residency differs from retained page set");
    }
}

static void wait_event(struct progress_case *probe, bool expect_fault)
{
    struct pollfd events[2] = {
        {probe->descriptor, POLLIN, 0},
        {probe->completion_pipe[0], POLLIN, 0},
    };

    /* The existing outer disposable-VM timeout contains irrecoverable faults.
     * Neither sleeps nor elapsed time supplies an ordering/completion proof.
     */
    if (poll(events, 2, -1) < 0) {
        system_failure("progress event poll");
    }
    if ((events[0].revents & ~POLLIN) || (events[1].revents & ~POLLIN)) {
        protocol_failure("unexpected fault/completion descriptor condition");
    }
    if (expect_fault) {
        if (events[1].revents & POLLIN) {
            protocol_failure("completion arrived during negative phase");
        }
        if (!(events[0].revents & POLLIN)) {
            protocol_failure("poll returned without the required actual fault");
        }
    } else {
        if (events[0].revents & POLLIN) {
            protocol_failure("new fault after both progress pages were retained");
        }
        if (!(events[1].revents & POLLIN)) {
            protocol_failure("poll returned without a completion notification");
        }
    }
}

static unsigned int receive_fault(struct progress_case *probe,
                                   unsigned int expected_actor)
{
    struct uffd_msg message;
    unsigned int index;

    wait_event(probe, true);
    if (read(probe->descriptor, &message, sizeof(message)) != (ssize_t)sizeof(message)) {
        system_failure("progress fault receipt");
    }
    if (message.event != UFFD_EVENT_PAGEFAULT || message.arg.pagefault.flags != 0 ||
        message.arg.pagefault.feat.ptid == 0) {
        protocol_failure("expected a real missing read fault with thread identity");
    }
    for (index = 0; index < probe->actor_count; index++) {
        if (message.arg.pagefault.feat.ptid == (uint32_t)probe->actors[index].thread_id) {
            break;
        }
    }
    if (index == probe->actor_count ||
        (expected_actor < probe->actor_count && index != expected_actor)) {
        protocol_failure("fault came from a foreign or unscheduled actor");
    }

    struct page_domain *domain = &probe->domains[index];
    uintptr_t address = message.arg.pagefault.address & ~(uintptr_t)(PAGE_BYTES - 1);
    uintptr_t base = (uintptr_t)domain->address;

    if (domain->pending_held || address < base ||
        address - base >= DOMAIN_PAGES * PAGE_BYTES) {
        protocol_failure("fault does not belong to the actor's retained range");
    }
    unsigned int page = (unsigned int)((address - base) / PAGE_BYTES);

    if (domain->resident_mask & (1U << page)) {
        protocol_failure("fault requested an already retained resident page");
    }
    domain->pending = message;
    domain->pending_held = true;
    require_incomplete(probe);
    return index;
}

static unsigned int pending_page(const struct page_domain *domain)
{
    if (!domain->pending_held) {
        protocol_failure("missing consumed-fault custody");
    }
    uintptr_t address = domain->pending.arg.pagefault.address &
        ~(uintptr_t)(PAGE_BYTES - 1);

    return (unsigned int)((address - (uintptr_t)domain->address) / PAGE_BYTES);
}

static void populate_page(struct progress_case *probe, unsigned int actor,
                          unsigned int page)
{
    unsigned char contents[PAGE_BYTES];
    struct page_domain *domain = &probe->domains[actor];

    for (size_t offset = 0; offset < sizeof(contents); offset++) {
        contents[offset] = pattern_byte(actor, page, offset);
    }
    struct uffdio_copy install = {
        .dst = (uintptr_t)domain->address + page * PAGE_BYTES,
        .src = (uintptr_t)contents,
        .len = PAGE_BYTES,
        .mode = UFFDIO_COPY_MODE_WP | UFFDIO_COPY_MODE_DONTWAKE,
    };

    if (ioctl(probe->descriptor, UFFDIO_COPY, &install) != 0) {
        system_failure("progress page installation");
    }
    if (install.copy != PAGE_BYTES) {
        protocol_failure("page installation did not return a complete page");
    }
    domain->resident_mask |= 1U << page;
}

static void wake_pending(struct progress_case *probe, unsigned int actor)
{
    struct page_domain *domain = &probe->domains[actor];
    unsigned int page = pending_page(domain);
    struct uffdio_range range = {
        .start = (uintptr_t)domain->address + page * PAGE_BYTES,
        .len = PAGE_BYTES,
    };

    if (ioctl(probe->descriptor, UFFDIO_WAKE, &range) != 0) {
        system_failure("progress fault wake");
    }
    domain->pending_held = false;
}

static void alternate_one_page(struct progress_case *probe, unsigned int actor)
{
    struct page_domain *domain = &probe->domains[actor];
    unsigned int requested = pending_page(domain);

    require_incomplete(probe);
    if (domain->resident_mask != 0 &&
        domain->resident_mask != (1U << (requested ^ 1U))) {
        protocol_failure("negative policy did not retain exactly the other page");
    }
    for (unsigned int page = 0; page < DOMAIN_PAGES; page++) {
        if (!(domain->resident_mask & (1U << page))) {
            continue;
        }
        if (madvise(domain->address + page * PAGE_BYTES, PAGE_BYTES, MADV_DONTNEED) != 0) {
            system_failure("progress page discard");
        }
        domain->resident_mask &= ~(1U << page);
    }
    verify_residency(domain, 0);
    populate_page(probe, actor, requested);
    verify_residency(domain, 1U << requested);
    wake_pending(probe, actor);

    /* The next real fault proves a retry reached the other absent page.
     * It does not supply an instruction-retirement receipt.
     */
    receive_fault(probe, actor);
    if (pending_page(domain) != (requested ^ 1U)) {
        protocol_failure("missing faults did not genuinely alternate pages");
    }
    verify_residency(domain, 1U << requested);
    require_incomplete(probe);
}

static void retain_progress_pairs(struct progress_case *probe)
{
    require_incomplete(probe);
    for (unsigned int actor = 0; actor < probe->actor_count; actor++) {
        struct page_domain *domain = &probe->domains[actor];
        unsigned int page = pending_page(domain);

        if (domain->resident_mask != (1U << (page ^ 1U))) {
            protocol_failure("positive phase lost its actual retained first page");
        }
        /* This component changes its explicit physical policy from one to
         * two pages per domain. No Source budget or universal floor is issued.
         */
        populate_page(probe, actor, page);
        verify_residency(domain, 3);
    }
    /* All domains have their full pairs before any blocked actor is woken. */
    for (unsigned int actor = 0; actor < probe->actor_count; actor++) {
        wake_pending(probe, actor);
    }
}

static void verify_completions(struct progress_case *probe)
{
    unsigned int seen = 0;

    for (unsigned int receipt = 0; receipt < probe->actor_count; receipt++) {
        unsigned char actor;
        unsigned char expected[RESULT_BYTES];

        wait_event(probe, false);
        if (read(probe->completion_pipe[0], &actor, sizeof(actor)) !=
            (ssize_t)sizeof(actor)) {
            system_failure("progress completion receipt");
        }
        if (actor >= probe->actor_count || (seen & (1U << actor))) {
            protocol_failure("foreign or duplicate completion notification");
        }
        if (atomic_load_explicit(&probe->actors[actor].completed,
                                 memory_order_acquire) != 1) {
            protocol_failure("notification lacks actual post-instruction publication");
        }
        for (unsigned int byte = 0; byte < RESULT_BYTES; byte++) {
            unsigned int page = byte < RESULT_BYTES / 2 ? 0 : 1;
            size_t offset = page == 0 ? PAGE_BYTES - RESULT_BYTES / 2 + byte :
                byte - RESULT_BYTES / 2;

            expected[byte] = pattern_byte(actor, page, offset);
        }
        if (memcmp(probe->actors[actor].result, expected, sizeof(expected)) != 0) {
            protocol_failure("retired instruction returned different page bytes");
        }
        seen |= 1U << actor;
    }
    for (unsigned int actor = 0; actor < probe->actor_count; actor++) {
        void *result = NULL;

        check_thread_status(pthread_join(probe->actors[actor].thread, &result),
                            "progress actor join");
        if (result != NULL) {
            protocol_failure("actor returned an unexpected result");
        }
    }
}

static void run_progress_case(int descriptor, unsigned int actor_count)
{
    struct progress_case probe = {
        .descriptor = descriptor,
        .actor_count = actor_count,
        .mapping_bytes = actor_count * DOMAIN_PAGES * PAGE_BYTES,
    };
    pthread_attr_t attributes;

    if (actor_count == 0 || actor_count > MAX_ACTORS) {
        protocol_failure("invalid literal actor cohort");
    }
    probe.mapping = mmap(NULL, probe.mapping_bytes, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe.mapping == MAP_FAILED) {
        system_failure("progress anonymous mapping");
    }
    if (madvise(probe.mapping, probe.mapping_bytes, MADV_NOHUGEPAGE) != 0) {
        system_failure("progress base-page policy");
    }
    struct uffdio_register registration = {
        .range = {(uintptr_t)probe.mapping, probe.mapping_bytes},
        .mode = UFFDIO_REGISTER_MODE_MISSING | UFFDIO_REGISTER_MODE_WP,
    };
    uint64_t required = (1ULL << _UFFDIO_COPY) | (1ULL << _UFFDIO_WAKE) |
        (1ULL << _UFFDIO_WRITEPROTECT);

    if (ioctl(descriptor, UFFDIO_REGISTER, &registration) != 0) {
        system_failure("progress missing/WP registration");
    }
    if ((registration.ioctls & required) != required) {
        protocol_failure("registered range lacks the required kernel ioctls");
    }
    if (pipe2(probe.completion_pipe, O_CLOEXEC) != 0) {
        system_failure("progress completion pipe");
    }
    check_thread_status(pthread_barrier_init(&probe.start, NULL, actor_count + 1),
                        "progress barrier initialization");
    check_thread_status(pthread_attr_init(&attributes), "progress thread attributes");
    check_thread_status(pthread_attr_setstacksize(&attributes, 64 * 1024),
                        "progress actor stack size");

    for (unsigned int actor = 0; actor < actor_count; actor++) {
        struct page_domain *domain = &probe.domains[actor];
        struct load_actor *worker = &probe.actors[actor];

        domain->address = probe.mapping + actor * DOMAIN_PAGES * PAGE_BYTES;
        verify_residency(domain, 0);
        worker->address = domain->address + PAGE_BYTES - RESULT_BYTES / 2;
        worker->start = &probe.start;
        worker->completion_output = probe.completion_pipe[1];
        worker->index = (unsigned char)actor;
        atomic_init(&worker->completed, 0);
        check_thread_status(pthread_create(&worker->thread, &attributes,
                                           cross_page_load, worker),
                            "progress actor birth");
    }
    check_thread_status(pthread_attr_destroy(&attributes),
                        "progress attribute destruction");
    start_barrier(&probe.start);
    for (unsigned int actor = 0; actor < actor_count; actor++) {
        if (probe.actors[actor].thread_id <= 0 ||
            (actor != 0 && probe.actors[actor].thread_id == probe.actors[0].thread_id)) {
            protocol_failure("actual actor thread identities are not distinct");
        }
    }

    /* Consume one genuine fault from EVERY actor before servicing any actor.
     * Both parallel actors therefore hold actual kernel fault waits.
     */
    for (unsigned int actor = 0; actor < actor_count; actor++) {
        receive_fault(&probe, actor_count);
    }
    for (unsigned int step = 0; step < NEGATIVE_ALTERNATIONS; step++) {
        for (unsigned int actor = 0; actor < actor_count; actor++) {
            alternate_one_page(&probe, actor);
        }
    }
    require_incomplete(&probe);
    retain_progress_pairs(&probe);
    verify_completions(&probe);

    /* Successful physical joins precede every unregister, unmap and close. */
    check_thread_status(pthread_barrier_destroy(&probe.start),
                        "progress barrier destruction");
    if (ioctl(descriptor, UFFDIO_UNREGISTER, &registration.range) != 0) {
        system_failure("progress registration return");
    }
    if (munmap(probe.mapping, probe.mapping_bytes) != 0) {
        system_failure("progress mapping return");
    }
    if (close(probe.completion_pipe[0]) != 0 || close(probe.completion_pipe[1]) != 0) {
        system_failure("progress completion pipe close");
    }
}

int userfaultfd_progress_cases(int descriptor)
{
    run_progress_case(descriptor, 1);
    run_progress_case(descriptor, 2);

    /* The allowed credential child uses _exit; publish without stdio buffering. */
    if (dprintf(STDOUT_FILENO,
                "userfaultfd_progress_one_slot_alternations=8\n"
                "userfaultfd_progress_one_slot_completion=not-retired\n"
                "userfaultfd_progress_two_page_result=retired-and-joined\n"
                "userfaultfd_progress_two_domain_one_slot_alternations=8-per-domain\n"
                "userfaultfd_progress_two_domain_one_slot_completion=neither-retired\n"
                "userfaultfd_progress_two_domain_retained_pairs=both-retired-and-joined\n"
                "userfaultfd_progress_scope=kernel-host-instruction-only\n") < 0) {
        system_failure("progress evidence publication");
    }
    return 0;
}
