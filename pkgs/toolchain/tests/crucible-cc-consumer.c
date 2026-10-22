/* Checks the installed caller-backed pthread contract through its public ABI. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread-bounded.h>
#include <sched.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

_Static_assert(sizeof(struct pthread_bounded_config) == 136, "config ABI");
_Static_assert(sizeof(struct pthread_bounded_receipt) == 368, "receipt ABI");

static alignas(64) unsigned char backing[128 * 1024];
static alignas(64) unsigned char supplied_stack[1024 * 1024];
static atomic_bool worker_release;
static unsigned char worker_result;

static void *held_worker(void *argument)
{
    while (!atomic_load_explicit(&worker_release, memory_order_acquire)) {
        sched_yield();
    }

    return argument;
}

static void check_born_thread(pthread_bounded_t *control, uint64_t incarnation)
{
    struct pthread_bounded_receipt receipt;
    pthread_attr_t attributes;
    pthread_t thread;
    void *result = NULL;

    assert(pthread_attr_init(&attributes) == 0);
    assert(pthread_attr_setguardsize(&attributes, 0) == 0);
    assert(pthread_attr_setstack(&attributes, supplied_stack,
                                sizeof(supplied_stack)) == 0);
    assert(pthread_bounded_create_np(control, incarnation, &thread, &attributes,
                                     held_worker, &worker_result, &receipt) == 0);
    assert(pthread_attr_destroy(&attributes) == 0);

    assert(receipt.create_attempted && receipt.clone_attempted && receipt.born);
    assert(receipt.stack == (uintptr_t)supplied_stack);
    assert(receipt.stack_bytes == sizeof(supplied_stack));
    /* A live worker cannot return its supplied stack or arena to its caller. */
    assert(pthread_bounded_tryretire_np(control, incarnation, &result,
                                       &receipt) == EBUSY);
    assert(!receipt.kernel_exited && !receipt.joined);
    assert(!receipt.stack_returned && !receipt.backing_returned);

    struct timespec deadline;
    assert(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    deadline.tv_sec += 10;
    atomic_store_explicit(&worker_release, 1, memory_order_release);

    /* Exercise the public try-only terminal API within one fixed test bound.
     * No creation is repeated, and an EBUSY cut never resets the deadline. */
    for (;;) {
        int status = pthread_bounded_tryretire_np(control, incarnation, &result,
                                                 &receipt);
        if (status != EBUSY) {
            assert(status == 0);
            break;
        }

        struct timespec now;
        assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        assert(now.tv_sec < deadline.tv_sec ||
               (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec));
        assert(nanosleep(&(struct timespec) { .tv_nsec = 1000000 }, NULL) == 0);
    }

    assert(result == &worker_result);
    assert(receipt.entered && receipt.exit_cleanup_completed);
    assert(receipt.kernel_exited && receipt.joined);
    assert(receipt.list_returned && receipt.tls_returned);
    assert(receipt.stack_returned && receipt.registration_returned);
    assert(receipt.backing_returned && receipt.retire_status == 0);
    /* Successful physical return preserves the earlier live-worker refusal. */
    assert(receipt.first_error == EBUSY);
    assert(pthread_bounded_query_np(control, incarnation, &receipt) == ESRCH);
}

int main(void)
{
    struct pthread_bounded_config config = {
        .version = PTHREAD_BOUNDED_VERSION,
        .size = sizeof(config),
        .flags = PTHREAD_BOUNDED_STRICT,
    };
    struct pthread_bounded_receipt receipt;
    pthread_bounded_t *control = NULL;
    uint64_t incarnation = 0;

    for (size_t kind = 0; kind < PTHREAD_BOUNDED_KINDS; ++kind) {
        config.limit[kind] = (struct pthread_bounded_limit) { 1, 512, 16 };
    }

    assert(pthread_bounded_init_np(backing, sizeof(backing), &config,
                                   &control, &incarnation) == 0);
    assert(incarnation != 0);
    assert(pthread_bounded_query_np(control, incarnation, &receipt) == 0);
    assert(receipt.backing == (uintptr_t)backing);
    assert(!receipt.create_attempted && !receipt.born);
    assert(pthread_bounded_tryretire_np(control, incarnation, NULL, &receipt) == 0);
    assert(receipt.registration_returned && receipt.backing_returned);
    /* Retirement removes registration; reuse must distinguish the old epoch. */
    assert(pthread_bounded_query_np(control, incarnation, &receipt) == ESRCH);

    uint64_t previous = incarnation;
    assert(pthread_bounded_init_np(backing, sizeof(backing), &config,
                                   &control, &incarnation) == 0);
    assert(incarnation > previous);
    assert(pthread_bounded_query_np(control, previous, &receipt) == ESTALE);
    check_born_thread(control, incarnation);
    puts("PASS installed bounded libc: exact ABI, born thread, physical return and stale reuse");
    return 0;
}
