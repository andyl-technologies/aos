/* Checks the installed caller-backed pthread contract through its public ABI. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread-bounded.h>
#include <stdalign.h>
#include <stdio.h>

_Static_assert(sizeof(struct pthread_bounded_config) == 136, "config ABI");
_Static_assert(sizeof(struct pthread_bounded_receipt) == 368, "receipt ABI");

static alignas(64) unsigned char backing[128 * 1024];

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
    assert(pthread_bounded_tryretire_np(control, incarnation, NULL, &receipt) == 0);
    assert(receipt.backing_returned);
    puts("PASS installed bounded libc: exact ABI, real arena return and stale reuse");
    return 0;
}
