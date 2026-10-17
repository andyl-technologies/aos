/* SPDX-License-Identifier: MIT */
/* A mechanism check, not a certificate for any simulator or device model. */
#include <dmtcp.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int dmtcp_get_ckpt_signal(void) __attribute__((weak));

struct pending_event {
    uint64_t tick;
    uint64_t payload;
    struct pending_event *next;
};

static uint64_t random_state = UINT64_C(0x98372aac57016194);
static uint64_t memory[128];
static struct pending_event *pending;

static uint64_t
next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static uint64_t
fingerprint(void)
{
    uint64_t digest = random_state;
    for (size_t index = 0; index < 128; ++index) {
        digest = (digest ^ memory[index]) * UINT64_C(1099511628211);
    }
    for (const struct pending_event *event = pending; event; event = event->next) {
        digest = (digest ^ event->tick) * UINT64_C(1099511628211);
        digest = (digest ^ event->payload) * UINT64_C(1099511628211);
    }
    return digest;
}

int
main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: continuation-check baseline|capture output-prefix\n");
        return 2;
    }

    for (size_t index = 0; index < 128; ++index) {
        memory[index] = next_random();
    }
    for (uint64_t index = 0; index < 64; ++index) {
        struct pending_event *event = malloc(sizeof(*event));
        if (!event) {
            perror("malloc");
            return 1;
        }
        event->tick = index / 4;
        event->payload = next_random();
        event->next = pending;
        pending = event;
    }

    uint64_t before = fingerprint();
    int status = DMTCP_AFTER_CHECKPOINT;
    if (strcmp(argv[1], "capture") == 0) {
        errno = ENOENT;
        if (!dmtcp_get_ckpt_signal || dmtcp_get_ckpt_signal() != 40 ||
            errno != ENOENT) {
            fprintf(stderr, "checkpoint signal depends on unrelated errno\n");
            return 1;
        }
        status = dmtcp_checkpoint();
        if (status != DMTCP_AFTER_CHECKPOINT && status != DMTCP_AFTER_RESTART) {
            fprintf(stderr, "checkpoint failed: %d\n", status);
            return 1;
        }
    } else if (strcmp(argv[1], "baseline") != 0) {
        return 2;
    }

    if (fingerprint() != before) {
        fprintf(stderr, "capture changed future-affecting state\n");
        return 1;
    }

    char path[4096];
    int length = snprintf(path, sizeof(path), "%s.%s", argv[2],
        status == DMTCP_AFTER_RESTART ? "restored" : "original");
    if (length < 0 || (size_t)length >= sizeof(path)) {
        fprintf(stderr, "output path exceeds the fixture limit\n");
        return 1;
    }
    FILE *trace = fopen(path, "w");
    if (!trace) {
        perror("fopen");
        return 1;
    }

    fprintf(trace, "boundary=%016" PRIx64 "\n", before);
    while (pending) {
        struct pending_event *event = pending;
        pending = event->next;
        size_t address = (size_t)(event->payload % 128);
        memory[address] ^= next_random();
        fprintf(trace, "%02" PRIu64 ":%016" PRIx64 ":%016" PRIx64 "\n",
            event->tick, event->payload, fingerprint());
        free(event);
    }
    if (fclose(trace) != 0) {
        perror("fclose");
        return 1;
    }
    return 0;
}
