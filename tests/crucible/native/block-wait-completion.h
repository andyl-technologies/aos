/*
 * Private GPL-side joined-unit adapter, never a process or plugin ABI.
 * Copyright (c) 2026 Andyl, Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef CRUCIBLE_BLOCK_WAIT_COMPLETION_UNIT_H
#define CRUCIBLE_BLOCK_WAIT_COMPLETION_UNIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*BlockWaitUnitCallback)(uint32_t request, void *userdata);
typedef void (*BlockWaitUnitCompletion)(int status, int64_t target,
                                        void *userdata);
typedef void (*BlockWaitUnitIdle)(uint32_t vcpu, uint64_t raw,
                                  void *userdata);
typedef uint64_t (*BlockWaitUnitCurrent)(void *userdata);
typedef void (*BlockWaitUnitPublish)(uint64_t deadline, void *userdata);

typedef struct BlockWaitUnitCallbacks {
    BlockWaitUnitCallback wait;
    BlockWaitUnitCompletion complete;
    BlockWaitUnitIdle idle;
    BlockWaitUnitCurrent current;
    BlockWaitUnitPublish publish;
    void *userdata;
} BlockWaitUnitCallbacks;

typedef struct BlockWaitUnitResult {
    uint32_t polls;
    uint32_t delivered;
    uint32_t due_timer_callbacks;
    uint32_t doorbell_reads;
    uint32_t completion_callbacks;
    uint32_t cpu_kicks;
    int64_t result;
    uint64_t completed_coordinate;
} BlockWaitUnitResult;

/* The caller owns the callback state until the joined unit has returned. */
int block_wait_unit_run(const BlockWaitUnitCallbacks *callbacks,
                        bool initially_due_timer, BlockWaitUnitResult *result);
uint64_t block_wait_unit_raw(void);
int64_t block_wait_unit_deadline(void);
int block_wait_unit_enqueue(int64_t target);
int block_wait_unit_arm_timer(int64_t deadline, uint64_t tick,
                              uint64_t *generation);
int block_wait_unit_query_timer(uint64_t generation, void *record);

#endif
