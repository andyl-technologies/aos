/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Actual registry implementation is compiled separately. These inventory and
 * BQL predicates are synthetic; the model cannot qualify a native scope. */
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/crucible-timer-selection.h"
#include "qemu/timer.h"
#include "plugins/qemu-plugin.h"

static bool generation_changed;
static uint32_t observed_count = 2;

bool bql_locked(void)
{
    return true;
}

int qemu_timer_crucible_node_birth_inventory(
    QemuPluginCrucibleNodeTimerInventory *inventory,
    QemuPluginCrucibleNodeTimerList *lists, uint32_t list_capacity,
    QemuPluginCrucibleNodeTimerBirth *timers, uint32_t timer_capacity)
{
    memset(inventory, 0, sizeof(*inventory));
    memset(timers, 0, sizeof(*timers));
    inventory->current_ps = 0;
    inventory->mutation_generation = 1;
    inventory->timer_count = observed_count;
    for (uint32_t index = 0; index < observed_count; index++) {
        timers[index] = (QemuPluginCrucibleNodeTimerBirth) { 0 };
        timers[index].timer.timer_id = index + 1;
        timers[index].timer.list_id = 1;
        timers[index].timer.arm_generation = 2;
        timers[index].timer.expiry_ps = 50;
    }
    return 0;
}

int qemu_timer_node_selection_publish(uint64_t generation,
    const QemuPluginCrucibleNodeTimerSelection *candidate,
    const QemuPluginCrucibleNodeTimerBirth *timers,
    QemuPluginCrucibleNodeTimerSelection *summary)
{
    if (generation_changed || generation != 1) {
        return -EAGAIN;
    }
    return qemu_timer_node_selection_install(candidate, timers, summary);
}

int main(int argc, char **argv)
{
    G_STATIC_ASSERT(sizeof(QemuPluginCrucibleNodeTimerSelection) == 176);
    G_STATIC_ASSERT(sizeof(QemuPluginCrucibleNodeTimerBirth) == 200);
    G_STATIC_ASSERT(sizeof(QemuPluginCrucibleNodeTimerDisposition) == 128);

    QemuPluginCrucibleNodeTimerSelection origin = {
        .version = 1, .size = 176, .flags = 3, .gate_generation = 1,
        .next_service_deadline_ps = UINT64_MAX,
    };
    QemuPluginCrucibleNodeTimerSelection summary, retained[16], zero = { 0 };
    QemuPluginCrucibleNodeTimerBirth rows[64];
    QemuPluginCrucibleNodeTimerDisposition dispositions[64];
    uint8_t foreign[32] = { 2 };

    origin.prepared_scope_hash[0] = 1;
    if (argc == 2 && !strcmp(argv[1], "bounds")) {
        observed_count = 65;
        assert(qemu_timer_node_selection_capture(&origin, &summary, rows, 64) == -ENOSPC);
        assert(!memcmp(&summary, &zero, sizeof(summary)));
        observed_count = 64;
        assert(!qemu_timer_node_selection_capture(&origin, &summary, rows, 64));
        assert(summary.row_count == 64 && summary.selection_id == 1);
        assert(rows[0].timer.timer_id == 1 && rows[63].timer.timer_id == 64);
        origin.gate_generation = 2;
        assert(qemu_timer_node_selection_capture(&origin, &summary, rows, 64) == -ESTALE);
        assert(!memcmp(&summary, &zero, sizeof(summary)));
        puts("PASS extracted native frontier bound64/reject65/no-credit-consumption/constructor0-changed-HOLD-refusal");
        return 0;
    }
    assert(qemu_timer_node_selection_capture(&origin, &summary, rows, 0) == -ENOSPC);
    assert(!memcmp(&summary, &zero, sizeof(zero)));
    generation_changed = true;
    assert(qemu_timer_node_selection_capture(&origin, &summary, rows, 64) == -EAGAIN);
    generation_changed = false;
    if (argc == 3 && !strcmp(argv[1], "digest")) {
        FILE *output;

        observed_count = 1;
        assert(!qemu_timer_node_selection_capture(&origin, &summary, rows, 64));
        output = fopen(argv[2], "wb");
        assert(output);
        assert(fwrite(&summary, sizeof(summary), 1, output) == 1);
        assert(fwrite(rows, sizeof(rows[0]), 1, output) == 1);
        assert(!fclose(output));
        return 0;
    }
    origin.source_original_digest[0] = 1;
    for (uint32_t index = 0; index < 16; index++) {
        origin.source_original_sequence = index + 1;
        assert(!qemu_timer_node_selection_capture(&origin, &retained[index], rows, 64));
        assert(retained[index].selection_id == index + 1);
    }
    origin.source_original_sequence = 17;
    assert(qemu_timer_node_selection_capture(&origin, &summary, rows, 64) == -ENOSPC);
    assert(!memcmp(&summary, &zero, sizeof(zero)));
    origin.source_original_sequence = 1;
    assert(!qemu_timer_node_selection_capture(&origin, &summary, rows, 64));
    assert(!memcmp(&summary, &retained[0], sizeof(summary)));
    origin.gate_generation = 2;
    assert(qemu_timer_node_selection_capture(&origin, &summary, rows, 64) == -ESTALE);
    assert(!memcmp(&summary, &zero, sizeof(summary)));
    origin.gate_generation = 1;
    assert(!qemu_timer_node_selection_capture(&origin, &summary, rows, 64));
    assert(!memcmp(&summary, &retained[0], sizeof(summary)));
    assert(qemu_plugin_crucible_node_query_timer_selection(foreign, 1,
        retained[0].selection_digest, &summary, rows, dispositions, 64) == -ESTALE);
    assert(!memcmp(&summary, &zero, sizeof(summary)));
    qemu_timer_node_selection_note(1, 3, 1, 3, 8, 9);
    assert(!qemu_plugin_crucible_node_query_timer_selection(
        origin.prepared_scope_hash, retained[0].selection_id,
        retained[0].selection_digest, &summary, rows, dispositions, 64));
    assert(dispositions[0].status == 0);

    qemu_timer_node_selection_note(1, 2, 1, 3, 8, 9);
    qemu_timer_node_selection_note(1, 2, 2, 4, 10, 11);
    for (uint32_t index = 0; index < 16; index++) {
        assert(!qemu_plugin_crucible_node_query_timer_selection(
            origin.prepared_scope_hash, retained[index].selection_id,
            retained[index].selection_digest, &summary, rows, dispositions, 64));
        assert(dispositions[0].status == 1 && dispositions[0].flags == 3);
        assert(dispositions[0].mutation_generation == 3);
        assert(dispositions[0].parent_timer_id == 8);
        assert(dispositions[0].parent_arm_generation == 9);
        assert(!dispositions[0].source_original_sequence);
        assert(!memcmp(&summary, &retained[index], sizeof(summary)));
    }
    puts("PASS extracted native registry capacity16/originalretry/changed-generation/changed-HOLD/foreign-scope/first-disposition-only");
    return 0;
}
