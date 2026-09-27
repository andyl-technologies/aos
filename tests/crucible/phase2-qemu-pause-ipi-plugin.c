/* SPDX-License-Identifier: GPL-2.0-only */

#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static FILE *events;
static bool saw_pause[2];
static bool saw_hlt;
static bool idle_stop_requested;

static void record(const char *kind, unsigned int vcpu)
{
    fprintf(events, "%s,%u,%" PRIu64 "\n", kind, vcpu, qemu_plugin_icount_raw());
    fflush(events);
}

static void on_pause(unsigned int vcpu, void *userdata)
{
    if (vcpu == (uintptr_t)userdata && !saw_pause[vcpu]) {
        saw_pause[vcpu] = true;
        record("pause", vcpu);
    }
}

static void on_hlt(unsigned int vcpu, void *userdata)
{
    (void)userdata;

    if (vcpu == 0 && !saw_hlt) {
        saw_hlt = true;
        record("hlt", vcpu);
    }
}

static void on_idle(unsigned int vcpu, uint64_t raw_icount, void *userdata)
{
    (void)raw_icount;
    (void)userdata;

    if (saw_hlt && !idle_stop_requested) {
        idle_stop_requested = true;
        record("idle", vcpu);
        qemu_plugin_request_shutdown(0);
    }
}

static void on_resume(unsigned int vcpu, uint64_t raw_icount, void *userdata)
{
    (void)vcpu;
    (void)raw_icount;
    (void)userdata;
}

static void on_memory(
    unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr,
    void *userdata)
{
    if (vcpu != (uintptr_t)userdata || !qemu_plugin_mem_is_store(info)) {
        return;
    }

    const struct qemu_plugin_hwaddr *address = qemu_plugin_get_hwaddr(info, vaddr);
    if (address == NULL) {
        return;
    }

    const uint64_t physical = qemu_plugin_hwaddr_phys_addr(address);
    if (qemu_plugin_hwaddr_is_io(address)) {
        const qemu_plugin_mem_value value = qemu_plugin_mem_get_value(info);
        if (physical == 0xfee00300 && value.type == QEMU_PLUGIN_MEM_VALUE_U32 &&
            value.data.u32 == 0x00000608) {
            record("ipi", vcpu);
        }
        return;
    }

    switch (physical) {
    case 0x700c:
        record("send", vcpu);
        break;
    case 0x7010:
        record("ap", vcpu);
        break;
    }
}

static void on_translate(struct qemu_plugin_tb *tb, void *userdata)
{
    (void)userdata;

    for (size_t index = 0; index < qemu_plugin_tb_n_insns(tb); index++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, index);
        const uint64_t pc = qemu_plugin_insn_vaddr(insn);
        int guest_vcpu;
        unsigned char bytes[2];

        /* Firmware also writes low RAM and uses PAUSE; count guest text only. */
        if (pc >= 0x100000 && pc < 0x110000) {
            guest_vcpu = 0;
        } else if (pc >= 0x8000 && pc < 0x9000) {
            guest_vcpu = 1;
        } else {
            continue;
        }

        if (qemu_plugin_insn_size(insn) == sizeof(bytes) &&
            qemu_plugin_insn_data(insn, bytes, sizeof(bytes)) == sizeof(bytes) &&
            bytes[0] == 0xf3 && bytes[1] == 0x90) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, on_pause, QEMU_PLUGIN_CB_NO_REGS,
                (void *)(uintptr_t)guest_vcpu);
        }
        if (guest_vcpu == 0 && qemu_plugin_insn_size(insn) == 1 &&
            qemu_plugin_insn_data(insn, bytes, 1) == 1 && bytes[0] == 0xf4) {
            qemu_plugin_register_vcpu_insn_exec_cb(
                insn, on_hlt, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        qemu_plugin_register_vcpu_mem_cb(
            insn, on_memory, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_W,
            (void *)(uintptr_t)guest_vcpu);
    }
}

static void on_plugin_exit(void *userdata)
{
    (void)userdata;
    fclose(events);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(
    qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    (void)info;

    if (argc != 1 || strncmp(argv[0], "out=", 4) != 0) {
        return -1;
    }
    events = fopen(argv[0] + 4, "w");
    if (events == NULL) {
        return -1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_translate, NULL);
    qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
    qemu_plugin_register_vcpu_idle_resume_cb(on_idle, on_resume, NULL);
    return 0;
}
