#include <qemu-plugin.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/*
 * This is an ABI-and-arithmetic model microtest. It deliberately does not call
 * itself a live-QEMU test: the real header supplies the declarations while the
 * stubs below make callback registration and the entry-icount contract
 * executable in the hermetic check.
 */

static qemu_plugin_id_t registered_plugin_id;
static qemu_plugin_vcpu_tb_trans_cb_t registered_translate;
static qemu_plugin_vcpu_udata_cb_t registered_execute;
static qemu_plugin_simple_cb_t registered_flush;
static struct qemu_plugin_tb *registered_tb;
static enum qemu_plugin_cb_flags registered_flags;
static void *registered_userdata;

static int64_t model_committed;
static int64_t model_budget;
static int64_t model_remaining;
static size_t model_tb_insns;
static int model_active_vcpu;
static int model_precise_icount;
static int model_single_threaded_rr;
static uint64_t observed_entry_icount;

static void
coverage_probe_translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
  (void)id;
  (void)tb;
}

static void
coverage_probe_execute(unsigned int vcpu_index, void *userdata)
{
  (void)vcpu_index;
  (void)userdata;
}

static void
coverage_probe_flush(qemu_plugin_id_t id)
{
  (void)id;
}

int
crucible_coverage_abi_probe(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
  uint64_t entry_icount = 0;

  qemu_plugin_register_vcpu_tb_trans_cb(id, coverage_probe_translate);
  qemu_plugin_register_vcpu_tb_exec_cb(
    tb, coverage_probe_execute, QEMU_PLUGIN_CB_NO_REGS, NULL);
  qemu_plugin_register_flush_cb(id, coverage_probe_flush);
  return qemu_plugin_icount_at_tb_entry(
    (uint64_t)qemu_plugin_tb_n_insns(tb), &entry_icount);
}

void
qemu_plugin_register_vcpu_tb_trans_cb(qemu_plugin_id_t id,
                                      qemu_plugin_vcpu_tb_trans_cb_t cb)
{
  registered_plugin_id = id;
  registered_translate = cb;
}

void
qemu_plugin_register_vcpu_tb_exec_cb(struct qemu_plugin_tb *tb,
                                     qemu_plugin_vcpu_udata_cb_t cb,
                                     enum qemu_plugin_cb_flags flags,
                                     void *userdata)
{
  registered_tb = tb;
  registered_execute = cb;
  registered_flags = flags;
  registered_userdata = userdata;
}

void
qemu_plugin_register_flush_cb(qemu_plugin_id_t id,
                              qemu_plugin_simple_cb_t cb)
{
  registered_plugin_id = id;
  registered_flush = cb;
}

size_t
qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb)
{
  return tb == registered_tb ? model_tb_insns : 0;
}

int
qemu_plugin_icount_at_tb_entry(uint64_t tb_insns, uint64_t *entry_icount)
{
  int64_t executed;
  int64_t observed;

  if (entry_icount == NULL || tb_insns == 0 || !model_active_vcpu ||
      !model_precise_icount || !model_single_threaded_rr ||
      model_remaining > model_budget) {
    return -1;
  }
  executed = model_budget - model_remaining;
  if (executed < 0 || model_committed > INT64_MAX - executed) {
    return -1;
  }
  observed = model_committed + executed;
  if (observed < 0 || (uint64_t)observed < tb_insns) {
    return -1;
  }
  observed_entry_icount = (uint64_t)observed - tb_insns;
  *entry_icount = observed_entry_icount;
  return 0;
}

static int
check_entry(int64_t committed, int64_t budget, int64_t remaining,
            uint64_t tb_insns, uint64_t expected_entry)
{
  uint64_t entry = UINT64_MAX;

  model_committed = committed;
  model_budget = budget;
  model_remaining = remaining;
  if (qemu_plugin_icount_at_tb_entry(tb_insns, &entry) != 0) {
    return 1;
  }
  return entry != expected_entry;
}

int
main(void)
{
  struct qemu_plugin_tb *tb = (struct qemu_plugin_tb *)(uintptr_t)0x1000;

  model_tb_insns = 7;
  model_committed = 100;
  model_budget = 40;
  model_remaining = 33;
  model_active_vcpu = 1;
  model_precise_icount = 1;
  model_single_threaded_rr = 1;
  if (crucible_coverage_abi_probe(0xc0de, tb) != 0) {
    return 1;
  }
  if (registered_plugin_id != 0xc0de || registered_translate == NULL ||
      registered_execute == NULL || registered_flush == NULL ||
      registered_tb != tb || registered_flags != QEMU_PLUGIN_CB_NO_REGS ||
      registered_userdata != NULL || observed_entry_icount != 100) {
    return 2;
  }

  registered_translate(registered_plugin_id, tb);
  registered_execute(2, registered_userdata);
  registered_flush(registered_plugin_id);

  /* First TB, chained TB, post-budget-refill TB, and next RR vCPU. */
  if (check_entry(100, 40, 33, 7, 100) ||
      check_entry(100, 40, 28, 5, 107) ||
      check_entry(112, 30, 21, 9, 112) ||
      check_entry(200, 10, 8, 2, 200)) {
    return 3;
  }

  model_budget = 3;
  model_remaining = 4;
  if (qemu_plugin_icount_at_tb_entry(1, &observed_entry_icount) == 0 ||
      qemu_plugin_icount_at_tb_entry(0, &observed_entry_icount) == 0 ||
      qemu_plugin_icount_at_tb_entry(1, NULL) == 0) {
    return 4;
  }
  model_remaining = 2;
  model_active_vcpu = 0;
  if (qemu_plugin_icount_at_tb_entry(1, &observed_entry_icount) == 0) {
    return 5;
  }
  model_active_vcpu = 1;
  model_single_threaded_rr = 0;
  if (qemu_plugin_icount_at_tb_entry(1, &observed_entry_icount) == 0) {
    return 6;
  }
  model_single_threaded_rr = 1;
  model_precise_icount = 0;
  if (qemu_plugin_icount_at_tb_entry(1, &observed_entry_icount) == 0) {
    return 7;
  }
  model_precise_icount = 1;
  model_committed = INT64_MAX;
  model_budget = 2;
  model_remaining = 1;
  if (qemu_plugin_icount_at_tb_entry(1, &observed_entry_icount) == 0) {
    return 8;
  }
  return 0;
}
