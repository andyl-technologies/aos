/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <qemu-plugin.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static atomic_bool advance_pending;

static void
advance_complete(int status, int64_t target_tick, void *userdata)
{
  (void)target_tick;
  (void)userdata;

  if (status != 0 ||
      !atomic_exchange_explicit(&advance_pending, false, memory_order_acq_rel)) {
    abort();
  }
}

static void
vcpu_idle(unsigned int vcpu_index, uint64_t raw_icount, void *userdata)
{
  const int64_t deadline_ps = qemu_plugin_clock_deadline_ps();

  (void)vcpu_index;
  (void)raw_icount;
  (void)userdata;

  if (deadline_ps < 0) {
    return;
  }
  if (atomic_exchange_explicit(&advance_pending, true, memory_order_acq_rel) ||
      qemu_plugin_advance_time_ticks(deadline_ps) != 0) {
    abort();
  }
}

static void
vcpu_resumed(unsigned int vcpu_index, uint64_t raw_icount, void *userdata)
{
  (void)vcpu_index;
  (void)raw_icount;
  (void)userdata;
}

QEMU_PLUGIN_EXPORT int
qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                    int argc, char **argv)
{
  (void)id;
  (void)info;
  (void)argv;

  if (argc != 0) {
    return -1;
  }
  if (!qemu_plugin_request_time_control() ||
      qemu_plugin_register_time_advance_cb(advance_complete, NULL) != 0) {
    return -1;
  }

  qemu_plugin_register_vcpu_idle_resume_cb(vcpu_idle, vcpu_resumed, NULL);
  return 0;
}
