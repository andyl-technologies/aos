# SPDX-License-Identifier: GPL-2.0-or-later
"""Check exact native writer call sites without claiming complete roots."""

import argparse
from pathlib import Path


def function(text, signature):
    if text.count(signature) != 1:
        raise ValueError("native function signature missing or ambiguous")
    start = text.index(signature)
    end = text.find("\n}\n", start)
    if end < 0:
        raise ValueError("native function extent absent")
    return text[start:end + 3]


def before_effect(body, guard, effect):
    if body.count(guard) != 1 or effect not in body:
        raise ValueError("original guard/effect missing or ambiguous")
    if body.index(guard) >= body.index(effect):
        raise ValueError("writer guard follows the original effect")


# Each entry binds one real call site to its first relevant writer operation.
# Actual guard behavior is independently compiled by native-held-roots-model.
CASES = [
    ("monitor/monitor.c", "static void monitor_init(",
     "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_MONITOR);",
     "qemu_mutex_init(&mon->mon_lock)"),
    ("chardev/char.c", "static void char_init(",
     "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_CHARACTER);",
     "chr->handover_yank_instance ="),
    ("iothread.c", "static void iothread_instance_init(",
     "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_IOTHREAD);",
     "iothread->poll_max_ns ="),
    ("block.c", "BlockDriverState *bdrv_new(",
     "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_BLOCK_NODE);",
     "bs = g_new0("),
    ("block/block-backend.c", "BlockBackend *blk_new(",
     "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_BLOCK_BACKEND);",
     "blk = g_new0("),
    ("system/qtest.c", "static void qtest_endpoint_instance_init(",
     "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_QTEST);", "\n}"),
    ("system/qtest.c", "void qtest_server_set_send_handler(",
     "qemu_crucible_endpoint_root_input_guard(CRUCIBLE_ENDPOINT_QTEST);",
     "qtest_server_send ="),
    ("system/qtest.c", "void qtest_server_inproc_recv(",
     "qemu_crucible_endpoint_root_input_guard(CRUCIBLE_ENDPOINT_QTEST);",
     "if (!qtest_inproc_inbuf)"),
    ("monitor/fds.c", "AddfdInfo *monitor_fdset_add_fd(",
     "qemu_crucible_endpoint_root_input_guard(CRUCIBLE_ENDPOINT_MONITOR);",
     "QEMU_LOCK_GUARD(&mon_fdsets_lock)"),
]

for signature, effect in [
    ("static void qemu_net_client_setup(", "nc->info ="),
    ("NetClientState *qemu_new_net_client(", "nc = g_malloc0("),
    ("NetClientState *qemu_new_net_control_client(", "nc = g_malloc0("),
    ("NICState *qemu_new_nic(", "nic = g_malloc0("),
    ("static int net_client_init1(", "peer = net_hub_add_port("),
]:
    CASES.append(("net/net.c", signature,
                  "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_NETWORK);",
                  effect))

for path, signature, name, effect in [
    ("system/cpus.c", "void cpu_set_interrupt(", "CPU IRQ set", "qemu_cpu_node_observe("),
    ("hw/core/cpu-common.c", "void cpu_reset_interrupt(", "CPU IRQ clear", "qemu_cpu_node_observe("),
    ("hw/core/cpu-common.c", "void cpu_reset(", "CPU reset", "qemu_cpu_node_observe("),
    ("hw/core/cpu-common.c", "static void cpu_common_reset_hold(", "CPU reset hold", "cpu->interrupt_request ="),
]:
    CASES.append((path, signature,
                  f'qemu_irq_node_root_cpu_mutation_guard("{name}");', effect))

for signature, effect in [
    ("void qemu_init_irq(", "object_initialize("),
    ("void qemu_init_irq_child(", "object_initialize_child("),
    ("void qemu_init_irqs(", "for (size_t i ="),
    ("qemu_irq *qemu_extend_irqs(", "s = old ? g_renew("),
    ("qemu_irq qemu_allocate_irq(", "irq = IRQ(object_new("),
    ("void qemu_free_irqs(", "for (i ="),
    ("void qemu_free_irq(", "object_unref("),
    ("void qemu_irq_set_observer(", "for (i ="),
]:
    CASES.append(("hw/core/irq.c", signature,
                  "qemu_irq_node_root_lifetime_guard();", effect))

for signature, effect in [
    ("static void node_gpio_property_release(", "for (unsigned group ="),
    ("static void node_gpio_allow_set_link(", "object_property_allow_set_link("),
    ("static NamedGPIOList *qdev_get_named_gpio_list(", "ngl = g_malloc0("),
    ("void qdev_init_gpio_in_named_with_opaque(", "gpio_list = qdev_get_named_gpio_list("),
    ("void qdev_init_gpio_out_named(", "gpio_list = qdev_get_named_gpio_list("),
    ("void qdev_connect_gpio_out_named(", "propname = g_strdup_printf("),
    ("static qemu_irq qdev_disconnect_gpio_out_named(", "propname = g_strdup_printf("),
    ("void qdev_pass_gpios(", "ngl = qdev_get_named_gpio_list("),
]:
    CASES.append(("hw/core/gpio.c", signature,
                  "qemu_irq_node_root_lifetime_guard();", effect))


def check_cases(source):
    for path, signature, guard, effect in CASES:
        body = function((source / path).read_text(), signature)
        before_effect(body, guard, effect)
        # Scoped removal/duplication and moving a guard after its original
        # effect must fail; unrelated guards cannot substitute for it.
        negatives = [body.replace(guard, "", 1),
                     body.replace(guard, guard + guard, 1)]
        if effect != "\n}":
            negatives.append(body.replace(guard, "", 1).replace(
                effect, effect + guard, 1))
        for changed in negatives:
            try:
                before_effect(changed, guard, effect)
            except ValueError:
                continue
            raise ValueError("altered native writer ordering was accepted")

    network = function((source / "net/net.c").read_text(),
                       "static int net_client_init1(")
    before_effect(network, "return 0; /* nothing to do */",
                  "qemu_crucible_endpoint_root_allocate(CRUCIBLE_ENDPOINT_NETWORK);")
    api = (source / "plugins/api-system.c").read_text()
    for predicate in [
        "!crucible_node_root_epoch_manifest_matches(epoch->epoch_version)",
        "!crucible_node_root_epoch_registered()",
    ]:
        if api.count(predicate) != 1:
            raise ValueError("dormant epoch manifest predicate changed")
    return len(CASES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    arguments = parser.parse_args()
    count = check_cases(arguments.source)
    print(f"PASS {count} exact native writer call sites and scoped ordering "
          "adversaries; net-none preserved; dormant epoch manifest guards retained")


if __name__ == "__main__":
    main()
