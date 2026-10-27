"""Proves a new installed kernel boot after QEMU/vTPM process power loss."""

from uuid import UUID


def power_cycle_and_require_new_boot(machine):
    """Retains backing state and rejects an unchanged or invalid boot identity."""
    previous = UUID(machine.succeed("cat /proc/sys/kernel/random/boot_id").strip())
    assert previous.int != 0, previous

    machine.power_cycle()

    current = UUID(machine.succeed("cat /proc/sys/kernel/random/boot_id").strip())
    assert current.int != 0 and current != previous, (previous, current)
