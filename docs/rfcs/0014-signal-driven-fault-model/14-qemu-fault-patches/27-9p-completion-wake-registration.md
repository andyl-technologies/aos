# Patch 0076: realize-time 9p completion wake registration

## Responsibility

`0076-crucible-9p-completion-wake-registration.patch` registers the 9p
completion notifier while the device is realized, independently of plugin
installation order. A completion that becomes available after the vCPU parks
must wake the QEMU main loop and drive the normal device-completion path; it
must not depend on polling, a later guest action, or host timing.

## Required behavior

- Registration occurs exactly once for each realized Crucible 9p device and is
  torn down with that device.
- Plugin installation before or after device realization produces the same
  notifier binding.
- The notifier only schedules ordinary QEMU completion work. It does not
  complete a request on the notifying thread or bypass the exact device
  boundary.
- Missing, duplicate, or failed registration is fatal before the node is
  admitted to production execution.
- QEMU without the Crucible device remains unchanged.

## Verification

The patch microtest checks both installation orders and rejects a removed
realize-time registration. The live 9p gate must park the guest, publish a
completion from the host-side 9p node, observe an event-driven wake, and verify
the exact typed response without a polling fallback. Checkpoint coverage must
repeat the same sequence after fresh-process restore.

## Boundary and licensing

This registration and callback are QEMU-side implementation and remain in the
applicable GPL scope. The Apache host sees only the versioned shared-memory 9p
request/response protocol and the scheduler wake contract. The patch commit
requires the QEMU-series DCO sign-off and is included in the retained
corresponding-source bundle.
