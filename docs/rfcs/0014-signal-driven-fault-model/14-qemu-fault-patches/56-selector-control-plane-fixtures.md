# Selector control-plane fixture isolation

Patch `0105-crucible-selector-control-plane-fixtures.patch` keeps the live
instruction-fault selector admission tests independent of data-plane delivery.

The overlap and exclusivity modes first install a persistent selector, then
submit a second selector whose admission must fail. On AArch64, the guest can
execute the targeted instruction while synchronizing the second request. A
reachable occurrence on the first selector would therefore emit a legitimate
fault event before the fixture observes the expected control-plane rejection.

For those control-plane-only modes, the test plugin now assigns both selectors
the same unreachable occurrence. Their instruction interval, vCPU scope, and
mutation still overlap exactly as the production admission check requires, but
neither rule can fire while the fixture is preparing the second request.

This patch changes only the live QEMU test plugin. It does not change production
selector admission, matching, mutation, event ordering, or any wire format.

## Gate coverage

- `checks.crucible.phase2.qemuInstructionFaults` runs the overlap and
  exclusivity cases against live x86 and AArch64 QEMU.
- `checks.crucible.phase2.qemuPatchRegeneration` proves the patch and tracked
  QEMU branch commit are identical.
- `checks.crucible.phase2.gates.patchMicrotests.rawGate` includes both gates in
  the aggregate patch-series contract.
