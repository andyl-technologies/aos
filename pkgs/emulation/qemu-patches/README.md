# AOS QEMU patch series

This directory contains patches applied to QEMU for Crucible. QEMU and these
modifications are on the GPL/upstream side of the
[Crucible process boundary](../../../docs/rfcs/0010-crucible/37-licensing-process-boundary.md).

Each patch follows the license of the upstream file it modifies. New QEMU-side
integration must use a GPL-compatible license, normally `GPL-2.0-only`, and must
not remove or replace a more specific upstream license notice. Commits touching
this directory require a Developer Certificate of Origin `Signed-off-by` line.

The Apache-licensed Crucible host must interact with this code only through the
versioned socket and shared-memory protocols. A release that distributes the
patched QEMU binary must also publish matching complete corresponding source as
described in [`LICENSING.md`](../../../LICENSING.md).
