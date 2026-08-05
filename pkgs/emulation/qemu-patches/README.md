# AOS QEMU patch series

This directory contains patches applied to QEMU for Crucible. QEMU and these
modifications are on the GPL/upstream side of the
[Crucible process boundary](../../../docs/rfcs/0010-crucible/37-licensing-process-boundary.md).

Each patch follows the license of the upstream file it modifies and must not
remove or replace a more specific upstream notice. New, unmarked QEMU files
inherit the default stated by QEMU's `LICENSE`, currently
`GPL-2.0-or-later`; an explicit per-file notice takes precedence. The
[`LICENSES.md`](LICENSES.md) inventory records every file created by this
series and the basis for its license. Commits touching this directory require a
Developer Certificate of Origin `Signed-off-by` line.

The Apache-licensed Crucible host must interact with this code only through the
versioned socket and shared-memory protocols. A release that distributes the
patched QEMU binary must also publish matching complete corresponding source as
described in [`LICENSING.md`](../../../LICENSING.md).
