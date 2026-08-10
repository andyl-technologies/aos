# Patch 0047 — `crucible-fault-command-abi`

## Purpose

Adds the closed GPL-side dispatcher shell and capability registry consumed by all
later fault patches. It applies no mutation by itself. Its absence makes every
RFC-0013 node capability unavailable.

## Capability and dependencies

- Provides `qemu.fault-command-abi.v1`.
- Depends on the existing sim accelerator, plugin registration, shared-memory
  dispatch, process attestation, and generated boundary ABI.
- Precedes patches 0048–0059.

## Public protocol work

The dual-licensed boundary registry defines the header/result in
[§14.3](README.md#143-common-commandresult-protocol) and one closed payload tag
for every later patch. Generated Rust and C views use explicit
little-endian field encoding and byte arrays; the C view is not a compiler-native
wire struct. Golden vectors cover every status, maximum payload, zero reserved
fields, malformed length/offset, unknown kind, and version mismatch.

The plugin owns ring consumption and validates ABI version, semantic version,
target node identity, sequence monotonicity, bounds, payload digest, reserved
zeros, and capability before calling QEMU. QEMU revalidates kind/version/length
and never trusts a plugin pointer beyond the synchronous call.

## QEMU-side API

Adds a GPL-side registry with operations conceptually equivalent to:

```text
register_fault_handler(kind, version, capability, validate, arm, apply, save)
query_fault_capabilities()
submit_validated_fault(command_bytes, payload_bytes)
cancel_unarmed_fault(command_sequence)
```

Actual QEMU interfaces use upstream-compatible C types and explicit ownership.
Handlers are registered only by compiled patches; plugins cannot register
arbitrary functions or string-named handlers. Duplicate kind/version
registration aborts sim-mode startup. Unknown kinds return
`unsupported_capability`.

The registry stores immutable descriptors after machine realization and a
bounded command table keyed by sequence. It stores copied canonical payload
bytes, not pointers into shared memory. Payload buffers are zeroed/freed after a
result and never exposed to the host directly.

## Capability report

Each capability row contains kind, semantic version, architecture/device scope,
maximum payload, maximum pending commands, supported phases, and required later
patch-series feature bits. Rows sort by numeric kind/version/scope. The report
hash enters QEMU process identity, reproduction artifacts, and the host admission
comparison.

## Failure and security behavior

- Unsupported major ABI fails plugin initialization.
- Unknown kind/version or malformed payload returns a typed rejection before
  arming and cannot crash QEMU.
- Duplicate/replayed sequence is rejected.
- Payload offsets are validated against the shared region by the plugin, then
  copied; QEMU receives no region-relative pointer.
- Maximum pending/payload bounds come from the
  [resource contract](../13-resource-and-performance-bounds.md) and are checked
  before allocation.
- Error text is diagnostic only; canonical results use stable numeric codes.

## State and replay

The registry descriptor set is immutable and therefore not VMState. Pending
commands become VMState in patch 0059. Until 0059 lands, the aggregate gate must
remain disabled and the PR draft; patch 0047's own microtest uses no save/load.

## Live microtests

1. Load the matched plugin and query a registry containing only the ABI
   capability; verify canonical sorted bytes/hash twice.
2. Send malformed headers, payload bounds, unknown kinds, duplicate sequences,
   nonzero reserved fields, wrong node hash, and version mismatches; verify exact
   result codes and no guest/QEMU state change.
3. Fill the command table and prove the next command fails without overwrite.
4. Revert this patch and prove ABI discovery fails.
5. Run the unpatched reference and patched QEMU without sim/plugin; compare the
   inertness corpus byte-for-byte.

## Licensing checklist

Modified QEMU files retain upstream notices. Any new registry file carries the
appropriate QEMU-default or explicit GPL-compatible SPDX notice and is added to
`LICENSES.md`. Plugin changes remain GPL-2.0-only; generated boundary definitions
remain `MIT OR Apache-2.0`. The patch commit is DCO-signed and corresponding
source/catalog/series metadata update together.

- **[QFP-ABI-1]** The ABI registry MUST be closed and immutable after machine
  realization; no runtime plugin-defined mutation callback is permitted.
- **[QFP-ABI-2]** A capability report mismatch MUST stop scenario admission
  before any vCPU executes.
