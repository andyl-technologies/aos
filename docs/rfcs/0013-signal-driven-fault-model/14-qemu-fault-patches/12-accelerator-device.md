# Patch 0069 — `crucible-accelerator-fault-device`

## Purpose

Provides production QEMU device paths for accelerator disappearance/reset,
result corruption, device-memory/ECC error, and service throttle across declared
GPU, TPU, and FPGA classes. It avoids claiming accelerator support from an
in-memory host test double.

## Capability and dependencies

- Provides `qemu.accelerator.lifecycle.v1`, `qemu.accelerator.result.v1`,
  `qemu.accelerator.memory.v1`, and `qemu.accelerator.service.v1`.
- Depends on 0047–0068, existing device callback/shared-memory infrastructure,
  memory/DMA hooks, hardware-error support, and deterministic service queues.

## Production device coverage

The patch provides one complete integration: the sim-only
`virtio-crucible-accelerator` production co-simulation device with closed
GPU-compute, tensor/TPU, and FPGA-job classes. It exposes a versioned virtio
transport to a guest and forwards bounded typed jobs/results through the public
shared-memory protocol to the host accelerator adapter. Existing QEMU
`virtio-gpu` devices are intentionally not registered as accelerator-fault
targets: their display/command paths do not provide the closed compute-job,
device-memory, ECC, and service interfaces required by this contract. Adding a
different realized device requires a new complete device registration and gate;
there is no generic or partially functional registration path.

The co-sim device is a real QEMU device and guest transport, not a test double.
Each class requires a live fixture driver/workload, strict job schema, and result
semantics. Arbitrary vendor command streams, passthrough/VFIO hardware, host GPU
libraries, and host device timing are forbidden.

The device uses the virtio specification's vendor-specific device ID `65535`.
QEMU's ordinary `virtio_init()` path deliberately accepts only IDs present in
its standard device-name table, so patch 0069 adds `virtio_init_named()` for an
explicit static-lifetime diagnostic name and uses it only for the co-sim device.
The ordinary path retains both of its fail-fast table assertions. A generic
unknown-ID fallback is forbidden: every other vendor-specific device must make
the same explicit naming decision. The live gate must realize the PCI function;
starting QEMU and reaching guest execution is the regression for this contract.
The device class also supplies the mandatory `get_features` callback. It passes
through only the transport feature set supplied by QEMU and advertises no
device-specific optional feature bits; a missing callback is a realization
failure, not an admissible reduced mode.

## Device/job manifest

The realized-device manifest reports stable device and implementation IDs,
class and fault-family masks, queue range/depth, maximum input/output bytes,
device-memory size, ECC-mode mask, closed job-kind count, and VMState support.
The manifest codec is
[`FaultAcceleratorCapabilityRowV1`](../../../../crates/crucible-shmem/src/shmem/fault_target_manifest.rs);
the QEMU producer is
[`qemu_plugin_crucible_fault_accelerator_manifest`](../../../../pkgs/emulation/qemu-patches/0069-crucible-accelerator-fault-device.patch).

The protocol has exactly one job kind per advertised class:

| Class | Job kind | Input bytes | Output bytes | Failure conditions |
|---|---:|---|---|---|
| GPU (`1`) | vector-add (`1`) | `count: u32le`, then `count` signed `i32le` left values and `count` signed `i32le` right values | `count` checked signed `i32le` sums | zero/truncated/trailing shape, size beyond the manifest limits, or signed addition overflow |
| TPU (`2`) | matrix-multiply (`1`) | `m: u16le`, `k: u16le`, `n: u16le`, then row-major signed i8 matrices of `m*k` and `k*n` bytes | row-major `m*n` checked signed `i32le` accumulators | zero/truncated/trailing shape, size beyond the manifest limits, or signed accumulation overflow |
| FPGA (`3`) | lookup-table (`1`) | exactly 256 LUT bytes followed by input bytes | one LUT result byte per input byte | truncated LUT or output beyond the manifest limit |

The normative host execution is in
[`accelerator_io_servicer.rs`](../../../../crates/crucible-qemu/src/supervision/accelerator_io_servicer.rs).
Job identity is the immutable tuple `(device_id, generation, sequence, class,
job_kind, queue_id, service_units, output_capacity)` plus the entry payload.

## Fault semantics

- Lifecycle transitions are exactly `reset`, `disappear`, and `reconnect`, with
  explicit `preserve/clear/device_reset` treatment for pending queues and
  attached memory. Permanent loss is a persistent `disappear` rule or node
  lifecycle failure, not a fourth accelerator transition.
- Result corruption selects job kind, optional queue, and occurrence, then
  applies equal-width nonzero mask/value bytes at an exact output-buffer/result
  schema offset after execution and before guest completion; before/after
  digests record it.
- Device-memory events use manifest address spaces and the memory/ECC contracts,
  including corrected telemetry and uncorrectable job/device outcomes.
- Service throttle uses a capacity ratio in `(0,1]`, optional positive memory
  byte rate, optional positive job rate, and exact thermal/power metadata to
  update checkpointed job/queue service ledgers and virtual-time deadlines. It
  never uses host accelerator utilization or sleeps.
- Thermal/power values are signal metadata driving service/lifecycle effects;
  no separate thermal device is implied.

## Virtio co-sim transport

Descriptor parsing is strict and bounded. The plugin/device copies or references
only validated guest buffers through versioned descriptors, creates a stable job,
and waits for the host adapter's scheduler-authorized result. Completion arrives
at exact virtual time and QEMU advances the virtqueue through existing
deterministic ioeventfd/device callback mechanisms. Malformed descriptors produce
typed virtio errors without host memory unsafety.

## Evidence and VMState

Evidence is command- and manifest-authenticated by the Apache bridge. Lifecycle
records carry old/new state, state policies, generations, device ID, and memory
digests. Result records carry class/job/queue/sequence, status, output bounds,
before/after digests, and mask/value digests. Memory records carry the configured
range/ECC/syndrome, overlap, counters, before/after digests, and transform digest.
Service records carry job identity, effective capacity/rates, exact accumulator
remainders, thermal/power metadata, sizes, and state digests. Patch 0069
serializes device lifecycle, counters, service remainders, memory/ECC overlays,
terminal state, and queue continuation; the host rejects checkpoints while
requests, completions, or host jobs remain live.

## Live microtests

1. Realize device ID `65535` through `virtio_init_named()` and prove that QEMU
   reaches guest execution with the mandatory feature callback and without
   weakening `virtio_init()` validation.
2. Run one real guest virtio transport job per co-sim GPU/TPU/FPGA class.
3. Apply every lifecycle transition and queue/memory state policy with work
   unadmitted, queued, executing, completed, and DMA-in-flight; verify the exact
   treatment.
4. Corrupt typed scalar/vector/buffer results and prove exact guest observation.
5. Inject corrected/uncorrectable device-memory errors and verify device/guest
   outcome plus platform record where declared.
6. Throttle service at exact ratios and checkpoint mid-job/queue.
7. Fuzz descriptor/job schemas and limits; no malformed input escapes validation.
8. Revert patch and fail live device gates; prove machines without the co-sim
   device do not advertise accelerator fault capability.

## Licensing checklist

QEMU device and hook files follow applicable QEMU/GPL licensing and enter the
new-file inventory. The loaded plugin remains GPL-2.0-only. The host adapter uses
only the dual-licensed public transport and no QEMU/vendor library. Fixture guest
driver licensing is separately declared. DCO, notices, microtests, catalog, and
corresponding source update together.

- **[QFP-ACCEL-1]** A class is advertised only after a live QEMU device and guest
  workload exercises every registered fault family.
- **[QFP-ACCEL-2]** Host passthrough hardware or vendor runtime behavior cannot be
  canonical accelerator state.
