# Patch 0058 — `crucible-accelerator-fault-device`

## Purpose

Provides production QEMU device paths for accelerator disappearance/reset,
result corruption, device-memory/ECC error, and service throttle across declared
GPU, TPU, and FPGA classes. It avoids claiming accelerator support from an
in-memory host test double.

## Capability and dependencies

- Provides `qemu.accelerator.lifecycle.v1`, `qemu.accelerator.result.v1`,
  `qemu.accelerator.memory.v1`, and `qemu.accelerator.service.v1`.
- Depends on 0047–0057, existing device callback/shared-memory infrastructure,
  memory/DMA hooks, hardware-error support, and deterministic service queues.

## Production device coverage

The patch provides two integration forms:

1. registration hooks for realized QEMU accelerator devices whose command,
   result, memory, lifecycle, and VMState boundaries can be completely described;
   the initial GPU coverage includes the pinned QEMU virtio-gpu device path;
2. a sim-only `virtio-crucible-accelerator` production co-simulation device with
   closed GPU-compute, tensor/TPU, and FPGA-job class descriptors. It exposes a
   versioned virtio transport to a guest and forwards bounded typed jobs/results
   through the public shared-memory protocol to the host accelerator adapter.

The co-sim device is a real QEMU device and guest transport, not a test double.
Each class requires a live fixture driver/workload, strict job schema, and result
semantics. Arbitrary vendor command streams, passthrough/VFIO hardware, host GPU
libraries, and host device timing are forbidden.

## Device/job manifest

Each device reports class, device/queue IDs, job kinds, input/output buffer
schemas, device-memory spaces/geometry, ECC/reporting modes, lifecycle states,
service units, DMA scopes, and VMState support. Job identity includes device,
queue, guest descriptor sequence, command/payload digest, and retry/replay
ordinal.

## Fault semantics

- Lifecycle transitions `reset`, `disappear`, `reconnect`, and `permanent_fail`
  declare treatment of unadmitted, queued, executing, completed, DMA-in-flight,
  and device-memory state.
- Result corruption targets registered typed result fields or exact output-buffer
  bits after execution and before guest completion; before/after digests record it.
- Device-memory events use manifest address spaces and the memory/ECC contracts,
  including corrected telemetry and uncorrectable job/device outcomes.
- Service throttle uses exact job-work/service curves, queue capacity, and
  virtual-time deadlines. It never uses host accelerator utilization or sleeps.
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

Evidence includes manifest/device identity, lifecycle/queue state, job schema and
ID, input/output digests, service ledger, DMA/device-memory changes, ECC record,
guest completion/status, and fingerprints. Patch 0059 serializes device
realization/lifecycle, queues, active jobs, service remainder, device memory,
fault rules, and pending completions.

## Live microtests

1. Run a real guest virtio-gpu workload and one job per co-sim GPU/TPU/FPGA class.
2. Apply every lifecycle state with work unadmitted, queued, executing, completed,
   and DMA-in-flight; verify declared treatment.
3. Corrupt typed scalar/vector/buffer results and prove exact guest observation.
4. Inject corrected/uncorrectable device-memory errors and verify device/guest
   outcome plus platform record where declared.
5. Throttle service at exact ratios and checkpoint mid-job/queue.
6. Fuzz descriptor/job schemas and limits; no malformed input escapes validation.
7. Revert patch and fail live device gates; prove non-sim machine enumeration and
   behavior equal unpatched QEMU.

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
