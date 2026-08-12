//! Production host adapter for deterministic accelerator co-simulation.
//!
//! The adapter consumes the public accelerator request ring, executes one of
//! three closed integer-only job schemas, and publishes results only after the
//! request's declared service units have elapsed in guest instruction time.
//! It does not call a host accelerator API, inspect host utilization, sleep, or
//! derive canonical state from wall time.

use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;

use crucible_shmem::{
    ACCELERATOR_STATUS_CANCELLED, AcceleratorClass, AcceleratorEntry, MappedSetupRegion,
    MappedSetupRegionAccessError, SetupRegionMapError, mmap_setup_region,
};
use thiserror::Error;

const STATUS_MALFORMED_JOB: u16 = 1;
const STATUS_UNSUPPORTED_JOB: u16 = 2;
const STATUS_ARITHMETIC_OVERFLOW: u16 = 3;

/// One accelerator servicing pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QemuLiveAcceleratorServiceStep {
    /// Requests consumed from the plugin-to-host ring.
    pub processed: usize,
    /// Completions published to the host-to-plugin ring.
    pub delivered: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingAcceleratorCompletion {
    due_icount: u64,
    completion: AcceleratorEntry,
}

/// Checkpointed host-side accelerator queue continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveAcceleratorCheckpoint {
    vm_slot: u32,
    pending: BTreeMap<(u64, u64), PendingAcceleratorCompletion>,
}

/// Production integer-only host accelerator adapter.
pub struct QemuLiveAcceleratorServicer {
    region: MappedSetupRegion,
    vm_slot: u32,
    pending: BTreeMap<(u64, u64), PendingAcceleratorCompletion>,
}

impl QemuLiveAcceleratorServicer {
    /// Maps the shared-memory accelerator rings for `vm_slot`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveAcceleratorServicerError::MapRegion`] when the public
    /// region cannot be mapped or validated.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
    ) -> Result<Self, QemuLiveAcceleratorServicerError> {
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveAcceleratorServicerError::MapRegion { source })?;
        Ok(Self {
            region,
            vm_slot,
            pending: BTreeMap::new(),
        })
    }

    /// Returns the earliest pending completion coordinate.
    #[must_use]
    pub fn next_completion_icount(&self) -> Option<u64> {
        self.pending
            .values()
            .map(|completion| completion.due_icount)
            .min()
    }

    /// Reports whether any accelerator request, completion, or host job is live.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveAcceleratorServicerError`] when either shared-memory
    /// ring has invalid geometry or corrupt producer/consumer indices.
    pub fn has_pending_work(&mut self) -> Result<bool, QemuLiveAcceleratorServicerError> {
        let rings = self
            .region
            .host_accelerator_rings_mut(self.vm_slot)
            .map_err(|source| QemuLiveAcceleratorServicerError::RegionAccess { source })?;
        let requests = rings
            .requests
            .live_len()
            .map_err(|source| QemuLiveAcceleratorServicerError::Ring { source })?;
        let completions = rings
            .completions
            .live_len()
            .map_err(|source| QemuLiveAcceleratorServicerError::Ring { source })?;
        Ok(!self.pending.is_empty() || requests != 0 || completions != 0)
    }

    /// Drains requests and publishes completions due at `guest_icount`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveAcceleratorServicerError`] for malformed shared-memory
    /// state, duplicate identities, coordinate overflow, or completion-ring
    /// backpressure. The request is never silently discarded.
    pub fn service(
        &mut self,
        guest_icount: u64,
    ) -> Result<QemuLiveAcceleratorServiceStep, QemuLiveAcceleratorServicerError> {
        let mut step = QemuLiveAcceleratorServiceStep::default();
        loop {
            let request = {
                let mut rings = self
                    .region
                    .host_accelerator_rings_mut(self.vm_slot)
                    .map_err(|source| QemuLiveAcceleratorServicerError::RegionAccess { source })?;
                rings
                    .requests
                    .dequeue()
                    .map_err(|source| QemuLiveAcceleratorServicerError::Ring { source })?
            };
            let Some(request) = request else { break };
            let identity = (request.generation(), request.sequence());
            if request.is_cancellation() {
                if let Some(pending) = self.pending.get(&identity) {
                    if !same_job_envelope(request, pending.completion) {
                        return Err(QemuLiveAcceleratorServicerError::CancellationMismatch {
                            generation: identity.0,
                            sequence: identity.1,
                        });
                    }
                }
                let completion = completion_for(request, ACCELERATOR_STATUS_CANCELLED, &[])?;
                self.pending.insert(
                    identity,
                    PendingAcceleratorCompletion {
                        due_icount: guest_icount,
                        completion,
                    },
                );
                step.processed += 1;
                continue;
            }
            if self.pending.contains_key(&identity) {
                return Err(QemuLiveAcceleratorServicerError::DuplicateRequest {
                    generation: identity.0,
                    sequence: identity.1,
                });
            }
            let (due_icount, completion) = match guest_icount.checked_add(request.service_units()) {
                Some(due_icount) => (due_icount, execute_request(request)?),
                None => (
                    guest_icount,
                    completion_for(request, STATUS_MALFORMED_JOB, &[])?,
                ),
            };
            self.pending.insert(
                identity,
                PendingAcceleratorCompletion {
                    due_icount,
                    completion,
                },
            );
            step.processed += 1;
        }

        let due = self
            .pending
            .iter()
            .filter(|(_identity, completion)| completion.due_icount <= guest_icount)
            .map(|(identity, _completion)| *identity)
            .collect::<Vec<_>>();
        for identity in due {
            let completion = self
                .pending
                .get(&identity)
                .ok_or(QemuLiveAcceleratorServicerError::InternalMissingCompletion)?
                .completion;
            {
                let mut rings = self
                    .region
                    .host_accelerator_rings_mut(self.vm_slot)
                    .map_err(|source| QemuLiveAcceleratorServicerError::RegionAccess { source })?;
                rings
                    .completions
                    .enqueue(completion)
                    .map_err(|source| QemuLiveAcceleratorServicerError::Ring { source })?;
            }
            self.pending.remove(&identity);
            step.delivered += 1;
        }
        Ok(step)
    }

    /// Captures pending host-side accelerator work.
    #[must_use]
    pub fn checkpoint(&self) -> QemuLiveAcceleratorCheckpoint {
        QemuLiveAcceleratorCheckpoint {
            vm_slot: self.vm_slot,
            pending: self.pending.clone(),
        }
    }

    /// Restores pending host-side accelerator work atomically.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveAcceleratorServicerError::CheckpointBindingMismatch`]
    /// when the checkpoint belongs to another VM slot.
    pub fn restore_checkpoint(
        &mut self,
        checkpoint: &QemuLiveAcceleratorCheckpoint,
    ) -> Result<(), QemuLiveAcceleratorServicerError> {
        if checkpoint.vm_slot != self.vm_slot {
            return Err(QemuLiveAcceleratorServicerError::CheckpointBindingMismatch);
        }
        self.pending = checkpoint.pending.clone();
        Ok(())
    }

    /// Validates that `checkpoint` belongs to this VM slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveAcceleratorServicerError::CheckpointBindingMismatch`]
    /// when the checkpoint belongs to another VM slot.
    pub fn validate_checkpoint(
        &self,
        checkpoint: &QemuLiveAcceleratorCheckpoint,
    ) -> Result<(), QemuLiveAcceleratorServicerError> {
        if checkpoint.vm_slot != self.vm_slot {
            return Err(QemuLiveAcceleratorServicerError::CheckpointBindingMismatch);
        }
        Ok(())
    }
}

fn same_job_envelope(request: AcceleratorEntry, completion: AcceleratorEntry) -> bool {
    request.device_id() == completion.device_id()
        && request.class() == completion.class()
        && request.job_kind() == completion.job_kind()
        && request.queue_id() == completion.queue_id()
        && request.service_units() == completion.service_units()
        && request.output_capacity() == completion.output_capacity()
}

fn execute_request(
    request: AcceleratorEntry,
) -> Result<AcceleratorEntry, QemuLiveAcceleratorServicerError> {
    let input = request
        .data()
        .map_err(|source| QemuLiveAcceleratorServicerError::Entry { source })?;
    let capacity = request.output_capacity() as usize;
    let (status, output) = match (request.class(), request.job_kind()) {
        (class, 1) if class == AcceleratorClass::Gpu as u16 => {
            execute_gpu_vector_add(input, capacity)
        }
        (class, 1) if class == AcceleratorClass::Tpu as u16 => {
            execute_tpu_i8_matmul(input, capacity)
        }
        (class, 1) if class == AcceleratorClass::Fpga as u16 => execute_fpga_lut(input, capacity),
        _ => (STATUS_UNSUPPORTED_JOB, Vec::new()),
    };
    completion_for(request, status, &output)
}

fn completion_for(
    request: AcceleratorEntry,
    status: u16,
    output: &[u8],
) -> Result<AcceleratorEntry, QemuLiveAcceleratorServicerError> {
    let class = match request.class() {
        1 => AcceleratorClass::Gpu,
        2 => AcceleratorClass::Tpu,
        3 => AcceleratorClass::Fpga,
        _ => return Err(QemuLiveAcceleratorServicerError::UnknownClass),
    };
    AcceleratorEntry::new(
        request.sequence(),
        request.generation(),
        request.device_id(),
        class,
        request.job_kind(),
        request.queue_id(),
        status,
        true,
        request.service_units(),
        request.output_capacity(),
        output,
    )
    .map_err(|source| QemuLiveAcceleratorServicerError::Entry { source })
}

fn execute_gpu_vector_add(input: &[u8], capacity: usize) -> (u16, Vec<u8>) {
    let Some(count_bytes) = input.get(..4) else {
        return (STATUS_MALFORMED_JOB, Vec::new());
    };
    let count = u32::from_le_bytes(count_bytes.try_into().unwrap_or([0; 4])) as usize;
    let Some(vector_bytes) = count.checked_mul(8) else {
        return (STATUS_MALFORMED_JOB, Vec::new());
    };
    if input.len() != 4 + vector_bytes || count.checked_mul(4).is_none_or(|len| len > capacity) {
        return (STATUS_MALFORMED_JOB, Vec::new());
    }
    let mut output = Vec::with_capacity(count * 4);
    for index in 0..count {
        let lhs_at = 4 + index * 4;
        let rhs_at = 4 + count * 4 + index * 4;
        let lhs = i32::from_le_bytes(input[lhs_at..lhs_at + 4].try_into().unwrap_or([0; 4]));
        let rhs = i32::from_le_bytes(input[rhs_at..rhs_at + 4].try_into().unwrap_or([0; 4]));
        let Some(sum) = lhs.checked_add(rhs) else {
            return (STATUS_ARITHMETIC_OVERFLOW, Vec::new());
        };
        output.extend_from_slice(&sum.to_le_bytes());
    }
    (0, output)
}

fn execute_tpu_i8_matmul(input: &[u8], capacity: usize) -> (u16, Vec<u8>) {
    let Some(header) = input.get(..6) else {
        return (STATUS_MALFORMED_JOB, Vec::new());
    };
    let m = u16::from_le_bytes([header[0], header[1]]) as usize;
    let k = u16::from_le_bytes([header[2], header[3]]) as usize;
    let n = u16::from_le_bytes([header[4], header[5]]) as usize;
    let Some(lhs_len) = m.checked_mul(k) else {
        return (STATUS_MALFORMED_JOB, Vec::new());
    };
    let Some(rhs_len) = k.checked_mul(n) else {
        return (STATUS_MALFORMED_JOB, Vec::new());
    };
    let Some(expected) = 6usize
        .checked_add(lhs_len)
        .and_then(|v| v.checked_add(rhs_len))
    else {
        return (STATUS_MALFORMED_JOB, Vec::new());
    };
    if m == 0 || k == 0 || n == 0 || input.len() != expected {
        return (STATUS_MALFORMED_JOB, Vec::new());
    }
    let lhs = &input[6..6 + lhs_len];
    let rhs = &input[6 + lhs_len..];
    let Some(output_len) = m.checked_mul(n).and_then(|v| v.checked_mul(4)) else {
        return (STATUS_MALFORMED_JOB, Vec::new());
    };
    if output_len > capacity {
        return (STATUS_MALFORMED_JOB, Vec::new());
    }
    let mut output = Vec::with_capacity(output_len);
    for row in 0..m {
        for column in 0..n {
            let mut sum = 0_i32;
            for inner in 0..k {
                let product = i32::from(lhs[row * k + inner] as i8)
                    * i32::from(rhs[inner * n + column] as i8);
                let Some(next) = sum.checked_add(product) else {
                    return (STATUS_ARITHMETIC_OVERFLOW, Vec::new());
                };
                sum = next;
            }
            output.extend_from_slice(&sum.to_le_bytes());
        }
    }
    (0, output)
}

fn execute_fpga_lut(input: &[u8], capacity: usize) -> (u16, Vec<u8>) {
    if input.len() < 256 {
        return (STATUS_MALFORMED_JOB, Vec::new());
    }
    let (lut, values) = input.split_at(256);
    if values.len() > capacity {
        return (STATUS_MALFORMED_JOB, Vec::new());
    }
    let output = values.iter().map(|value| lut[*value as usize]).collect();
    (0, output)
}

/// Production accelerator adapter failure.
#[derive(Debug, Error)]
pub enum QemuLiveAcceleratorServicerError {
    /// The public shared-memory region could not be mapped.
    #[error("map accelerator shared-memory region: {source}")]
    MapRegion { source: SetupRegionMapError },
    /// A typed mapped segment was invalid.
    #[error("access accelerator shared-memory region: {source}")]
    RegionAccess {
        source: MappedSetupRegionAccessError,
    },
    /// A ring operation failed.
    #[error("accelerator ring operation failed: {source}")]
    Ring {
        source: crucible_shmem::SpscRingError,
    },
    /// A fixed accelerator entry was invalid.
    #[error("accelerator entry is invalid: {source}")]
    Entry {
        source: crucible_shmem::AcceleratorEntryError,
    },
    /// The same generation/sequence appeared twice.
    #[error("duplicate accelerator request generation {generation} sequence {sequence}")]
    DuplicateRequest { generation: u64, sequence: u64 },
    /// A cancellation did not match the immutable envelope of its request.
    #[error(
        "accelerator cancellation generation {generation} sequence {sequence} does not match its request"
    )]
    CancellationMismatch { generation: u64, sequence: u64 },
    /// Completion time overflowed the coordinate space.
    #[error("accelerator service coordinate overflow at {guest_icount} + {service_units}")]
    ServiceCoordinateOverflow {
        guest_icount: u64,
        service_units: u64,
    },
    /// A validated entry carried an unknown class.
    #[error("validated accelerator entry carried an unknown class")]
    UnknownClass,
    /// Internal queue identity disappeared between selection and commit.
    #[error("selected accelerator completion disappeared before publication")]
    InternalMissingCompletion,
    /// A checkpoint belonged to another VM slot.
    #[error("accelerator checkpoint VM-slot binding mismatch")]
    CheckpointBindingMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_job_schemas_are_integer_only_and_strict() {
        let mut gpu = 2_u32.to_le_bytes().to_vec();
        gpu.extend_from_slice(&1_i32.to_le_bytes());
        gpu.extend_from_slice(&2_i32.to_le_bytes());
        gpu.extend_from_slice(&3_i32.to_le_bytes());
        gpu.extend_from_slice(&4_i32.to_le_bytes());
        assert_eq!(
            execute_gpu_vector_add(&gpu, 8),
            (0, [4_i32.to_le_bytes(), 6_i32.to_le_bytes()].concat())
        );
        assert_eq!(
            execute_gpu_vector_add(&gpu[..gpu.len() - 1], 8).0,
            STATUS_MALFORMED_JOB
        );

        let mut fpga = (0_u8..=255).rev().collect::<Vec<_>>();
        fpga.extend_from_slice(&[0, 1, 255]);
        assert_eq!(execute_fpga_lut(&fpga, 3), (0, vec![255, 254, 0]));

        let mut tpu = vec![1, 0, 2, 0, 1, 0, 2, 3, 4, 5];
        assert_eq!(
            execute_tpu_i8_matmul(&tpu, 4),
            (0, 23_i32.to_le_bytes().to_vec())
        );
        tpu.push(0);
        assert_eq!(execute_tpu_i8_matmul(&tpu, 4).0, STATUS_MALFORMED_JOB);
    }
}
