//! Stream comparison and mismatch localization for the single-VM gate.

use std::error::Error;
use std::fmt;

use super::types::{SingleVmFingerprintSample, SingleVmFingerprintStream};

/// The specific way two single-VM fingerprint streams differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintMismatch {
    /// The sample index where comparison first failed.
    pub sample_index: usize,
    /// The class and payload of the mismatch.
    pub kind: SingleVmFingerprintMismatchKind,
    /// Last icount known to match before this mismatch.
    pub previous_matching_icount: Option<u64>,
    /// First icount known to differ, when the mismatch is tied to the run axis.
    pub first_different_icount: Option<u64>,
}

impl fmt::Display for SingleVmFingerprintMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SingleVmFingerprintMismatchKind::Definition { .. } => {
                write!(formatter, "fingerprint definitions differ")
            }
            SingleVmFingerprintMismatchKind::Sample {
                first,
                second,
                difference,
            } => write!(
                formatter,
                "fingerprint sample {} differs at {}: first seq={} node={} icount={}, second seq={} node={} icount={}",
                self.sample_index,
                difference.material_token(),
                first.seq,
                first.node,
                first.icount,
                second.seq,
                second.node,
                second.icount
            ),
            SingleVmFingerprintMismatchKind::Length {
                first_len,
                second_len,
            } => write!(
                formatter,
                "fingerprint streams differ in length at sample {}: first={}, second={}",
                self.sample_index, first_len, second_len
            ),
            SingleVmFingerprintMismatchKind::Final { .. } => write!(
                formatter,
                "fingerprint streams have matching samples but different final fingerprints"
            ),
        }
    }
}

impl Error for SingleVmFingerprintMismatch {}

/// The payload for a single-VM fingerprint mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintMismatchKind {
    /// The streams used different content-addressed fingerprint definitions.
    Definition {
        /// Definition digest from the first run.
        first: Vec<u8>,
        /// Definition digest from the second run.
        second: Vec<u8>,
    },
    /// A sample at the same index differs.
    Sample {
        /// Sample from the first run.
        first: Box<SingleVmFingerprintSample>,
        /// Sample from the second run.
        second: Box<SingleVmFingerprintSample>,
        /// First component that differed inside the sample material.
        difference: SingleVmFingerprintSampleDifference,
    },
    /// One stream ended before the other.
    Length {
        /// Number of samples in the first run.
        first_len: usize,
        /// Number of samples in the second run.
        second_len: usize,
    },
    /// Samples matched, but final run fingerprints differ.
    Final {
        /// Final fingerprint icount from the first run.
        first_icount: u64,
        /// Final fingerprint icount from the second run.
        second_icount: u64,
        /// Final fingerprint bytes from the first run.
        first: Vec<u8>,
        /// Final fingerprint bytes from the second run.
        second: Vec<u8>,
    },
}

/// The first sample component that differed between two fingerprint streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintSampleDifference {
    /// Sample sequence number differed.
    Sequence,
    /// Sample node identifier differed.
    Node,
    /// Aggregate node icount differed.
    Icount,
    /// Sample trigger differed.
    Trigger,
    /// The streams sampled different vCPU-set sizes.
    VcpuRegisterCount,
    /// A vCPU register entry appeared at a different index or id.
    VcpuRegisterId {
        /// Index at which the vCPU id differed.
        index: usize,
    },
    /// One vCPU's architectural register digest differed.
    VcpuRegisterDigest {
        /// vCPU whose register digest differed.
        vcpu_id: u64,
    },
    /// One vCPU's reported register-file byte count differed.
    VcpuRegisterFileBytes {
        /// vCPU whose register byte count differed.
        vcpu_id: u64,
    },
    /// One vCPU's local retired-instruction count differed.
    VcpuRetiredInstructionCount {
        /// vCPU whose retired count differed.
        vcpu_id: u64,
    },
    /// The RR cursor named a different current vCPU.
    RoundRobinCurrentVcpu,
    /// The RR cursor position within `rr_switch_quantum` differed.
    RoundRobinPositionInQuantum,
    /// The pinned RR switch quantum differed.
    RoundRobinSwitchQuantum,
    /// The guest-memory digest differed.
    GuestMemoryDigest,
    /// The device-state digest differed.
    DeviceStateDigest,
    /// Only the rolling digest differed after material comparison matched.
    RollingFingerprint,
}

impl SingleVmFingerprintSampleDifference {
    /// Returns the stable diagnostic component token.
    #[must_use]
    pub fn material_token(self) -> String {
        match self {
            Self::Sequence => "seq".to_owned(),
            Self::Node => "node".to_owned(),
            Self::Icount => "icount".to_owned(),
            Self::Trigger => "trigger".to_owned(),
            Self::VcpuRegisterCount => "vcpu_register_count".to_owned(),
            Self::VcpuRegisterId { index } => format!("vcpu_register_id[{index}]"),
            Self::VcpuRegisterDigest { vcpu_id } => {
                format!("vcpu_register_digest[{vcpu_id}]")
            }
            Self::VcpuRegisterFileBytes { vcpu_id } => {
                format!("vcpu_register_file_bytes[{vcpu_id}]")
            }
            Self::VcpuRetiredInstructionCount { vcpu_id } => {
                format!("vcpu_retired_instruction_count[{vcpu_id}]")
            }
            Self::RoundRobinCurrentVcpu => "rr_current_vcpu".to_owned(),
            Self::RoundRobinPositionInQuantum => "rr_position_in_quantum".to_owned(),
            Self::RoundRobinSwitchQuantum => "rr_switch_quantum".to_owned(),
            Self::GuestMemoryDigest => "guest_memory_digest".to_owned(),
            Self::DeviceStateDigest => "device_state_digest".to_owned(),
            Self::RollingFingerprint => "rolling_fingerprint".to_owned(),
        }
    }
}

/// Compares two single-VM fingerprint streams in canonical order.
///
/// # Errors
///
/// Returns [`SingleVmFingerprintMismatch`] at the first definition, sample,
/// length, or final-fingerprint difference.
pub fn compare_single_vm_fingerprint_streams(
    first: &SingleVmFingerprintStream,
    second: &SingleVmFingerprintStream,
    run_horizon_icount: u64,
) -> Result<(), SingleVmFingerprintMismatch> {
    if first.definition_digest != second.definition_digest {
        return Err(SingleVmFingerprintMismatch {
            sample_index: 0,
            kind: SingleVmFingerprintMismatchKind::Definition {
                first: first.definition_digest.clone(),
                second: second.definition_digest.clone(),
            },
            previous_matching_icount: None,
            first_different_icount: None,
        });
    }

    for (sample_index, (first_sample, second_sample)) in
        first.samples.iter().zip(second.samples.iter()).enumerate()
    {
        if first_sample != second_sample {
            let difference = first_sample_difference(first_sample, second_sample);
            let first_different_icount = first_sample.icount.min(second_sample.icount);
            return Err(SingleVmFingerprintMismatch {
                sample_index,
                kind: SingleVmFingerprintMismatchKind::Sample {
                    first: Box::new(first_sample.clone()),
                    second: Box::new(second_sample.clone()),
                    difference,
                },
                previous_matching_icount: previous_icount_before(
                    first,
                    sample_index,
                    first_different_icount,
                ),
                first_different_icount: Some(first_different_icount),
            });
        }
    }

    if first.samples.len() != second.samples.len() {
        let sample_index = first.samples.len().min(second.samples.len());
        let first_different_icount = first
            .samples
            .get(sample_index)
            .or_else(|| second.samples.get(sample_index))
            .map(|sample| sample.icount)
            .or(Some(run_horizon_icount));
        return Err(SingleVmFingerprintMismatch {
            sample_index,
            kind: SingleVmFingerprintMismatchKind::Length {
                first_len: first.samples.len(),
                second_len: second.samples.len(),
            },
            previous_matching_icount: previous_icount_before(
                first,
                sample_index,
                first_different_icount.unwrap_or(run_horizon_icount),
            ),
            first_different_icount,
        });
    }

    if first.final_icount != second.final_icount
        || first.final_fingerprint != second.final_fingerprint
    {
        let first_different_icount = first
            .final_icount
            .min(second.final_icount)
            .max(run_horizon_icount);
        return Err(SingleVmFingerprintMismatch {
            sample_index: first.samples.len(),
            kind: SingleVmFingerprintMismatchKind::Final {
                first_icount: first.final_icount,
                second_icount: second.final_icount,
                first: first.final_fingerprint.clone(),
                second: second.final_fingerprint.clone(),
            },
            previous_matching_icount: previous_icount_before(
                first,
                first.samples.len(),
                first_different_icount,
            ),
            first_different_icount: Some(first_different_icount),
        });
    }

    Ok(())
}

fn previous_icount_before(
    stream: &SingleVmFingerprintStream,
    sample_index: usize,
    first_different_icount: u64,
) -> Option<u64> {
    stream
        .samples
        .iter()
        .take(sample_index)
        .rev()
        .find(|sample| sample.icount < first_different_icount)
        .map(|sample| sample.icount)
}

fn first_sample_difference(
    first: &SingleVmFingerprintSample,
    second: &SingleVmFingerprintSample,
) -> SingleVmFingerprintSampleDifference {
    if first.seq != second.seq {
        return SingleVmFingerprintSampleDifference::Sequence;
    }
    if first.node != second.node {
        return SingleVmFingerprintSampleDifference::Node;
    }
    if first.icount != second.icount {
        return SingleVmFingerprintSampleDifference::Icount;
    }
    if first.trigger != second.trigger {
        return SingleVmFingerprintSampleDifference::Trigger;
    }

    let first_registers = first.nvcpu_fingerprint.vcpu_registers();
    let second_registers = second.nvcpu_fingerprint.vcpu_registers();
    if first_registers.len() != second_registers.len() {
        return SingleVmFingerprintSampleDifference::VcpuRegisterCount;
    }
    for (index, (first_register, second_register)) in first_registers
        .iter()
        .zip(second_registers.iter())
        .enumerate()
    {
        if first_register.vcpu_id() != second_register.vcpu_id() {
            return SingleVmFingerprintSampleDifference::VcpuRegisterId { index };
        }
        let vcpu_id = first_register.vcpu_id();
        if first_register.register_digest() != second_register.register_digest() {
            return SingleVmFingerprintSampleDifference::VcpuRegisterDigest { vcpu_id };
        }
        if first_register.register_file_bytes() != second_register.register_file_bytes() {
            return SingleVmFingerprintSampleDifference::VcpuRegisterFileBytes { vcpu_id };
        }
        if first_register.retired_instruction_count() != second_register.retired_instruction_count()
        {
            return SingleVmFingerprintSampleDifference::VcpuRetiredInstructionCount { vcpu_id };
        }
    }

    let first_cursor = first.nvcpu_fingerprint.rr_cursor();
    let second_cursor = second.nvcpu_fingerprint.rr_cursor();
    if first_cursor.current_vcpu() != second_cursor.current_vcpu() {
        return SingleVmFingerprintSampleDifference::RoundRobinCurrentVcpu;
    }
    if first_cursor.position_in_quantum() != second_cursor.position_in_quantum() {
        return SingleVmFingerprintSampleDifference::RoundRobinPositionInQuantum;
    }
    if first_cursor.rr_switch_quantum() != second_cursor.rr_switch_quantum() {
        return SingleVmFingerprintSampleDifference::RoundRobinSwitchQuantum;
    }
    if first.nvcpu_fingerprint.guest_memory_digest()
        != second.nvcpu_fingerprint.guest_memory_digest()
    {
        return SingleVmFingerprintSampleDifference::GuestMemoryDigest;
    }
    if first.nvcpu_fingerprint.device_state_digest()
        != second.nvcpu_fingerprint.device_state_digest()
    {
        return SingleVmFingerprintSampleDifference::DeviceStateDigest;
    }
    SingleVmFingerprintSampleDifference::RollingFingerprint
}
