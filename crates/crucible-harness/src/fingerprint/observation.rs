//! Host-side observation boundary for execution-fingerprint samples.
//!
//! The sampling code in this module asks a backend for black-box state digests
//! and folds the returned bytes into the fixed fingerprint definition. It does
//! not require guest cooperation and does not read wall-clock time.

use std::error::Error;
use std::fmt;

use super::definition::FINGERPRINT_DIGEST_BYTES;
use super::definition::{FingerprintDefinition, FingerprintDigest, FingerprintSampleTrigger};
use super::hasher::FingerprintHasher;
use super::stream::FingerprintSample;

/// Host-observed architectural register state for one vCPU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcpuRegisterDigest {
    vcpu_id: u64,
    register_digest: FingerprintDigest,
    retired_instruction_count: u64,
}

impl VcpuRegisterDigest {
    /// Builds a host-observed vCPU register digest.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintSampleError::InvalidDigestLength`] when
    /// `register_digest` is not the fixed execution-fingerprint digest length.
    pub fn new(
        vcpu_id: u64,
        register_digest: impl Into<FingerprintDigest>,
        retired_instruction_count: u64,
    ) -> Result<Self, FingerprintSampleError> {
        let register_digest = register_digest.into();
        validate_digest_len("register_digest", &register_digest)?;
        Ok(Self {
            vcpu_id,
            register_digest,
            retired_instruction_count,
        })
    }

    /// Returns the vCPU identifier.
    #[must_use]
    pub fn vcpu_id(&self) -> u64 {
        self.vcpu_id
    }

    /// Returns the digest of the architectural register file.
    #[must_use]
    pub fn register_digest(&self) -> &[u8] {
        &self.register_digest
    }

    /// Returns the vCPU-local retired-instruction count.
    #[must_use]
    pub fn retired_instruction_count(&self) -> u64 {
        self.retired_instruction_count
    }
}

/// The retired-instruction count for one vCPU in the RR scheduler state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VcpuRetiredCount {
    vcpu_id: u64,
    retired_instruction_count: u64,
}

impl VcpuRetiredCount {
    /// Builds a per-vCPU retired-instruction count.
    #[must_use]
    pub fn new(vcpu_id: u64, retired_instruction_count: u64) -> Self {
        Self {
            vcpu_id,
            retired_instruction_count,
        }
    }

    /// Returns the vCPU identifier.
    #[must_use]
    pub fn vcpu_id(&self) -> u64 {
        self.vcpu_id
    }

    /// Returns the vCPU-local retired-instruction count.
    #[must_use]
    pub fn retired_instruction_count(&self) -> u64 {
        self.retired_instruction_count
    }
}

/// Host-observed RR scheduler state included in the fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrSchedulerState {
    current_vcpu: u64,
    quantum_remaining: u64,
    per_vcpu_retired: Vec<VcpuRetiredCount>,
}

impl RrSchedulerState {
    /// Builds a host-observed RR scheduler state snapshot.
    ///
    /// Per-vCPU retired counts are sorted by vCPU id so equivalent host
    /// observations hash identically regardless of collection order.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintSampleError::EmptyVcpuSet`] when no retired counts
    /// are provided, or [`FingerprintSampleError::DuplicateVcpu`] when a vCPU id
    /// appears more than once.
    pub fn new(
        current_vcpu: u64,
        quantum_remaining: u64,
        per_vcpu_retired: Vec<VcpuRetiredCount>,
    ) -> Result<Self, FingerprintSampleError> {
        let per_vcpu_retired = sorted_counts(per_vcpu_retired)?;
        Ok(Self {
            current_vcpu,
            quantum_remaining,
            per_vcpu_retired,
        })
    }

    /// Returns the current RR vCPU cursor.
    #[must_use]
    pub fn current_vcpu(&self) -> u64 {
        self.current_vcpu
    }

    /// Returns the remaining aggregate-icount units in the current quantum.
    #[must_use]
    pub fn quantum_remaining(&self) -> u64 {
        self.quantum_remaining
    }

    /// Returns sorted per-vCPU retired-instruction counts.
    #[must_use]
    pub fn per_vcpu_retired(&self) -> &[VcpuRetiredCount] {
        &self.per_vcpu_retired
    }
}

/// The host-side sample position requested from a backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintObservationRequest {
    /// Monotonic sample number within the stream.
    pub seq: u64,
    /// Stable node identifier associated with this sample.
    pub node: String,
    /// Node-local instruction count at the sample point.
    pub icount: u64,
    /// The deterministic reason this sample is taken.
    pub trigger: FingerprintSampleTrigger,
}

/// A host-side black-box observation boundary for execution fingerprints.
pub trait FingerprintObserver {
    /// Reads one atomic host-side fingerprint observation.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintObservationError`] when the backend cannot provide a
    /// stable host-side observation at the requested sample point.
    fn observe_sample(
        &mut self,
        request: &FingerprintObservationRequest,
        definition: &FingerprintDefinition,
    ) -> Result<HostFingerprintObservation, FingerprintObservationError>;
}

/// One atomic host-side observation used to build a fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostFingerprintObservation {
    /// The aggregate icount observed by the backend with the sampled state.
    pub observed_icount: u64,
    /// Register digests for every vCPU.
    pub vcpu_registers: Vec<VcpuRegisterDigest>,
    /// RR scheduler state sampled with the registers and memory/device digests.
    pub rr_scheduler: RrSchedulerState,
    /// Memory digest selected by the fixed fingerprint definition.
    pub memory_digest: FingerprintDigest,
    /// Emulated device-state digest sampled with memory and registers.
    pub device_digest: FingerprintDigest,
}

/// A backend observation error reported through the fingerprint sampler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintObservationError {
    message: String,
}

impl FingerprintObservationError {
    /// Builds a host-observation error.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend-provided error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FingerprintObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for FingerprintObservationError {}

/// Host-observed state used to construct one execution-fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintSampleMaterial {
    seq: u64,
    node: String,
    icount: u64,
    trigger: FingerprintSampleTrigger,
    vcpu_registers: Vec<VcpuRegisterDigest>,
    rr_scheduler: RrSchedulerState,
    memory_digest: FingerprintDigest,
    device_digest: FingerprintDigest,
}

impl FingerprintSampleMaterial {
    /// Builds one host-observed fingerprint sample material record.
    ///
    /// vCPU register digests are sorted by vCPU id so equivalent observations
    /// hash identically regardless of collection order.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintSampleError::EmptyNode`],
    /// [`FingerprintSampleError::EmptyVcpuSet`], or
    /// [`FingerprintSampleError::DuplicateVcpu`] when the material cannot define
    /// one unambiguous sample.
    pub fn new(
        request: FingerprintObservationRequest,
        vcpu_registers: Vec<VcpuRegisterDigest>,
        rr_scheduler: RrSchedulerState,
        memory_digest: impl Into<FingerprintDigest>,
        device_digest: impl Into<FingerprintDigest>,
    ) -> Result<Self, FingerprintSampleError> {
        if request.node.is_empty() {
            return Err(FingerprintSampleError::EmptyNode);
        }
        let vcpu_registers = sorted_registers(vcpu_registers)?;
        validate_matching_vcpu_sets(&vcpu_registers, &rr_scheduler)?;
        let memory_digest = memory_digest.into();
        let device_digest = device_digest.into();
        validate_digest_len("memory_digest", &memory_digest)?;
        validate_digest_len("device_digest", &device_digest)?;
        Ok(Self {
            seq: request.seq,
            node: request.node,
            icount: request.icount,
            trigger: request.trigger,
            vcpu_registers,
            rr_scheduler,
            memory_digest,
            device_digest,
        })
    }

    /// Returns the monotonic sample number.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the stable node identifier.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the aggregate node icount at the sample point.
    #[must_use]
    pub fn icount(&self) -> u64 {
        self.icount
    }

    /// Returns the deterministic reason this sample is taken.
    #[must_use]
    pub fn trigger(&self) -> FingerprintSampleTrigger {
        self.trigger
    }

    /// Returns sorted vCPU register digests.
    #[must_use]
    pub fn vcpu_registers(&self) -> &[VcpuRegisterDigest] {
        &self.vcpu_registers
    }

    /// Returns the host-observed RR scheduler state.
    #[must_use]
    pub fn rr_scheduler(&self) -> &RrSchedulerState {
        &self.rr_scheduler
    }

    /// Returns the host-observed memory digest.
    #[must_use]
    pub fn memory_digest(&self) -> &[u8] {
        &self.memory_digest
    }

    /// Returns the host-observed device-state digest.
    #[must_use]
    pub fn device_digest(&self) -> &[u8] {
        &self.device_digest
    }
}

/// A validation or observation error for a fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FingerprintSampleError {
    /// Node identifiers must be stable and non-empty.
    EmptyNode,
    /// Every sample must include at least one vCPU.
    EmptyVcpuSet,
    /// A vCPU id appeared more than once.
    DuplicateVcpu {
        /// The duplicated vCPU id.
        vcpu_id: u64,
    },
    /// Register and RR scheduler state named different vCPU sets.
    MismatchedVcpuSet,
    /// The current RR cursor did not point to a sampled vCPU.
    CurrentVcpuMissing {
        /// The current vCPU cursor reported by the RR scheduler.
        current_vcpu: u64,
    },
    /// A digest did not use the fixed 256-bit shape.
    InvalidDigestLength {
        /// The digest field that had the wrong length.
        field: &'static str,
        /// The number of bytes provided.
        len: usize,
    },
    /// The backend did not sample state at the requested aggregate icount.
    ObservedIcountMismatch {
        /// The requested aggregate icount.
        requested: u64,
        /// The aggregate icount reported by the backend observation.
        observed: u64,
    },
    /// The sample was requested away from the fixed cadence.
    OffCadence {
        /// The offending aggregate icount.
        icount: u64,
        /// The rejected sample trigger.
        trigger: FingerprintSampleTrigger,
    },
    /// The host-side observation boundary failed.
    Observation {
        /// The backend observation error.
        source: FingerprintObservationError,
    },
}

impl fmt::Display for FingerprintSampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNode => write!(
                formatter,
                "execution-fingerprint node identifier must be non-empty"
            ),
            Self::EmptyVcpuSet => write!(
                formatter,
                "execution-fingerprint sample must include at least one vCPU"
            ),
            Self::DuplicateVcpu { vcpu_id } => write!(
                formatter,
                "execution-fingerprint sample contains duplicate vCPU id {vcpu_id}"
            ),
            Self::MismatchedVcpuSet => write!(
                formatter,
                "execution-fingerprint register and RR scheduler vCPU sets differ"
            ),
            Self::CurrentVcpuMissing { current_vcpu } => write!(
                formatter,
                "execution-fingerprint current vCPU {current_vcpu} is missing from sampled state"
            ),
            Self::InvalidDigestLength { field, len } => write!(
                formatter,
                "execution-fingerprint {field} digest length {len} is not {FINGERPRINT_DIGEST_BYTES} bytes"
            ),
            Self::ObservedIcountMismatch {
                requested,
                observed,
            } => write!(
                formatter,
                "execution-fingerprint observed icount {observed} does not match requested icount {requested}"
            ),
            Self::OffCadence { icount, trigger } => write!(
                formatter,
                "execution-fingerprint sample at icount {icount} is off cadence for {trigger:?}"
            ),
            Self::Observation { source } => {
                write!(
                    formatter,
                    "execution-fingerprint observation failed: {source}"
                )
            }
        }
    }
}

impl Error for FingerprintSampleError {}

/// Observes and computes one rolling fingerprint sample through a host boundary.
///
/// # Errors
///
/// Returns [`FingerprintSampleError`] when observation fails, vCPU state is
/// ambiguous, or the sample is not allowed by the fixed cadence.
pub fn observe_fingerprint_sample<Observer: FingerprintObserver>(
    definition: &FingerprintDefinition,
    previous_rolling_fingerprint: &[u8],
    request: FingerprintObservationRequest,
    observer: &mut Observer,
) -> Result<FingerprintSample, FingerprintSampleError> {
    let observed = observer
        .observe_sample(&request, definition)
        .map_err(|source| FingerprintSampleError::Observation { source })?;
    if observed.observed_icount != request.icount {
        return Err(FingerprintSampleError::ObservedIcountMismatch {
            requested: request.icount,
            observed: observed.observed_icount,
        });
    }
    let material = FingerprintSampleMaterial::new(
        request,
        observed.vcpu_registers,
        observed.rr_scheduler,
        observed.memory_digest,
        observed.device_digest,
    )?;

    compute_fingerprint_sample(definition, previous_rolling_fingerprint, &material)
}

/// Computes one rolling execution-fingerprint sample.
///
/// # Errors
///
/// Returns [`FingerprintSampleError::OffCadence`] when `material` is not at the
/// fixed periodic cadence or an allowed deterministic event boundary.
pub fn compute_fingerprint_sample(
    definition: &FingerprintDefinition,
    previous_rolling_fingerprint: &[u8],
    material: &FingerprintSampleMaterial,
) -> Result<FingerprintSample, FingerprintSampleError> {
    if !definition.accepts_sample(material.icount, material.trigger) {
        return Err(FingerprintSampleError::OffCadence {
            icount: material.icount,
            trigger: material.trigger,
        });
    }

    let mut hasher = FingerprintHasher::new();
    hasher.write_tag("fingerprint-sample");
    hasher.write_bytes(&definition.digest());
    hasher.write_bytes(previous_rolling_fingerprint);
    hasher.write_u64(material.seq);
    hasher.write_bytes(material.node.as_bytes());
    hasher.write_u64(material.icount);
    write_trigger(&mut hasher, material.trigger);
    write_registers(&mut hasher, &material.vcpu_registers);
    write_rr_scheduler(&mut hasher, &material.rr_scheduler);
    hasher.write_bytes(&material.memory_digest);
    hasher.write_bytes(&material.device_digest);

    Ok(FingerprintSample {
        seq: material.seq,
        node: material.node.clone(),
        icount: material.icount,
        trigger: material.trigger,
        rolling_fingerprint: hasher.finish(),
    })
}

fn write_trigger(hasher: &mut FingerprintHasher, trigger: FingerprintSampleTrigger) {
    hasher.write_tag(match trigger {
        FingerprintSampleTrigger::Periodic => "periodic",
        FingerprintSampleTrigger::Event(event) => match event {
            super::definition::FingerprintEventBoundary::HorizonAdvance => "horizon-advance",
            super::definition::FingerprintEventBoundary::FrameDelivery => "frame-delivery",
            super::definition::FingerprintEventBoundary::FaultActivation => "fault-activation",
        },
    });
}

fn write_registers(hasher: &mut FingerprintHasher, registers: &[VcpuRegisterDigest]) {
    hasher.write_u64(registers.len() as u64);
    for register in registers {
        hasher.write_u64(register.vcpu_id);
        hasher.write_bytes(&register.register_digest);
        hasher.write_u64(register.retired_instruction_count);
    }
}

fn write_rr_scheduler(hasher: &mut FingerprintHasher, state: &RrSchedulerState) {
    hasher.write_u64(state.current_vcpu);
    hasher.write_u64(state.quantum_remaining);
    hasher.write_u64(state.per_vcpu_retired.len() as u64);
    for count in &state.per_vcpu_retired {
        hasher.write_u64(count.vcpu_id);
        hasher.write_u64(count.retired_instruction_count);
    }
}

fn sorted_registers(
    mut registers: Vec<VcpuRegisterDigest>,
) -> Result<Vec<VcpuRegisterDigest>, FingerprintSampleError> {
    if registers.is_empty() {
        return Err(FingerprintSampleError::EmptyVcpuSet);
    }
    registers.sort_by_key(|register| register.vcpu_id);
    reject_duplicate_vcpus(registers.iter().map(|register| register.vcpu_id))?;
    Ok(registers)
}

fn sorted_counts(
    mut counts: Vec<VcpuRetiredCount>,
) -> Result<Vec<VcpuRetiredCount>, FingerprintSampleError> {
    if counts.is_empty() {
        return Err(FingerprintSampleError::EmptyVcpuSet);
    }
    counts.sort_by_key(|count| count.vcpu_id);
    reject_duplicate_vcpus(counts.iter().map(|count| count.vcpu_id))?;
    Ok(counts)
}

fn validate_matching_vcpu_sets(
    registers: &[VcpuRegisterDigest],
    rr_scheduler: &RrSchedulerState,
) -> Result<(), FingerprintSampleError> {
    if !registers
        .iter()
        .any(|register| register.vcpu_id == rr_scheduler.current_vcpu)
    {
        return Err(FingerprintSampleError::CurrentVcpuMissing {
            current_vcpu: rr_scheduler.current_vcpu,
        });
    }

    let register_ids = registers
        .iter()
        .map(|register| register.vcpu_id)
        .collect::<Vec<_>>();
    let rr_ids = rr_scheduler
        .per_vcpu_retired
        .iter()
        .map(|count| count.vcpu_id)
        .collect::<Vec<_>>();
    if register_ids != rr_ids {
        return Err(FingerprintSampleError::MismatchedVcpuSet);
    }

    Ok(())
}

fn validate_digest_len(field: &'static str, digest: &[u8]) -> Result<(), FingerprintSampleError> {
    if digest.len() == FINGERPRINT_DIGEST_BYTES {
        Ok(())
    } else {
        Err(FingerprintSampleError::InvalidDigestLength {
            field,
            len: digest.len(),
        })
    }
}

fn reject_duplicate_vcpus(
    vcpu_ids: impl IntoIterator<Item = u64>,
) -> Result<(), FingerprintSampleError> {
    let mut previous = None;
    for vcpu_id in vcpu_ids {
        if previous == Some(vcpu_id) {
            return Err(FingerprintSampleError::DuplicateVcpu { vcpu_id });
        }
        previous = Some(vcpu_id);
    }
    Ok(())
}
