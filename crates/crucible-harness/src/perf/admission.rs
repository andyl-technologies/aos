//! Host-parallelism admission classes and the canonical mechanism register.
//!
//! Every host-parallel mechanism is recorded as either Class A (work outside
//! the guest-observable boundary) or Class B (observable work whose commit
//! coordinate is fixed before dispatch). The perf gate validates this register
//! so an optimization cannot silently bypass the determinism argument in RFC
//! 0010 section 25.12.1.

use std::collections::BTreeSet;

use super::report::PerfBenchError;

/// Stable identifier for cross-node host-worker execution.
pub const HOST_WORKER_POOL: &str = "scheduler-host-worker-pool";
/// Stable identifier for asynchronous execution-fingerprint digestion.
pub const FINGERPRINT_DIGEST_OFFLOAD: &str = "fingerprint-digest-offload";
/// Stable identifier for device-side host-work overlap.
pub const DEVICE_WORK_OVERLAP: &str = "device-host-work-overlap";
/// Stable identifier for translation-prefetch experimentation.
pub const TRANSLATION_PREFETCH: &str = "translation-prefetch";
/// Stable identifier for segment-parallel replay.
pub const SEGMENT_PARALLEL_REPLAY: &str = "segment-parallel-replay";

const REQUIRED_MECHANISMS: [&str; 5] = [
    HOST_WORKER_POOL,
    FINGERPRINT_DIGEST_OFFLOAD,
    DEVICE_WORK_OVERLAP,
    TRANSLATION_PREFETCH,
    SEGMENT_PARALLEL_REPLAY,
];
const PROVING_GATES: [&str; 6] = [
    "gate:adversarial-determinism",
    "gate:divergence-bisect",
    "gate:e2e-determinism",
    "gate:perf-bench",
    "gate:replay-oracle",
    "gate:single-vm-fingerprint",
];

/// Classifies why host-parallel work is deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostParallelismClass {
    /// The work cannot affect guest state, fingerprints, or canonical logs.
    OutsideObservableBoundary,
    /// The observable commit coordinate is fixed before host dispatch.
    CommitPinnedToVirtualTime,
}

/// Records one admitted host-parallel mechanism and its proving gates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostParallelismAdmission {
    /// Stable mechanism identifier.
    pub mechanism: String,
    /// Determinism admission class.
    pub class: HostParallelismClass,
    /// Human-readable argument explaining why the class applies.
    pub argument: String,
    /// Canonical gates that prove the class argument.
    pub proving_gates: Vec<String>,
}

impl HostParallelismAdmission {
    /// Builds one host-parallelism admission record.
    #[must_use]
    pub fn new(
        mechanism: impl Into<String>,
        class: HostParallelismClass,
        argument: impl Into<String>,
        proving_gates: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            mechanism: mechanism.into(),
            class,
            argument: argument.into(),
            proving_gates: proving_gates.into_iter().map(Into::into).collect(),
        }
    }
}

/// Returns the canonical RFC 0010 host-parallelism admission register.
#[must_use]
pub fn canonical_host_parallelism_admissions() -> Vec<HostParallelismAdmission> {
    vec![
        HostParallelismAdmission::new(
            HOST_WORKER_POOL,
            HostParallelismClass::CommitPinnedToVirtualTime,
            "each node ceiling and completion-order key are fixed before worker dispatch",
            ["gate:perf-bench", "gate:adversarial-determinism"],
        ),
        HostParallelismAdmission::new(
            FINGERPRINT_DIGEST_OFFLOAD,
            HostParallelismClass::OutsideObservableBoundary,
            "workers digest an immutable sample captured at the exact icount coordinate",
            ["gate:single-vm-fingerprint", "gate:perf-bench"],
        ),
        HostParallelismAdmission::new(
            DEVICE_WORK_OVERLAP,
            HostParallelismClass::CommitPinnedToVirtualTime,
            "device completion icount is fixed before host work is dispatched",
            ["gate:e2e-determinism", "gate:perf-bench"],
        ),
        HostParallelismAdmission::new(
            TRANSLATION_PREFETCH,
            HostParallelismClass::OutsideObservableBoundary,
            "prefetched translation may be consumed only after fingerprint-neutrality proof",
            ["gate:single-vm-fingerprint", "gate:perf-bench"],
        ),
        HostParallelismAdmission::new(
            SEGMENT_PARALLEL_REPLAY,
            HostParallelismClass::OutsideObservableBoundary,
            "checkpoint-bounded segment results are joined in canonical coordinate order",
            ["gate:replay-oracle", "gate:divergence-bisect"],
        ),
    ]
}

/// Validates that every admitted mechanism has one class argument and proving gate.
///
/// # Errors
///
/// Returns [`PerfBenchError`] for a missing required mechanism, a duplicate or
/// empty identifier, an empty class argument, or a record with no unique,
/// canonical proving gate.
pub fn validate_host_parallelism_admissions(
    admissions: &[HostParallelismAdmission],
) -> Result<(), PerfBenchError> {
    let mut seen = BTreeSet::new();
    for admission in admissions {
        let mut proving_gates = BTreeSet::new();
        if admission.mechanism.is_empty()
            || !seen.insert(admission.mechanism.clone())
            || admission.argument.trim().is_empty()
            || admission.proving_gates.is_empty()
            || admission.proving_gates.iter().any(|gate| {
                !PROVING_GATES.contains(&gate.as_str()) || !proving_gates.insert(gate.as_str())
            })
        {
            return Err(PerfBenchError::InvalidHostParallelismAdmission {
                mechanism: admission.mechanism.clone(),
            });
        }
    }
    for required in REQUIRED_MECHANISMS {
        if !seen.contains(required) {
            return Err(PerfBenchError::MissingHostParallelismAdmission {
                mechanism: String::from(required),
            });
        }
    }
    Ok(())
}
