//! Public data types for the single-VM fingerprint gate.

use thiserror::Error;

use super::compare::SingleVmFingerprintMismatch;

/// The byte length of canonical execution-fingerprint digests.
pub const SINGLE_VM_FINGERPRINT_DIGEST_BYTES: usize = 32;

/// The deterministic reason a single-VM fingerprint sample exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintTrigger {
    /// The sample was taken at the fixed periodic aggregate-icount cadence.
    Periodic,
    /// The sample was taken at a deterministic host-visible event boundary.
    Event(SingleVmFingerprintEventBoundary),
}

/// A deterministic event boundary that may force a fingerprint sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintEventBoundary {
    /// A scheduler horizon advanced.
    HorizonAdvance,
    /// An icount-stamped frame became visible.
    FrameDelivery,
    /// A scheduled fault activation became visible.
    FaultActivation,
}

/// Deterministic host-condition labels applied around both gate runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmHostProfile {
    name: String,
    stressors: Vec<String>,
}

impl SingleVmHostProfile {
    /// Builds a deterministic host profile.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError::InvalidHostProfile`] when the
    /// profile name is empty, a stressor label is empty, or the same stressor is
    /// named more than once.
    pub fn new(
        name: impl Into<String>,
        stressors: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let name = name.into();
        if name.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidHostProfile {
                reason: "host profile name must be non-empty",
            });
        }

        let mut stressors = stressors.into_iter().map(Into::into).collect::<Vec<_>>();
        stressors.sort();
        for (index, stressor) in stressors.iter().enumerate() {
            if stressor.is_empty() {
                return Err(SingleVmFingerprintGateError::InvalidHostProfile {
                    reason: "host profile stressor labels must be non-empty",
                });
            }
            if index > 0 && stressors[index - 1] == *stressor {
                return Err(SingleVmFingerprintGateError::InvalidHostProfile {
                    reason: "host profile stressor labels must be unique",
                });
            }
        }

        Ok(Self { name, stressors })
    }

    /// Builds the conservative deterministic host-condition profile for Phase 1.
    #[must_use]
    pub fn phase1_adversarial() -> Self {
        Self {
            name: "phase1-single-vm-host-adversarial".to_owned(),
            stressors: vec![
                "host-scheduler-yield-points".to_owned(),
                "poll-order-rotation".to_owned(),
                "stdio-drain-order-variation".to_owned(),
            ],
        }
    }

    /// Returns the stable profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the sorted deterministic host-stressor labels.
    #[must_use]
    pub fn stressors(&self) -> &[String] {
        &self.stressors
    }
}

/// A fixed single-VM scenario for `gate:single-vm-fingerprint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintScenario {
    pub(super) id: String,
    pub(super) fingerprint_definition_digest: Vec<u8>,
    pub(super) run_horizon_icount: u64,
    host_profile: SingleVmHostProfile,
}

impl SingleVmFingerprintScenario {
    /// Builds a fixed single-VM fingerprint-gate scenario.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the scenario id is empty,
    /// the run horizon is zero, or the fingerprint-definition digest is not the
    /// canonical digest width.
    pub fn new(
        id: impl Into<String>,
        fingerprint_definition_digest: impl Into<Vec<u8>>,
        run_horizon_icount: u64,
        host_profile: SingleVmHostProfile,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "scenario id must be non-empty",
            });
        }
        if run_horizon_icount == 0 {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "run horizon icount must be non-zero",
            });
        }
        let fingerprint_definition_digest = fingerprint_definition_digest.into();
        validate_digest_len(
            "fingerprint_definition_digest",
            &fingerprint_definition_digest,
        )?;

        Ok(Self {
            id,
            fingerprint_definition_digest,
            run_horizon_icount,
            host_profile,
        })
    }

    /// Returns the content-addressed scenario id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the content-addressed fingerprint definition digest.
    #[must_use]
    pub fn fingerprint_definition_digest(&self) -> &[u8] {
        &self.fingerprint_definition_digest
    }

    /// Returns the aggregate icount each run must reach.
    #[must_use]
    pub fn run_horizon_icount(&self) -> u64 {
        self.run_horizon_icount
    }

    /// Returns the deterministic host-condition profile for both runs.
    #[must_use]
    pub fn host_profile(&self) -> &SingleVmHostProfile {
        &self.host_profile
    }
}

/// Which of the two required gate runs a backend should execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintRunOrdinal {
    /// The first run of the fixed scenario.
    First,
    /// The second run of the fixed scenario.
    Second,
}

/// A request sent from the gate driver to a backend runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintRunRequest {
    scenario: SingleVmFingerprintScenario,
    ordinal: SingleVmFingerprintRunOrdinal,
}

impl SingleVmFingerprintRunRequest {
    /// Builds a single run request for a fixed scenario.
    #[must_use]
    pub fn new(
        scenario: SingleVmFingerprintScenario,
        ordinal: SingleVmFingerprintRunOrdinal,
    ) -> Self {
        Self { scenario, ordinal }
    }

    /// Returns the fixed scenario to execute.
    #[must_use]
    pub fn scenario(&self) -> &SingleVmFingerprintScenario {
        &self.scenario
    }

    /// Returns whether this is the first or second run.
    #[must_use]
    pub fn ordinal(&self) -> SingleVmFingerprintRunOrdinal {
        self.ordinal
    }
}

/// One canonical fingerprint sample from a single-VM run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintSample {
    /// Monotonic sample number within the stream.
    pub seq: u64,
    /// Stable node identifier associated with the sampled VM.
    pub node: String,
    /// Aggregate node icount at the sample point.
    pub icount: u64,
    /// The deterministic reason the sample was taken.
    pub trigger: SingleVmFingerprintTrigger,
    /// Rolling fingerprint bytes after incorporating this sample.
    pub rolling_fingerprint: Vec<u8>,
}

/// The ordered fingerprint stream for one single-VM run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintStream {
    /// The fixed content-addressed fingerprint definition digest.
    pub definition_digest: Vec<u8>,
    /// Samples in canonical comparison order.
    pub samples: Vec<SingleVmFingerprintSample>,
    /// Aggregate node icount associated with the final fingerprint.
    pub final_icount: u64,
    /// Final run fingerprint bytes.
    pub final_fingerprint: Vec<u8>,
}

impl SingleVmFingerprintStream {
    /// Builds a validated single-VM fingerprint stream.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when a digest has the wrong
    /// length, the stream is empty, samples are not canonical, or a sample
    /// appears beyond the scenario horizon.
    pub fn new(
        definition_digest: impl Into<Vec<u8>>,
        samples: Vec<SingleVmFingerprintSample>,
        final_icount: u64,
        final_fingerprint: impl Into<Vec<u8>>,
        run_horizon_icount: u64,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let definition_digest = definition_digest.into();
        validate_digest_len("definition_digest", &definition_digest)?;
        validate_samples(&samples, run_horizon_icount)?;
        validate_final_icount(final_icount, run_horizon_icount)?;
        let final_fingerprint = final_fingerprint.into();
        validate_digest_len("final_fingerprint", &final_fingerprint)?;

        Ok(Self {
            definition_digest,
            samples,
            final_icount,
            final_fingerprint,
        })
    }
}

/// A backend capable of executing one fixed single-VM fingerprint run.
pub trait SingleVmFingerprintRunner {
    /// Runs the requested VM and returns its canonical fingerprint stream.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintRunError`] when the backend cannot complete
    /// the requested run or cannot obtain a canonical fingerprint stream.
    fn run_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>;
}

/// A backend execution failure before stream comparison.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("single-VM fingerprint backend failed: {message}")]
pub struct SingleVmFingerprintRunError {
    message: String,
}

impl SingleVmFingerprintRunError {
    /// Builds a backend execution failure.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend-provided message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The successful result of `gate:single-vm-fingerprint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintGateReport {
    /// The content-addressed scenario id that was executed twice.
    pub scenario_id: String,
    /// The first run stream.
    pub first_stream: SingleVmFingerprintStream,
    /// The second run stream.
    pub second_stream: SingleVmFingerprintStream,
    /// The shared final fingerprint proven equal by the gate.
    pub matching_final_fingerprint: Vec<u8>,
    /// Number of compared samples.
    pub sample_count: usize,
}

/// A validation, execution, or comparison failure from the single-VM gate.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SingleVmFingerprintGateError {
    /// The requested scenario is not fixed enough to compare.
    #[error("invalid single-VM fingerprint scenario: {reason}")]
    InvalidScenario {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// The host-condition profile is ambiguous.
    #[error("invalid single-VM fingerprint host profile: {reason}")]
    InvalidHostProfile {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// A digest does not use the canonical fixed length.
    #[error("{field} digest length {len} is not {SINGLE_VM_FINGERPRINT_DIGEST_BYTES} bytes")]
    InvalidDigestLength {
        /// Digest field with the wrong length.
        field: &'static str,
        /// Provided byte length.
        len: usize,
    },
    /// A backend failed one of the two required runs.
    #[error("{ordinal:?} single-VM fingerprint run failed: {source}")]
    RunFailed {
        /// Which of the two runs failed.
        ordinal: SingleVmFingerprintRunOrdinal,
        /// Backend failure.
        source: SingleVmFingerprintRunError,
    },
    /// A backend returned a non-canonical stream.
    #[error("invalid {ordinal:?} single-VM fingerprint stream: {reason}")]
    InvalidStreamForRun {
        /// Which run returned the invalid stream.
        ordinal: SingleVmFingerprintRunOrdinal,
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// A stream is not internally canonical.
    #[error("invalid single-VM fingerprint stream: {reason}")]
    InvalidStream {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// The two canonical streams differed.
    #[error("single-VM fingerprint streams differ: {mismatch}")]
    Mismatch {
        /// The first deterministic mismatch.
        mismatch: SingleVmFingerprintMismatch,
        /// First run stream to include in diagnostics.
        first_stream: Box<SingleVmFingerprintStream>,
        /// Second run stream to include in diagnostics.
        second_stream: Box<SingleVmFingerprintStream>,
    },
}

pub(super) fn validate_samples(
    samples: &[SingleVmFingerprintSample],
    run_horizon_icount: u64,
) -> Result<(), SingleVmFingerprintGateError> {
    if samples.is_empty() {
        return Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include at least one sample",
        });
    }
    let mut previous_icount = None;
    for (index, sample) in samples.iter().enumerate() {
        if sample.seq != index as u64 {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample sequence numbers must match canonical stream order",
            });
        }
        if sample.node.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample node id must be non-empty",
            });
        }
        if sample.icount == 0 || sample.icount > run_horizon_icount {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample icount must be within the scenario horizon",
            });
        }
        if previous_icount.is_some_and(|previous| previous > sample.icount) {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample icounts must be monotonically ordered",
            });
        }
        validate_digest_len("rolling_fingerprint", &sample.rolling_fingerprint)?;
        previous_icount = Some(sample.icount);
    }
    if previous_icount != Some(run_horizon_icount) {
        return Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include a sample at the scenario horizon",
        });
    }
    Ok(())
}

pub(super) fn validate_final_icount(
    final_icount: u64,
    run_horizon_icount: u64,
) -> Result<(), SingleVmFingerprintGateError> {
    if final_icount < run_horizon_icount {
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "final fingerprint icount must be at or beyond the scenario horizon",
        })
    } else {
        Ok(())
    }
}

pub(super) fn validate_digest_len(
    field: &'static str,
    digest: &[u8],
) -> Result<(), SingleVmFingerprintGateError> {
    if digest.len() == SINGLE_VM_FINGERPRINT_DIGEST_BYTES {
        Ok(())
    } else {
        Err(SingleVmFingerprintGateError::InvalidDigestLength {
            field,
            len: digest.len(),
        })
    }
}
