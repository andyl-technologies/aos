//! Public lifecycle, limits, results, and execution-policy types.

use std::time::Duration;

use dispatch_model::{Assignment, Evaluation};
use serde::{Deserialize, Serialize};

use crate::providers::ResourceGrant;

pub(crate) mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let quantity = dispatch_model::Quantity::deserialize(deserializer)?;
        Ok(quantity.get())
    }
}

pub(crate) mod optional_decimal_u64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(|value| value.to_string()).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        let quantity = Option::<dispatch_model::Quantity>::deserialize(deserializer)?;
        Ok(quantity.map(|quantity| quantity.get()))
    }
}

mod decimal_u32 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u32, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
        use serde::de::Error;
        let value = super::decimal_u64::deserialize(deserializer)?;
        u32::try_from(value).map_err(D::Error::custom)
    }
}

mod optional_digest {
    use serde::{Deserialize, Deserializer, Serializer, ser::Error};

    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let Some(bytes) = value else {
            return serializer.serialize_none();
        };
        if bytes.len() != 32 {
            return Err(S::Error::custom("commitment must contain 32 bytes"));
        }
        let mut text = String::with_capacity(64);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut text, "{byte:02x}").map_err(S::Error::custom)?;
        }
        serializer.serialize_some(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        use serde::de::Error;
        let Some(text) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        if text.len() != 64
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "commitment must be 64 lowercase hexadecimal digits",
            ));
        }
        let mut bytes = Vec::with_capacity(32);
        for pair in text.as_bytes().as_chunks::<2>().0 {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| D::Error::custom("invalid hexadecimal commitment"))?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| D::Error::custom("invalid hexadecimal commitment"))?;
            bytes.push((high * 16 + low) as u8);
        }
        Ok(Some(bytes))
    }
}

/// Chooses whether a worker can be reused after a completed solve.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExecutionProfile {
    /// Reuses bounded workers within one stable session grant.
    #[default]
    Warm,
    /// Retires the worker after every solve.
    Fresh,
}

/// Defines session-local accounting limits, independent of modeled resources.
#[derive(Clone, Debug)]
pub struct SessionLimits {
    /// Maximum simultaneous execution slots.
    pub max_workers: usize,
    /// Maximum queued requests, excluding dispatched work.
    pub max_pending: usize,
    /// Maximum retained request and prepared-input bytes.
    pub max_input_bytes: usize,
    /// Maximum accepted jobs whose terminal records have not expired.
    pub max_retained_results: usize,
    /// Maximum number of retained prepared inputs.
    pub max_prepared: usize,
    /// Maximum worker frame payload, including candidates and evaluations.
    pub max_frame_bytes: u32,
    /// Time a terminal result remains queryable after completion.
    pub result_retention: Duration,
    /// Maximum wait for confirmed worker termination.
    pub cleanup_timeout: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_workers: 1,
            max_pending: 32,
            max_input_bytes: 64 * 1024 * 1024,
            max_retained_results: 64,
            max_prepared: 16,
            max_frame_bytes: 16 * 1024 * 1024,
            result_retention: Duration::from_secs(60),
            cleanup_timeout: Duration::from_secs(5),
        }
    }
}

/// States execution guarantees a caller refuses to downgrade.
#[derive(Clone, Debug, Default)]
pub struct RequiredGuarantees {
    /// Requires native termination independent of solver cooperation.
    pub hard_cancellation: bool,
    /// Requires a worker-specific memory/OOM boundary.
    pub independent_memory: bool,
    /// Requires application-wide accounting across sessions.
    pub aggregate_accounting: bool,
    /// Requires owner-loss cleanup independent of normal destruction.
    pub owner_cleanup: bool,
}

/// Selects a native search algorithm explicitly.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    /// Selects Rebalancer's assignment local search.
    #[default]
    LocalSearch,
    /// Requests a separately advertised mixed-integer search mode.
    Mip,
}

/// Configures a solve without modifying its immutable allocation semantics.
#[derive(Clone, Debug)]
pub struct SolveOptions {
    /// Submission-to-terminal wall budget, including queue and verification.
    pub deadline: Duration,
    /// Explicit native thread count; this is not a physical CPU entitlement.
    pub threads: u32,
    /// Explicit search seed, when supported by the backend.
    pub seed: Option<u64>,
    /// The selected algorithm.
    pub mode: SearchMode,
    /// Optional candidate hint, independent of the observed baseline.
    pub hint: Option<Assignment>,
}

impl Default for SolveOptions {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(30),
            threads: 1,
            seed: None,
            mode: SearchMode::LocalSearch,
            hint: None,
        }
    }
}

/// Classifies why computation stopped, independently of candidate feasibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    /// Search completed normally.
    Completed,
    /// A submission deadline or native search limit was reached.
    LimitReached,
    /// Cancellation won the terminal race.
    Cancelled,
    /// Input or requested semantics were rejected.
    Rejected,
    /// An execution stage failed.
    ExecutionFailed,
}

/// Classifies a candidate independently of computation termination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateClass {
    /// No candidate was available.
    Absent,
    /// Independent verification rejected the proposed candidate.
    Rejected,
    /// The candidate satisfied every hard requirement without repair debt.
    FullyFeasible,
    /// The candidate satisfied hard requirements and authorized repair envelopes.
    RepairProposal,
}

/// Distinguishes rejection categories without interpreting diagnostic prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Input violates the portable model or interchange schema.
    InvalidInput,
    /// The selected backend cannot preserve the requested semantics.
    UnsupportedModel,
    /// Requested execution authority was not granted.
    Unauthorized,
}

/// Classifies search evidence as a backend claim rather than a verified proof.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// No search evidence is available.
    #[default]
    None,
    /// The local search exhausted its configured neighborhood.
    LocalSearchExhausted,
    /// The backend reported a numerical bound.
    BackendReportedBound,
    /// The backend reported infeasibility over its candidate domain.
    BackendReportedInfeasible,
    /// The backend reported optimality under its numerical assumptions.
    BackendReportedOptimal,
}

/// Preserves the scope and assumptions of native search evidence.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchEvidence {
    /// The independently labeled evidence category.
    pub kind: EvidenceKind,
    /// The objective tier to which any claimed bound applies.
    #[serde(with = "decimal_u32")]
    pub objective_tier: u32,
    /// Exact typed JSON supplied for a claimed bound, never verification authority.
    pub bound: Option<dispatch_protocol::reports::BoundReport>,
    /// Candidate-domain or formulation restrictions attached to the claim.
    pub restriction: String,
    /// Native tolerance assumptions attached to the claim.
    pub tolerance: String,
}

/// Records requested or effective native options independently of commitments.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveOptions {
    /// The selected search algorithm.
    pub mode: SearchMode,
    /// The original or remaining wall-clock budget in milliseconds.
    #[serde(with = "decimal_u64")]
    pub wall_time_millis: u64,
    /// The configured native thread count, not a CPU quota.
    #[serde(with = "decimal_u32")]
    pub threads: u32,
    /// The explicit native seed, absent when not supplied.
    #[serde(with = "optional_decimal_u64")]
    pub seed: Option<u64>,
    /// Any cooperative native memory setting, not an enforced memory ceiling.
    #[serde(with = "decimal_u64")]
    pub memory_bytes: u64,
    /// Any cooperative native CPU-time setting.
    #[serde(with = "decimal_u64")]
    pub cpu_time_millis: u64,
    /// Any explicit native search iteration limit.
    #[serde(with = "decimal_u64")]
    pub maximum_iterations: u64,
}

/// Reports a measured execution stage without substituting zero for absence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageTiming {
    /// The stage name: materializing, searching, or verifying.
    pub stage: String,
    /// The measured stage wall duration when available.
    #[serde(with = "optional_decimal_u64")]
    pub wall_time_micros: Option<u64>,
    /// The measured CPU duration when available.
    #[serde(with = "optional_decimal_u64")]
    pub cpu_time_micros: Option<u64>,
}

/// Explains why a provenance field or measurement is absent.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailabilityReason {
    /// The execution stage establishing this field never began.
    NotStarted,
    /// Portable input validation did not establish this fact.
    NotValidated,
    /// Backend capability negotiation did not establish this identity.
    NotNegotiated,
    /// The backend did not report the field.
    NotReported,
    /// The provider or backend did not measure the quantity.
    NotMeasured,
}

/// Attributes an execution failure when a provider has trustworthy evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkerFailureCause {
    /// The worker's own enforced memory boundary killed execution.
    WorkerMemoryLimit,
    /// An enclosing application or solver boundary killed execution.
    AncestorMemoryLimit {
        /// The enclosing unit identified by the provider.
        unit: String,
    },
    /// The provider cannot establish a specific resource failure.
    Unknown,
}

/// Retains provider evidence separately from allocation infeasibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerFailureReport {
    /// The resource attribution established by the provider.
    pub cause: WorkerFailureCause,
    /// Bounded provider diagnostics and their limitations.
    pub detail: String,
}

/// Identifies how a backend handled random seed selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedPolicy {
    /// An explicitly requested seed was supported by the negotiated backend.
    Explicit,
    /// The backend selected a seed without reporting its value.
    BackendSelectedUnreported,
    /// The negotiated backend does not support seed selection.
    Unsupported,
}

/// Returns a snapshot-bound result from the trusted execution runner.
///
/// Serialization does not preserve local verification authority. Imported
/// assignments must be independently checked before application.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SolveResult {
    /// The session-local job identity.
    #[serde(with = "decimal_u64")]
    pub job_id: u64,
    /// The owning session generation.
    #[serde(with = "decimal_u64")]
    pub session_generation: u64,
    /// The selected worker generation, absent before worker startup.
    #[serde(with = "optional_decimal_u64")]
    pub worker_generation: Option<u64>,
    /// The final computation outcome.
    pub termination: Termination,
    /// A typed rejection reason when the computation was rejected.
    pub rejection: Option<RejectionReason>,
    /// The independent candidate classification.
    pub candidate: CandidateClass,
    /// The returned candidate, if any.
    pub assignment: Option<Assignment>,
    /// Exact evaluator output from the trusted runner.
    pub evaluation: Option<Evaluation>,
    /// The exact evaluator implementation and model semantic version.
    pub evaluator_version: Option<String>,
    /// The validated model commitment, if established.
    #[serde(with = "optional_digest")]
    pub model_digest: Option<Vec<u8>>,
    /// The request commitment, if established.
    #[serde(with = "optional_digest")]
    pub request_digest: Option<Vec<u8>>,
    /// The selected native backend build, if negotiation completed.
    pub backend_build_id: Option<String>,
    /// Opaque consumer revisions copied from the validated immutable model.
    pub observation_basis: Option<std::collections::BTreeMap<String, String>>,
    /// Options requested at submission, independent of remaining execution time.
    pub requested_options: Option<EffectiveOptions>,
    /// The negotiated seed-selection policy, absent before negotiation.
    pub seed_policy: Option<SeedPolicy>,
    /// Native options reported after execution, absent when not established.
    pub effective_options: Option<EffectiveOptions>,
    /// Search evidence and its restrictions, never an independent proof.
    pub search_evidence: SearchEvidence,
    /// Stage measurements with explicit presence for available values.
    pub timings: Vec<StageTiming>,
    /// Whether any bounded diagnostics were omitted.
    pub diagnostics_truncated: bool,
    /// Typed absence reasons; null metadata does not imply zero or a default.
    pub provenance_unavailable: std::collections::BTreeMap<String, UnavailabilityReason>,
    /// Provider-established resource failure evidence, when available.
    pub failure_report: Option<WorkerFailureReport>,
    /// Bounded descriptive diagnostics; these are not feasibility proofs.
    pub detail: String,
    /// The authorized execution policy.
    pub grant: ResourceGrant,
}

/// Describes a job's currently observable lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobStatus {
    /// The job is waiting for an execution slot.
    Queued,
    /// Startup, materialization, or native computation is active.
    Running,
    /// A terminal record is retained.
    Terminal,
    /// The terminal retention interval ended.
    Expired,
}

/// Chooses how accepted work is treated during session close.
#[derive(Clone, Copy, Debug)]
pub enum CloseMode {
    /// Allows accepted work to finish until the close deadline.
    Drain,
    /// Requests cancellation immediately.
    Cancel,
}

/// Reports explicit session-close progress without implying cleanup success.
#[derive(Clone, Debug, Default)]
pub struct CleanupReport {
    /// Number of jobs with committed terminal records.
    pub completed: usize,
    /// Number of accepted jobs not confirmed terminal by the close deadline.
    pub unconfirmed: usize,
    /// Number of idle workers whose termination could not be confirmed.
    pub workers_unconfirmed: usize,
}
