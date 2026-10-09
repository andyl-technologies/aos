//! Typed Protobuf messages for isolated allocation workers.
//!
//! These checked-in derives mirror `protocol/dispatch/worker.proto`. Keeping
//! bindings in source lets Cargo consumers build without a native schema compiler.
//! Workers carry portable JSON models inside typed, versioned envelopes.

/// Carries the worker envelope protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct WorkerEnvelope {
    /// Encodes protocol version according to the published schema.
    #[prost(message, optional, tag = "1")]
    pub protocol_version: Option<Version>,
    /// Encodes session generation according to the published schema.
    #[prost(uint64, tag = "2")]
    pub session_generation: u64,
    /// Encodes worker generation according to the published schema.
    #[prost(uint64, tag = "3")]
    pub worker_generation: u64,
    /// Encodes request id according to the published schema.
    #[prost(uint64, tag = "4")]
    pub request_id: u64,
    /// Selects exactly one envelope operation.
    #[prost(
        oneof = "worker_envelope::Body",
        tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21"
    )]
    pub body: Option<worker_envelope::Body>,
}

/// Carries the version protocol message.
#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct Version {
    /// Encodes major according to the published schema.
    #[prost(uint32, tag = "1")]
    pub major: u32,
    /// Encodes minor according to the published schema.
    #[prost(uint32, tag = "2")]
    pub minor: u32,
}

/// Carries the hello protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Hello {
    /// Encodes protocol versions according to the published schema.
    #[prost(message, repeated, tag = "1")]
    pub protocol_versions: Vec<Version>,
    /// Encodes model versions according to the published schema.
    #[prost(message, repeated, tag = "2")]
    pub model_versions: Vec<Version>,
    /// Encodes limits according to the published schema.
    #[prost(message, optional, tag = "3")]
    pub limits: Option<WireLimits>,
    /// Encodes required capabilities according to the published schema.
    #[prost(string, repeated, tag = "4")]
    pub required_capabilities: Vec<String>,
}

/// Carries the wire limits protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct WireLimits {
    /// Encodes max frame bytes according to the published schema.
    #[prost(uint32, tag = "1")]
    pub max_frame_bytes: u32,
    /// Encodes max problem bytes according to the published schema.
    #[prost(uint64, tag = "2")]
    pub max_problem_bytes: u64,
    /// Encodes max decoded bytes according to the published schema.
    #[prost(uint64, tag = "3")]
    pub max_decoded_bytes: u64,
    /// Encodes max items according to the published schema.
    #[prost(uint64, tag = "4")]
    pub max_items: u64,
    /// Encodes max targets according to the published schema.
    #[prost(uint64, tag = "5")]
    pub max_targets: u64,
    /// Encodes max dimensions according to the published schema.
    #[prost(uint64, tag = "6")]
    pub max_dimensions: u64,
    /// Encodes max memberships according to the published schema.
    #[prost(uint64, tag = "7")]
    pub max_memberships: u64,
    /// Encodes max domain entries according to the published schema.
    #[prost(uint64, tag = "8")]
    pub max_domain_entries: u64,
    /// Encodes max overrides according to the published schema.
    #[prost(uint64, tag = "9")]
    pub max_overrides: u64,
    /// Encodes max constraints according to the published schema.
    #[prost(uint64, tag = "10")]
    pub max_constraints: u64,
    /// Encodes max objectives according to the published schema.
    #[prost(uint64, tag = "11")]
    pub max_objectives: u64,
    /// Encodes max nesting according to the published schema.
    #[prost(uint32, tag = "12")]
    pub max_nesting: u32,
    /// Encodes max string bytes according to the published schema.
    #[prost(uint32, tag = "13")]
    pub max_string_bytes: u32,
    /// Encodes max prepared according to the published schema.
    #[prost(uint32, tag = "14")]
    pub max_prepared: u32,
    /// Encodes max prepared bytes according to the published schema.
    #[prost(uint64, tag = "15")]
    pub max_prepared_bytes: u64,
    /// Encodes max diagnostic bytes according to the published schema.
    #[prost(uint32, tag = "16")]
    pub max_diagnostic_bytes: u32,
}

/// Carries the capabilities protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Capabilities {
    /// Encodes protocol version according to the published schema.
    #[prost(message, optional, tag = "1")]
    pub protocol_version: Option<Version>,
    /// Encodes model versions according to the published schema.
    #[prost(message, repeated, tag = "2")]
    pub model_versions: Vec<Version>,
    /// Encodes limits according to the published schema.
    #[prost(message, optional, tag = "3")]
    pub limits: Option<WireLimits>,
    /// Encodes backend name according to the published schema.
    #[prost(string, tag = "4")]
    pub backend_name: String,
    /// Encodes backend build id according to the published schema.
    #[prost(string, tag = "5")]
    pub backend_build_id: String,
    /// Encodes capabilities according to the published schema.
    #[prost(string, repeated, tag = "6")]
    pub capabilities: Vec<String>,
    /// Encodes constraint kinds according to the published schema.
    #[prost(string, repeated, tag = "7")]
    pub constraint_kinds: Vec<String>,
    /// Encodes objective kinds according to the published schema.
    #[prost(string, repeated, tag = "8")]
    pub objective_kinds: Vec<String>,
    /// Encodes maximum exact integer according to the published schema.
    #[prost(uint64, tag = "9")]
    pub maximum_exact_integer: u64,
    /// Encodes graceful cancel according to the published schema.
    #[prost(bool, tag = "10")]
    pub graceful_cancel: bool,
    /// Encodes candidate stream according to the published schema.
    #[prost(bool, tag = "11")]
    pub candidate_stream: bool,
    /// Encodes incremental updates according to the published schema.
    #[prost(bool, tag = "12")]
    pub incremental_updates: bool,
    /// Encodes prepared native state according to the published schema.
    #[prost(bool, tag = "13")]
    pub prepared_native_state: bool,
    /// Encodes search modes according to the published schema.
    #[prost(enumeration = "SearchMode", repeated, tag = "14")]
    pub search_modes: Vec<i32>,
    /// Encodes seed supported according to the published schema.
    #[prost(bool, tag = "15")]
    pub seed_supported: bool,
    /// Encodes stage timings according to the published schema.
    #[prost(bool, tag = "16")]
    pub stage_timings: bool,
}

/// Carries the prepare protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Prepare {
    /// Encodes problem json according to the published schema.
    #[prost(bytes = "vec", tag = "1")]
    pub problem_json: Vec<u8>,
    /// Encodes model digest according to the published schema.
    #[prost(bytes = "vec", tag = "2")]
    pub model_digest: Vec<u8>,
}

/// Carries the prepared protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Prepared {
    /// Encodes handle according to the published schema.
    #[prost(string, tag = "1")]
    pub handle: String,
    /// Encodes model digest according to the published schema.
    #[prost(bytes = "vec", tag = "2")]
    pub model_digest: Vec<u8>,
}

/// Carries the solve protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Solve {
    /// Encodes problem json according to the published schema.
    #[prost(bytes = "vec", tag = "1")]
    pub problem_json: Vec<u8>,
    /// Encodes prepared handle according to the published schema.
    #[prost(string, tag = "2")]
    pub prepared_handle: String,
    /// Encodes model digest according to the published schema.
    #[prost(bytes = "vec", tag = "3")]
    pub model_digest: Vec<u8>,
    /// Encodes request digest according to the published schema.
    #[prost(bytes = "vec", tag = "4")]
    pub request_digest: Vec<u8>,
    /// Encodes hint json according to the published schema.
    #[prost(bytes = "vec", tag = "5")]
    pub hint_json: Vec<u8>,
    /// Encodes options according to the published schema.
    #[prost(message, optional, tag = "6")]
    pub options: Option<SolveOptions>,
    /// Propagates the submission budget without changing request identity.
    #[prost(uint64, optional, tag = "7")]
    pub remaining_wall_time_millis: Option<u64>,
}

/// Carries the solve options protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct SolveOptions {
    /// Encodes mode according to the published schema.
    #[prost(enumeration = "SearchMode", tag = "1")]
    pub mode: i32,
    /// Encodes wall time millis according to the published schema.
    #[prost(uint64, tag = "2")]
    pub wall_time_millis: u64,
    /// Encodes threads according to the published schema.
    #[prost(uint32, tag = "3")]
    pub threads: u32,
    /// Encodes seed according to the published schema.
    #[prost(uint64, optional, tag = "4")]
    pub seed: Option<u64>,
    /// Encodes memory bytes according to the published schema.
    #[prost(uint64, tag = "5")]
    pub memory_bytes: u64,
    /// Encodes cpu time millis according to the published schema.
    #[prost(uint64, tag = "6")]
    pub cpu_time_millis: u64,
    /// Encodes maximum iterations according to the published schema.
    #[prost(uint64, tag = "7")]
    pub maximum_iterations: u64,
}

/// Carries the progress protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Progress {
    /// Encodes stage according to the published schema.
    #[prost(enumeration = "ExecutionStage", tag = "1")]
    pub stage: i32,
    /// Encodes completed iterations according to the published schema.
    #[prost(uint64, tag = "2")]
    pub completed_iterations: u64,
    /// Encodes detail according to the published schema.
    #[prost(string, tag = "3")]
    pub detail: String,
}

/// Carries the candidate protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Candidate {
    /// Encodes assignment json according to the published schema.
    #[prost(bytes = "vec", tag = "1")]
    pub assignment_json: Vec<u8>,
    /// Encodes model digest according to the published schema.
    #[prost(bytes = "vec", tag = "2")]
    pub model_digest: Vec<u8>,
}

/// Carries the finished protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Finished {
    /// Encodes termination according to the published schema.
    #[prost(enumeration = "Termination", tag = "1")]
    pub termination: i32,
    /// Encodes assignment json according to the published schema.
    #[prost(bytes = "vec", tag = "2")]
    pub assignment_json: Vec<u8>,
    /// Encodes evidence according to the published schema.
    #[prost(message, optional, tag = "3")]
    pub evidence: Option<SearchEvidence>,
    /// Encodes detail according to the published schema.
    #[prost(string, tag = "4")]
    pub detail: String,
    /// Encodes model digest according to the published schema.
    #[prost(bytes = "vec", tag = "5")]
    pub model_digest: Vec<u8>,
    /// Encodes request digest according to the published schema.
    #[prost(bytes = "vec", tag = "6")]
    pub request_digest: Vec<u8>,
    /// Encodes backend build id according to the published schema.
    #[prost(string, tag = "7")]
    pub backend_build_id: String,
    /// Encodes effective options according to the published schema.
    #[prost(message, optional, tag = "8")]
    pub effective_options: Option<SolveOptions>,
    /// Encodes evaluation json according to the published schema.
    #[prost(bytes = "vec", tag = "9")]
    pub evaluation_json: Vec<u8>,
    /// Encodes verification class according to the published schema.
    #[prost(enumeration = "VerificationClass", tag = "10")]
    pub verification_class: i32,
    /// Encodes timings according to the published schema.
    #[prost(message, repeated, tag = "11")]
    pub timings: Vec<StageTiming>,
    /// Encodes diagnostics truncated according to the published schema.
    #[prost(bool, tag = "12")]
    pub diagnostics_truncated: bool,
    /// Identifies a known rejection or execution-failure category.
    #[prost(enumeration = "ErrorCode", optional, tag = "13")]
    pub error_code: Option<i32>,
    /// Carries the exact observation references bound by the trusted runner.
    #[prost(bytes = "vec", tag = "14")]
    pub observation_basis_json: Vec<u8>,
    /// Identifies the independent evaluator when verification was established.
    #[prost(string, tag = "15")]
    pub evaluator_version: String,
}

/// Carries the search evidence protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct SearchEvidence {
    /// Encodes kind according to the published schema.
    #[prost(enumeration = "EvidenceKind", tag = "1")]
    pub kind: i32,
    /// Encodes bound json according to the published schema.
    #[prost(bytes = "vec", tag = "2")]
    pub bound_json: Vec<u8>,
    /// Encodes objective tier according to the published schema.
    #[prost(uint32, tag = "3")]
    pub objective_tier: u32,
    /// Encodes restriction according to the published schema.
    #[prost(string, tag = "4")]
    pub restriction: String,
    /// Encodes tolerance according to the published schema.
    #[prost(string, tag = "5")]
    pub tolerance: String,
}

/// Carries the stage timing protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct StageTiming {
    /// Encodes stage according to the published schema.
    #[prost(enumeration = "ExecutionStage", tag = "1")]
    pub stage: i32,
    /// Encodes wall time micros according to the published schema.
    #[prost(uint64, optional, tag = "2")]
    pub wall_time_micros: Option<u64>,
    /// Encodes cpu time micros according to the published schema.
    #[prost(uint64, optional, tag = "3")]
    pub cpu_time_micros: Option<u64>,
}

/// Carries the release protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Release {
    /// Encodes handle according to the published schema.
    #[prost(string, tag = "1")]
    pub handle: String,
}

/// Carries the released protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Released {
    /// Encodes handle according to the published schema.
    #[prost(string, tag = "1")]
    pub handle: String,
}

/// Carries the cancel protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct Cancel {
    /// Encodes solve request id according to the published schema.
    #[prost(uint64, tag = "1")]
    pub solve_request_id: u64,
}

/// Carries the protocol error protocol message.
#[derive(Clone, PartialEq, Eq, ::prost::Message)]
pub struct ProtocolError {
    /// Encodes code according to the published schema.
    #[prost(enumeration = "ErrorCode", tag = "1")]
    pub code: i32,
    /// Encodes detail according to the published schema.
    #[prost(string, tag = "2")]
    pub detail: String,
    /// Encodes unsupported features according to the published schema.
    #[prost(string, repeated, tag = "3")]
    pub unsupported_features: Vec<String>,
}

/// Identifies the search mode alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum SearchMode {
    /// Indicates unspecified.
    Unspecified = 0,
    /// Indicates local search.
    LocalSearch = 1,
    /// Indicates mip.
    Mip = 2,
}

/// Identifies the execution stage alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum ExecutionStage {
    /// Indicates unspecified.
    Unspecified = 0,
    /// Indicates materializing.
    Materializing = 1,
    /// Indicates searching.
    Searching = 2,
    /// Indicates verifying.
    Verifying = 3,
}

/// Identifies the termination alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum Termination {
    /// Indicates unspecified.
    Unspecified = 0,
    /// Indicates completed.
    Completed = 1,
    /// Indicates limit reached.
    LimitReached = 2,
    /// Indicates cancelled.
    Cancelled = 3,
    /// Indicates rejected.
    Rejected = 4,
    /// Indicates execution failed.
    ExecutionFailed = 5,
}

/// Identifies the verification class alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum VerificationClass {
    /// Indicates unspecified.
    Unspecified = 0,
    /// Indicates absent.
    Absent = 1,
    /// Indicates rejected.
    Rejected = 2,
    /// Indicates fully feasible.
    FullyFeasible = 3,
    /// Indicates repair proposal.
    RepairProposal = 4,
}

/// Identifies the evidence kind alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum EvidenceKind {
    /// Indicates none.
    None = 0,
    /// Indicates local search exhausted.
    LocalSearchExhausted = 1,
    /// Indicates backend reported bound.
    BackendReportedBound = 2,
    /// Indicates backend reported infeasible.
    BackendReportedInfeasible = 3,
    /// Indicates backend reported optimal.
    BackendReportedOptimal = 4,
}

/// Identifies the error code alternative.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, ::prost::Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    /// Indicates unspecified.
    Unspecified = 0,
    /// Indicates invalid message.
    InvalidMessage = 1,
    /// Indicates unsupported version.
    UnsupportedVersion = 2,
    /// Indicates unsupported model.
    UnsupportedModel = 3,
    /// Indicates resource limit.
    ResourceLimit = 4,
    /// Indicates stale handle.
    StaleHandle = 5,
    /// Indicates wrong generation.
    WrongGeneration = 6,
    /// Indicates busy.
    Busy = 7,
    /// Indicates internal.
    Internal = 8,
    /// Indicates commitment mismatch.
    CommitmentMismatch = 9,
}

/// Contains the mutually exclusive worker envelope payloads.
pub mod worker_envelope {
    /// Identifies the envelope operation and its typed payload.
    #[derive(Clone, PartialEq, Eq, ::prost::Oneof)]
    pub enum Body {
        /// Carries the hello operation.
        #[prost(message, tag = "10")]
        Hello(super::Hello),
        /// Carries the capabilities operation.
        #[prost(message, tag = "11")]
        Capabilities(super::Capabilities),
        /// Carries the prepare operation.
        #[prost(message, tag = "12")]
        Prepare(super::Prepare),
        /// Carries the prepared operation.
        #[prost(message, tag = "13")]
        Prepared(super::Prepared),
        /// Carries the solve operation.
        #[prost(message, tag = "14")]
        Solve(super::Solve),
        /// Carries the progress operation.
        #[prost(message, tag = "15")]
        Progress(super::Progress),
        /// Carries the candidate operation.
        #[prost(message, tag = "16")]
        Candidate(super::Candidate),
        /// Carries the finished operation.
        #[prost(message, tag = "17")]
        Finished(super::Finished),
        /// Carries the release operation.
        #[prost(message, tag = "18")]
        Release(super::Release),
        /// Carries the released operation.
        #[prost(message, tag = "19")]
        Released(super::Released),
        /// Carries the error operation.
        #[prost(message, tag = "20")]
        Error(super::ProtocolError),
        /// Carries the cancel operation.
        #[prost(message, tag = "21")]
        Cancel(super::Cancel),
    }
}
