//! Scoped assignment execution with independently supervised solver processes.
//!
//! A [`Session`] combines bounded admission and immutable execution policy.
//! [`providers`] authorize and supervise workers; the `dispatch-worker`
//! executable validates portable inputs and independently checks native output.
//! Model resources and solver CPU/memory entitlements remain separate contracts.
//!
//! # Examples
//!
//! Applications select installed executables through trusted configuration and
//! explicitly close a session when its accepted work is complete:
//!
//! ```no_run
//! use std::{path::PathBuf, sync::Arc, time::Duration};
//! use dispatch_model::Problem;
//! use dispatch_runtime::{
//!     CloseMode, RuntimeError, SessionBuilder, SolveOptions,
//!     providers::{SubprocessProvider, WorkerLaunch},
//! };
//!
//! async fn propose(
//!     problem: Problem,
//!     runner: PathBuf,
//!     backend: PathBuf,
//! ) -> Result<(), RuntimeError> {
//!     let launch = WorkerLaunch {
//!         runner,
//!         native_backend: backend,
//!         native_arguments: Vec::new(),
//!         session_generation: 0,
//!         worker_generation: 0,
//!         max_frame_bytes: 16 * 1024 * 1024,
//!     };
//!     let session = SessionBuilder::new(
//!         Arc::new(SubprocessProvider::new()),
//!         launch,
//!     ).start().await?;
//!     let result = session.submit(problem, SolveOptions::default())?.wait().await?;
//!     println!("{:?}: {:?}", result.termination, result.candidate);
//!     let cleanup = session.close(CloseMode::Drain, Duration::from_secs(5)).await?;
//!     println!("Cleanup: {cleanup:?}");
//!     Ok(())
//! }
//! ```

mod connection;
mod encoding;
mod error;
mod lease;
pub mod providers;
mod scheduler;
mod session;
mod types;
pub mod worker;

pub use error::RuntimeError;
pub use providers::{
    CooperativeCancellation, EmbeddedBackend, EmbeddedProvider, EmbeddedSolution,
    ExecutionProvider, ResourceGrant, SubprocessProvider, WorkerConnection, WorkerControl,
    WorkerLaunch,
};
pub use session::{Job, PreparedInput, Session, SessionBuilder};
pub use types::{
    CandidateClass, CleanupReport, CloseMode, EffectiveOptions, EvidenceKind, ExecutionGuarantee,
    ExecutionProfile, JobStatus, RejectionReason, RequiredGuarantees, SearchEvidence, SearchMode,
    SeedPolicy, SessionLimits, SolveOptions, SolveResult, StageTiming, Termination,
    UnavailabilityReason, WorkerFailureCause, WorkerFailureReport,
};
