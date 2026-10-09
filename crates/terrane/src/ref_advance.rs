//! Coordinates guarded durable ref transitions from specification 09.
//!
//! The coordinator publishes immutable content and its verified commit before
//! appending an exact immutable reflog record and comparing the entire previous
//! authority record. Runtime-specific waiting remains behind the injected clock.

// Guard diagnostics reuse the operation's actual clock without another tracer.
#[cfg(test)]
mod phase_trace;
#[cfg(test)]
pub(crate) use phase_trace::PhaseTrace;

mod coordinator;
mod disclosure;
#[cfg(unix)]
mod disclosure_rotation;
mod native;
#[cfg(unix)]
mod overlay;
mod prepared;
mod watch;

#[cfg(all(test, feature = "tokio"))]
pub(crate) mod tests;

#[cfg(all(test, feature = "tokio", unix))]
pub(crate) mod native_fixture;

#[cfg(all(test, feature = "tokio", unix))]
mod consumed_tests;

#[cfg(all(test, feature = "tokio"))]
mod fault_tests;

#[cfg(all(test, feature = "tokio"))]
mod read_tests;

#[cfg(all(test, feature = "tokio"))]
mod attribute_tests;

#[cfg(all(test, feature = "tokio"))]
mod join_tests;

#[cfg(all(test, feature = "tokio"))]
mod source_tests;

#[cfg(all(test, feature = "tokio"))]
mod disclosure_tests;

#[cfg(all(test, feature = "tokio"))]
mod domain_tests;

#[cfg(all(test, feature = "tokio", unix))]
mod original_tests;

pub use crate::guard::{CommitRequest, StagedUpload};
pub(crate) use coordinator::NativeStage;
pub use coordinator::{
    AdvanceError, CommitTiming, Coordinator, FoldOutcome, TagAnnotation, WriterSession,
};
pub use disclosure::DisclosureUpload;
pub(crate) use prepared::{PreparedAdvance, PublicationStep};
pub use watch::{GuardedWatch, WatchClock};

pub(crate) use native::{
    FsRef, NativeTagRequest, PublicationBinding, PublicationClock, PublicationObservation,
    RetainedPublication,
};

#[cfg(all(test, feature = "tokio", unix))]
mod legacy_completion_tests;

#[cfg(all(test, feature = "tokio", unix))]
mod meta_batch_tests;

#[cfg(all(test, feature = "tokio", feature = "surface-sdk", unix))]
mod active_completion_tests;
