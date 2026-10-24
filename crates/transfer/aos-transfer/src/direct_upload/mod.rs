//! Direct provider upload transport with bounded, replayable file ranges.
//!
//! Logical Hub admission and final publication remain protocol-adapter work.
//! This module does not authorize provider completion or visibility changes.

#[cfg(unix)]
mod checkpoint;
mod engine;
mod metrics;
mod network;
#[cfg(unix)]
mod policy;
mod provider;
mod provider_observation;
mod source;

#[cfg(unix)]
pub use checkpoint::{
    ensure_private_checkpoint_directory, DirectCompletionPage, DirectOciAllocation,
    DirectPublicationAdmission, DirectPublicationHeader, DirectRetainedCompletion,
    SqliteDirectCheckpoints,
};

pub use engine::{
    upload_direct_batch, DirectCheckpointStore, DirectClientError, DirectGrantAttempt,
    DirectObservedPart, DirectPartReceipt, DirectPartTransport, DirectUploadControl,
    DirectUploadObject,
};
pub use provider::{
    PrivateProviderEndpoint, ProviderContext, ProviderError, ProviderOptions, ProviderTransport,
};

pub use metrics::{DirectControlKind, DirectTransferMetrics, DirectTransferSummary};

pub use source::{
    open_regular_source_file, AdmittedSource, PartChecksum, PartChecksumAlgorithm, PartIdentity,
    PartSource, SourceError, SourceWaveBudget, SOURCE_CHUNK_BYTES,
};

#[cfg(test)]
mod tests;
