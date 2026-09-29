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
mod source;

#[cfg(unix)]
pub use checkpoint::{
    DirectCompletionPage, DirectOciAllocation, DirectPublicationAdmission, DirectPublicationHeader,
    DirectRetainedCompletion, SqliteDirectCheckpoints, ensure_private_checkpoint_directory,
};

pub use engine::{
    DirectCheckpointStore, DirectClientError, DirectGrantAttempt, DirectObservedPart,
    DirectPartReceipt, DirectPartTransport, DirectUploadControl, DirectUploadObject,
    upload_direct_batch,
};
pub use provider::{
    PrivateProviderEndpoint, ProviderContext, ProviderError, ProviderOptions, ProviderTransport,
};

pub use metrics::{DirectControlKind, DirectTransferMetrics, DirectTransferSummary};

pub use source::{
    AdmittedSource, PartChecksum, PartChecksumAlgorithm, PartIdentity, PartSource,
    SOURCE_CHUNK_BYTES, SourceError, SourceWaveBudget, open_regular_source_file,
};

#[cfg(test)]
mod tests;
