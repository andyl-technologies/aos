//! Reusable transport operations and caller-owned progress observation.
//!
//! [`progress`] defines presentation-neutral observers and shared progress
//! handles and is available without default features. The default `transfer`
//! feature enables connection pooling, resumable downloads, multipart uploads,
//! authentication, integrity verification, and HTTP, S3, SFTP, and file transports.
//!
//! With `transfer` enabled, the `transfer` module owns orchestration, `managed`
//! provides durable downloads and uploads, `multipart` coordinates upload
//! sessions, and `protocol` implements transport backends. Supporting modules
//! own request types, authentication, pooling, retry policy, and bandwidth limits.

#[cfg(feature = "transfer")]
pub mod auth;
#[cfg(feature = "transfer")]
pub mod bandwidth;
#[cfg(feature = "transfer")]
pub mod hash;
#[cfg(feature = "transfer")]
pub mod managed;
#[cfg(feature = "transfer")]
pub mod multipart;
#[cfg(feature = "transfer")]
pub mod pool;
pub mod progress;
#[cfg(feature = "transfer")]
pub mod protocol;
#[cfg(feature = "transfer")]
pub mod retry;
#[cfg(feature = "transfer")]
pub mod transfer;
#[cfg(feature = "transfer")]
pub mod types;

// Re-export commonly used types at the crate root.
#[cfg(feature = "transfer")]
pub use auth::{AuthStore, Credential};
#[cfg(feature = "transfer")]
pub use bandwidth::BandwidthLimiter;
#[cfg(feature = "transfer")]
pub use bytes::Bytes;
#[cfg(feature = "transfer")]
pub use hash::StreamingHasher;
#[cfg(feature = "transfer")]
pub use managed::{
    DownloadRequest, DownloadResult, HashDownloadRequest, HashDownloadResult, ResumePolicy,
    UploadRequest, UploadSource,
};
#[cfg(feature = "transfer")]
pub use multipart::{
    MultipartAdmission, MultipartBackend, MultipartFailurePolicy, MultipartSessionMissing,
    MultipartSessionState, MultipartSource, MultipartUploadRequest, MultipartUploadResult,
};
#[cfg(feature = "transfer")]
pub use pool::{ConnectionPool, PoolConfig};
pub use progress::{
    BatchProgressHandler, NoopObserver, NoopProgress, ProgressHandler, ProgressSink, TransferEvent,
    TransferObserver, TransferProgress,
};
#[cfg(feature = "transfer")]
pub use retry::RetryConfig;
#[cfg(feature = "transfer")]
pub use transfer::{TransferEngine, TransferEngineConfig};
#[cfg(feature = "transfer")]
pub use types::{
    HashAlgorithm, HashSpec, Method, TransferBody, TransferOutput, TransferRequest, TransferResult,
    TransferSink,
};

/// The shared transfer manager used by CLI and service workflows.
///
/// `TransferEngine` remains as the compatibility name while callers migrate
/// to the manager terminology. Both names refer to the same implementation and
/// therefore share identical pooling, retry, resume, integrity, and progress
/// behavior.
#[cfg(feature = "transfer")]
pub type TransferManager = TransferEngine;

/// Configuration for [`TransferManager`].
#[cfg(feature = "transfer")]
pub type TransferManagerConfig = TransferEngineConfig;
