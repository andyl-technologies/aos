//! `aos-net` -- Low-level networking/transport library.
//!
//! Provides transport primitives for the AOS ecosystem:
//!
//! - Per-domain connection pooling and reuse
//! - Parallel transfers with concurrency control
//! - Resumable/incomplete download support
//! - HTTP/1.1 + HTTP/2 (ALPN negotiation)
//! - Multi-protocol support (HTTP, S3, SFTP, and `file://`)
//! - Backend-neutral multipart uploads with continuation policy
//! - Per-operation structured progress observation
//! - Auth management (per-domain credential store)
//! - Bandwidth limiting
//! - Retry with exponential backoff
//!
//! # Architecture
//!
//! The crate is organized in layers:
//!
//! - [`transfer`] -- the [`TransferEngine`], which orchestrates every
//!   transfer: it picks a protocol from the URL scheme, acquires a
//!   connection-pool permit, applies credentials, retries on transient
//!   failures, and runs the streaming pipeline (per-chunk hashing,
//!   bandwidth limiting, and progress callbacks).
//! - [`managed`] -- identity-bound durable downloads, atomic installation,
//!   mirror fallback, streaming hash-only downloads, and rewindable uploads.
//! - [`multipart`] -- the [`MultipartBackend`] adapter contract and shared
//!   multipart session orchestration.
//! - [`protocol`] -- the [`protocol::Protocol`] trait plus per-scheme
//!   implementations for HTTP(S), S3, SFTP/SSH, and `file://`.
//! - [`types`] -- request/response types ([`TransferRequest`],
//!   [`TransferResult`], [`TransferOutput`], ...).
//! - Supporting services: [`auth`] (per-domain [`AuthStore`]), [`pool`]
//!   (per-host/global concurrency limits), [`retry`] (backoff with
//!   jitter and error classification), [`bandwidth`] (token-bucket
//!   [`BandwidthLimiter`]), [`hash`] (streaming SHA-256/SHA-512
//!   verification), and [`progress`] (callback traits).
//!
//! # Usage
//!
//! The primary API is [`TransferManager`], which orchestrates all transfers:
//!
//! ```ignore
//! use aos_net::{TransferManager, TransferManagerConfig, TransferRequest};
//!
//! let manager = TransferManager::new(TransferManagerConfig::default());
//!
//! // Simple GET to memory
//! let result = manager.execute(TransferRequest::get("https://example.com/file.tar.gz")).await?;
//!
//! // HEAD to check existence
//! let result = manager.head("https://example.com/file.tar.gz").await?;
//!
//! // Batch parallel downloads
//! let requests = vec![
//!     TransferRequest::get("https://example.com/a.tar.gz"),
//!     TransferRequest::get("https://example.com/b.tar.gz"),
//! ];
//! let results = manager.execute_batch(requests, None).await;
//! ```

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
pub mod network_configuration;
#[cfg(feature = "transfer")]
pub mod pool;
#[cfg(feature = "transfer")]
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
    MultipartAdmission, MultipartBackend, MultipartFailurePolicy, MultipartSessionState,
    MultipartSource, MultipartUploadRequest, MultipartUploadResult,
};
pub use network_configuration::{BootstrapLinkSelector, BootstrapNetwork};
#[cfg(feature = "transfer")]
pub use pool::{ConnectionPool, PoolConfig};
#[cfg(feature = "transfer")]
pub use progress::{
    BatchProgressHandler, NoopObserver, NoopProgress, ProgressHandler, TransferEvent,
    TransferObserver,
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
