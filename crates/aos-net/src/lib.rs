//! `aos-net` -- Low-level networking/transport library.
//!
//! Provides transport primitives for the AOS ecosystem:
//!
//! - Per-domain connection pooling and reuse
//! - Parallel transfers with concurrency control
//! - Resumable/incomplete download support
//! - HTTP/1.1 + HTTP/2 (ALPN negotiation)
//! - Multi-protocol support (HTTP, S3, SFTP, FTP, file://)
//! - Multi-part upload/download
//! - Progress tracking (callback-based)
//! - Auth management (per-domain credential store)
//! - Bandwidth limiting
//! - Retry with exponential backoff
//!
//! # Usage
//!
//! The primary API is [`TransferEngine`], which orchestrates all transfers:
//!
//! ```ignore
//! use aos_net::transfer::{TransferEngine, TransferEngineConfig};
//! use aos_net::types::TransferRequest;
//!
//! let engine = TransferEngine::new(TransferEngineConfig::default());
//!
//! // Simple GET to memory
//! let result = engine.execute(TransferRequest::get("https://example.com/file.tar.gz")).await?;
//!
//! // HEAD to check existence
//! let result = engine.head("https://example.com/file.tar.gz").await?;
//!
//! // Batch parallel downloads
//! let requests = vec![
//!     TransferRequest::get("https://example.com/a.tar.gz"),
//!     TransferRequest::get("https://example.com/b.tar.gz"),
//! ];
//! let results = engine.execute_batch(requests, None).await;
//! ```

pub mod auth;
pub mod bandwidth;
pub mod hash;
pub mod pool;
pub mod progress;
pub mod protocol;
pub mod retry;
pub mod transfer;
pub mod types;

// Re-export commonly used types at the crate root.
pub use auth::{AuthStore, Credential};
pub use bandwidth::BandwidthLimiter;
pub use hash::StreamingHasher;
pub use pool::{ConnectionPool, PoolConfig};
pub use progress::{BatchProgressHandler, NoopProgress, ProgressHandler};
pub use retry::RetryConfig;
pub use transfer::{TransferEngine, TransferEngineConfig};
pub use types::{
    HashAlgorithm, HashSpec, Method, TransferBody, TransferOutput, TransferRequest, TransferResult,
};
