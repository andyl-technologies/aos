/// ConnectRPC-based client for the AOS server.
pub mod client;

pub use client::AosClient;

// Re-export proto types that consumers need.
pub use aos_proto::aos::build::v1::BuildEvent;
pub use aos_proto::aos::gc::v1::{EvictionCandidate, GcResponse};
