// Deprecated: REST+SSE client — use `client::AosClient` (ConnectRPC) instead.
pub mod build;
// Deprecated: SSE parser — use `client::AosClient` (ConnectRPC) instead.
pub mod sse;
/// ConnectRPC-based client for the AOS server.
pub mod client;

pub use build::{GcResponse, RemoteClient};
pub use sse::{EventAction, SseEvent, SseStream};
pub use client::AosClient;
