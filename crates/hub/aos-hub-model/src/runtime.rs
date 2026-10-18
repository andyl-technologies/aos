//! Thread-safety bounds shared by native and single-threaded Worker ports.

/// Requires runtime ports to be thread-safe on native deployments.
///
/// Native request futures may move between Tokio workers, so their ports must
/// implement `Send + Sync`. Worker ports execute on one JavaScript thread and
/// have no such bound. Blanket implementations preserve one trait definition
/// for both deployments without requiring a persistence dependency.
#[cfg(not(target_arch = "wasm32"))]
pub trait RuntimeBounds: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> RuntimeBounds for T {}

/// Accepts runtime ports on a single-threaded WebAssembly deployment.
#[cfg(target_arch = "wasm32")]
pub trait RuntimeBounds {}

#[cfg(target_arch = "wasm32")]
impl<T> RuntimeBounds for T {}
