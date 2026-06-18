//! Hosted-key signing — re-export of the shared [`aos_hub_core::signing`].
//!
//! The hosted-key signing logic (the pure ed25519 [`sign_release_tag`] /
//! [`sign_partition`] / [`verify_release_tag`], and the port-driven
//! [`advance_channel`] / [`resign_tag`]) moved into
//! [`aos_hub_core::signing`] (RFC-0004 Phase 5) so the *same* code signs on
//! the native hub and the Cloudflare Worker. It is re-exported here so the hub's
//! `signing::…` paths — and `crate::signing::…` from the seed builder and the
//! console — stay stable.
//!
//! The relocated [`advance_channel`] / [`resign_tag`] take a
//! [`SurfaceWriteProvider`](aos_hub_core::surface_write::SurfaceWriteProvider)
//! and a [`Reindexer`](aos_hub_core::reindex::Reindexer) rather than a host
//! path; the hub passes its native
//! [`HubSurfaceWriteProvider`](crate::coreports::HubSurfaceWriteProvider) and
//! [`HubReindexer`](crate::coreports::HubReindexer).

pub use aos_hub_core::signing::*;
