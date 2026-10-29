//! Offline derivation of incomplete encrypted object requirements.
//!
//! A verified capture supplies exact source rows to bounded private SQL replay.
//! Projected records remain encrypted and unpublished until full stream EOF,
//! relational/lifetime/Direct provenance checks and independent readback finish.
//! Both commands require the original capture; an inventory cannot promote
//! itself into storage completeness or restore/provider/serving authority.
//!
//! ```text
//! capture/ -> derive -> requirements/ (private encrypted projections)
//! capture/ + requirements/ -> verify exact projection and retained SQL
//! ```

mod workflow;

pub use workflow::{derive_object_requirements, verify_object_requirements};
