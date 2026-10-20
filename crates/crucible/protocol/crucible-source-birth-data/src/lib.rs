//! Shares portable complete-profile data and bounded SourceBirth derivation.
//!
//! [`profile`] defines the unchanged records, static checks and schema data used
//! by the transport and contained worker. [`source_birth`] owns their shared
//! literal/request/result codecs, canonical views and pure derivation schedule.
//! Engine retains installation, process containment, original Source association
//! and acceptance. Successful data validation or serialization grants no native
//! effect, Source, Birth, Initial, Recipe, registration or readiness authority.
//!
//! Ordinary parser/serializer allocations and failures remain subject to the
//! caller's resource envelope; this crate does not provide an OS supervisor.
//! Spec index: RFC-0025 files 01, 02, 05, 06, 08, 09.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod errors;
pub mod profile;
pub mod registration;
pub mod source_birth;

/// Preserves the original Host2 DATA factories.
pub mod host_definition;
/// Shares pure serializer geometry without runtime ownership.
pub mod serialization;

pub use errors::{ProviderError, RuntimeError};
