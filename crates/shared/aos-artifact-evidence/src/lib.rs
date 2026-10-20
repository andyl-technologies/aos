//! Portable identities and checked evidence for immutable artifact consumption.
//!
//! [`identity`] identifies artifact bytes and closure topology without assigning
//! module or activation policy. [`model`] owns the closed version-1 evidence
//! schema, [`document`] its canonical codec and required-feature admission, and
//! [`consumption`] checks realized linkage, execution, loading, and data access.
//! [`limits`] bounds decoding independently of module graph configuration.
//!
//! This crate performs no package lookup, host mutation, or filesystem access.
//! A checked report establishes its internal consistency; it does not itself
//! authenticate publication or prove a later live invocation consumed the bytes.
//!
//! # Examples
//!
//! ```no_run
//! use aos_artifact_evidence::consumption::CheckedArtifactConsumptionEvidence;
//!
//! let bytes = std::fs::read("artifact-consumption.json")?;
//! let checked = CheckedArtifactConsumptionEvidence::decode(&bytes)?;
//! assert_eq!(checked.document().schema, "aos.artifact-consumption.evidence/v1");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]

pub mod consumption;
pub mod diagnostic;
pub mod document;
pub mod identity;
pub mod limits;
pub mod model;

pub use diagnostic::DiagnosticCode;
pub use document::{RequiredFeature, VersionedDocument, decode_canonical, encode_canonical};
pub use identity::*;
pub use limits::{EVIDENCE_LIMITS_V1, LimitProfile};
pub use model::*;
