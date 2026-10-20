//! Retains private provisioning publication actions across the canonical Core engine.
//!
//! Historical records and public constructors cannot issue these actions. The
//! actual installed issuer must first complete its genuine new C continuation,
//! Root admission and Session transition, and pay the complete concrete inputs.
//! Existing Reconciler engines own admission, activation and effect progression.

pub(crate) mod action;
pub(crate) mod completion;

#[doc(hidden)]
pub use action::{OriginalPublicationActionV1, OriginalPublicationActionClosedV1};

mod issuance;
#[doc(hidden)]
pub use issuance::{OriginalStorageApplyIssuanceV1, OriginalStorageApplyIssuanceClosedV1};
