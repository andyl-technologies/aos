//! Verifies publication claims and orders immutable host publication.
//!
//! A manifest identity authenticates metadata, while its chunk commitments
//! authenticate assembled plaintext. Kernel adapters own descriptor lifetimes;
//! state adapters acknowledge only durable verity bindings.

mod claim;
mod leases;
mod sequence;
mod state;
pub use leases::{
    MAX_RETIREMENT_RECORD_BYTES, RetirementInode, RetirementLease, RetirementLeaseRequest,
    RetirementRecordCandidate,
};

pub use claim::{PublicationClaim, PublicationRecipe};
pub use sequence::{
    AdoptionFailure, PublicationKernel, PublicationState, PublishedObject, Publisher,
    RetainedPublishedObject, VerityBinding,
};
pub use state::FsPublicationState;
