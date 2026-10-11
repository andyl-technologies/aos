//! Closed portable descriptor, capability, owner, and binding schemas.
//!
//! ```json
//! { "id": "owner/0", "participant_ids": ["machine/0"], "state_domain_ids": ["cpu/0"] }
//! ```
//!
//! Local validation checks structure and bounds. Graph admission additionally
//! resolves all content and schemas, authenticates authority, and checks truthful
//! qualification and domain coverage before these records authorize any effect.

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    Bound, ContentRef, ContractError, Endpoint, Extensions, HashRef, Id, IdSet, Phase, Position,
    QuantumGrid, U64, Validate, Version, canonical, invalid,
    values::{validate_ids, validate_sorted},
};

// A nullable field is still required on the wire. Supplying an explicit
// deserializer disables serde's implicit default for missing Option fields.
pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

mod bindings;
mod descriptors;
mod extensions;
mod manifests;
mod profiles;

pub use bindings::*;
pub use descriptors::*;
pub use extensions::*;
pub use manifests::*;
pub use profiles::*;

mod capture;
mod events;
mod receipts;

pub use capture::*;
pub use events::*;
pub use receipts::*;

mod control_records;
pub use control_records::*;
