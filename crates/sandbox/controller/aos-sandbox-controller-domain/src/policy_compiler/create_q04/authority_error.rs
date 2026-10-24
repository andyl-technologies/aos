//! Projects real native Authority causes at the existing Q04 boundary.
//!
//! Canonical packet/model failures retain their historical Q04 categories.
//! New native owner and currentness failures move through Source-genesis's
//! owning Authority variant; no marker or formatted diagnostic replaces them.

use aos_sandbox_policy::native::RootAuthorityErrorV1;

use super::CreateQ04ErrorV1;
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

/// Moves the actual native Authority failure into its existing Q04 category.
pub(super) fn map_root_authority_error_v1(error: RootAuthorityErrorV1) -> CreateQ04ErrorV1 {
    use RootAuthorityErrorV1 as Native;

    match error {
        Native::Journal(error) => {
            match SourceGenesisErrorV1::from(Native::Journal(error)) {
                SourceGenesisErrorV1::Journal(error) => CreateQ04ErrorV1::Journal(error),
                original => CreateQ04ErrorV1::SourceGenesis(original),
            }
        }
        Native::Q04Data(error) => CreateQ04ErrorV1::from(error),
        Native::ControllerProject(error) => CreateQ04ErrorV1::from(error),
        Native::CacheReadback(error) => CreateQ04ErrorV1::from(error),
        Native::CacheNative(error) => CreateQ04ErrorV1::CacheJournal(error),
        Native::SignedInput(error) => CreateQ04ErrorV1::Deployment(error.into()),
        Native::Allocation(error) => CreateQ04ErrorV1::Allocation(error),
        original @ (Native::NonCanonical
        | Native::Conflict
        | Native::Stale
        | Native::AdmissionClosed
        | Native::Currentness(_)
        | Native::Origin(_)
        | Native::OriginBorrow(_)
        | Native::Credential(_)
        | Native::Seed(_)
        | Native::Authorization(_)
        | Native::AuthorizationSignature(_)
        | Native::Controller(_)
        | Native::ControllerGenesis(_)
        | Native::Source(_)
        | Native::Transport(_)
        | Native::Kernel(_)
        | Native::GenesisOpening(_)
        | Native::GenesisMutation(_)
        | Native::SavedFloorData(_)) => CreateQ04ErrorV1::SourceGenesis(original.into()),
    }
}
