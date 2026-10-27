//! Compares complete historical Runtime and publication assignment links.
//!
//! Native owners select and validate both records through their existing full
//! namespace engines. This predicate accepts DATA only and establishes no live
//! ownership, currentness, publication acceptance or execution authority.

use super::{RuntimeAuthorityBindingV1, RuntimeAuthorityStateV1};
use crate::publication::PublicationHistoryV1;

/// Reports differing historical binding and publication links.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("historical assignment binding and publication links differ")]
pub struct CurrentAssignmentLinksDataErrorV2;

/// Compares the same bound state, publication, manifest and lease identities.
///
/// # Errors
/// Rejects a non-bound state or a different publication, canonical manifest,
/// lease digest or lease generation.
pub fn require_current_assignment_history_data_v2(
    binding: &RuntimeAuthorityBindingV1,
    publication: &PublicationHistoryV1,
) -> Result<(), CurrentAssignmentLinksDataErrorV2> {
    if binding.state() != RuntimeAuthorityStateV1::Bound
        || binding.publication_digest() != publication.digest()
        || binding.manifest().canonical_bytes() != publication.manifest().canonical_bytes()
        || binding.lease_digest() != publication.lease_digest()
        || binding.lease_generation() != publication.lease_generation()
    {
        return Err(CurrentAssignmentLinksDataErrorV2);
    }
    Ok(())
}

/// Prices concrete borrowed-link arguments and the typed return forwarding.
///
/// This is Memory-only DATA. It does not price records as Rust fields or grant
/// admission. Returns `None` if checked representation arithmetic overflows.
#[must_use]
pub fn current_assignment_links_control_bytes_v2() -> Option<usize> {
    std::mem::size_of::<(&RuntimeAuthorityBindingV1, &PublicationHistoryV1)>()
        .checked_mul(3)?
        .checked_add(
            std::mem::size_of::<Result<(), CurrentAssignmentLinksDataErrorV2>>().checked_mul(3)?,
        )
}
