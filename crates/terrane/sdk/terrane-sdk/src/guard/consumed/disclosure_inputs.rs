//! Captures ordinary disclosure inputs from the actual native Guard state.
//!
//! Configured source roles and separately checked retained-import trust provide
//! row data only. Their genuine protected controls and Original associations
//! remain with the owning publication and are independently revalidated.

use terrane_format::gc::publication::evidence::DisclosureRow;

use super::super::Guard;
use super::snapshot_disclosure::SnapshotDisclosureInputs;
use crate::store::StoreFailure;

/// Projects only actual public rows before the data-only adapter clears evidence.
///
/// # Errors
/// Rejects unavailable retained inputs or contradictory ordinary role selectors.
pub(super) fn capture<S, C>(
    _guard: &Guard<S, C>,
) -> Result<SnapshotDisclosureInputs, StoreFailure> {
    #[cfg(unix)]
    let mut rows = Vec::<DisclosureRow>::new();
    #[cfg(not(unix))]
    let rows = Vec::<DisclosureRow>::new();
    #[cfg(unix)]
    {
        for trust in _guard.retained_public_trust()? {
            // Imported issuer labels remain scoped to their actual trust record.
            // Only its disclosure-role data enters this configuration projection.
            for role in trust.disclosure_roles {
                rows.push(DisclosureRow {
                    repository: role.repository,
                    domain: role.domain,
                    public_key: role.public_key,
                    not_before: role.not_before,
                    not_after: role.not_after,
                });
            }
        }
        // Preserve refusal before consulting configured roles when retained
        // trust alone already contains conflicting selector data.
        let retained = SnapshotDisclosureInputs::from_rows(rows)?;
        rows = retained.rows().to_vec();
        for role in _guard.configured_disclosure_roles()? {
            rows.push(DisclosureRow {
                repository: role.repository,
                domain: role.domain,
                public_key: role.public_key,
                not_before: role.not_before,
                not_after: role.not_after,
            });
        }
    }
    SnapshotDisclosureInputs::from_rows(rows)
}
