//! Rotates dedicated source keys through a current-authorized selected Guard update.
//!
//! This operation preserves immutable historical roles and completed source
//! lineages. Ordinary reopening still compares the exact selected snapshot;
//! it never installs an unselected or incomplete rotation as a repair.

use crate::bucket::{BucketBinding, FileBucket};
use crate::ref_advance::{AdvanceError, Coordinator};
use crate::store::{Clock, ContentValidator, LocalFs};

impl<F, B, V, C> Coordinator<FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    /// Rotates the physical source's dedicated disclosure key under current Admin authority.
    ///
    /// The complete selected Guard gains one freshly generated public role.
    /// Historical role rows remain unchanged, and existing completed sources
    /// retain their original authority and exact dependency evidence. A rotation
    /// requires an issue time strictly later than previous role starts; equal
    /// timestamps cannot select a new key unambiguously.
    ///
    /// The supplied reference must be the configured policy authority when one
    /// is present. The token's current Admin rights, whole head, epochs and ACLs
    /// remain checked through the native durable acknowledgment.
    ///
    /// # Errors
    /// Rejects missing native authority, denied or expired current Admin rights,
    /// mismatched selected configuration, ambiguous issue time, changed protected
    /// records, incomplete retained dependencies and failed durable publication.
    /// A failed durable installation can leave an unselected role; ordinary
    /// reopening refuses that incomplete state rather than repairing it.
    pub async fn rotate_disclosure_key(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<[u8; 32], AdvanceError> {
        let started = self.guard().clock().monotonic();
        crate::selected_bridge::native_guard::disclosure_rotation::rotate(
            self.guard(),
            reference,
            token,
            surface,
            started,
            self.maximum_commit_duration(),
        )
        .await
        .map_err(AdvanceError::Store)
    }
}
