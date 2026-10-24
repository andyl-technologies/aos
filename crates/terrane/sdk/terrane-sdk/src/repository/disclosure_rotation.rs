//! Rotates dedicated source keys through a current-authorized selected Guard update.
//!
//! This operation preserves immutable historical roles and completed source
//! lineages. Ordinary reopening still compares the exact selected snapshot;
//! it never installs an unselected or incomplete rotation as a repair.

use crate::bucket::{BucketBinding, FileBucket};
use crate::repository::Repository;
use crate::store::{Clock, ContentValidator, LocalFs};

impl<F, B, V, C> Repository<FileBucket<F, B, V>, C, F>
where
    F: LocalFs + BucketBinding + Sync,
    B: Clock + BucketBinding + Sync,
    V: ContentValidator + BucketBinding + Sync,
    C: Clock + Sync,
    FileBucket<F, B, V>: Sync,
{
    /// Selects a fresh dedicated disclosure key while retaining historical verification roles.
    ///
    /// The physical native publisher independently checks current Admin rights
    /// and carries every existing completed source through the selected update.
    ///
    /// # Errors
    /// Preserves current authorization, exact configuration, original authority,
    /// dependency, issue-time and durable publication failures.
    pub async fn rotate_disclosure_key(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<[u8; 32], crate::repository::Error> {
        self.coordinator()
            .rotate_disclosure_key(reference, token, surface)
            .await
            .map_err(crate::repository::Error::Advance)
    }
}
