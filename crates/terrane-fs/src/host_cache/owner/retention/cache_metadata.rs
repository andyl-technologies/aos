//! Releases actual reconstruction custody only after dependent sealed retirement.

use super::{Custody, RetainedManifest, hex, invalid};
use crate::{host_cache::NativeManifestSource, publisher_local::client::CacheBodyCompletion};
use std::{io, sync::Arc};

impl Custody {
    /// Removes original metadata registry entries after synchronized pin removal.
    ///
    /// # Errors
    /// Refuses an unrelated final reply, changed native source or remaining policy
    /// protection. Returned descriptors must drop outside the embedded-state lock.
    pub(in crate::host_cache::owner) fn release_retired_metadata(
        &mut self,
        metadata: &[Arc<RetainedManifest>],
        completion: &CacheBodyCompletion,
    ) -> io::Result<Vec<Arc<NativeManifestSource>>> {
        super::super::publication::residence::check_snapshot(self)?;
        for retained in metadata {
            completion.check_metadata(retained)?;
            let token = hex(retained.retention_id());
            let purpose = format!("metadata:{token}");
            if self.state.pins.iter().any(|row| row.owner == purpose)
                || self.state.leases.iter().any(|row| row.owner == purpose)
                || self.state.reservations.iter().any(|row| row.id == token)
                || !self
                    .sources
                    .get(retained.retention_id())
                    .is_some_and(|source| Arc::ptr_eq(source, &retained.source))
            {
                return Err(invalid(
                    "retired metadata differs from original synchronized custody",
                ));
            }
        }
        Ok(metadata
            .iter()
            .filter_map(|retained| self.sources.remove(retained.retention_id()))
            .collect())
    }
}
