//! Exposes guarded reference enumeration without exposing backend inventory.

use super::{Error, ListedRef, Repository};
use crate::store::{Clock, LocalFs, RefInventory, Store};

impl<S: Store + RefInventory, C: Clock, F: LocalFs> Repository<S, C, F> {
    /// Lists matching current refs after independent guarded read checks.
    ///
    /// Byte globs use `*` within a component and `**` across components. The
    /// materialized result omits absent and denied candidates and preserves
    /// lexical order. It supplies no cross-ref snapshot or streaming bound.
    ///
    /// # Errors
    /// Rejects invalid patterns or credentials, unavailable complete inventories,
    /// historical verification failures and changed or revoked closing records.
    pub async fn list_refs(
        &self,
        pattern: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<Vec<ListedRef>, Error> {
        Ok(self
            .coordinator
            .guard()
            .list_refs(pattern, token, surface)
            .await?)
    }
}

impl<S: Store, C: Clock, F: LocalFs> Repository<S, C, F> {
    /// Lists readable root occurrence paths within one named current reference.
    ///
    /// Each canonical root and graft occurrence receives an independent current
    /// Read check. A grant limited to a nested root can discover that occurrence
    /// without authority over its parent or a sibling containing the same root
    /// digest. Returned absolute byte paths are sorted; ordinary directories
    /// are not invented as additional authorization roots. Absent references
    /// and entirely denied root inventories produce an empty list.
    ///
    /// Discovery validates token identity before metadata I/O and at completion,
    /// and requires the same complete current reference throughout. The backend
    /// metadata graph is materialized before filtering. These paths grant no
    /// content access or later authority; every subsequent operation must repeat
    /// its own current policy checks.
    ///
    /// # Errors
    /// Rejects malformed reference names or credentials, unavailable native or
    /// historical evidence, a changed complete current reference, and backend
    /// failures. No partial list escapes a failed operation.
    pub async fn readable_root_paths(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self
            .coordinator
            .guard()
            .readable_root_paths(reference, token, surface)
            .await?)
    }
}
