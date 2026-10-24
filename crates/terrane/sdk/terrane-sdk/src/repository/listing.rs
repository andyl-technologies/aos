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
