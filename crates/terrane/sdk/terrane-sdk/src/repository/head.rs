//! Exposes current ref metadata through the repository's ordinary read guard.

use terrane_format::{auth::Verb, refs::RefRecord};

use super::{Error, Repository};
use crate::store::{Clock, LocalFs, Store};

impl<S: Store, C: Clock, F: LocalFs> Repository<S, C, F> {
    /// Reads a complete current ref record under fresh whole-root Read authority.
    ///
    /// The same guard checks token validity, current root ACLs and backend home
    /// as other repository reads. An authorized absent ref returns `None`.
    /// Branches and immutable tags use this point operation without materializing
    /// a reflog suffix or requiring a complete inventory. The result retains
    /// every record field, including policy and the candidate selector.
    ///
    /// Returned metadata grants no authority to read the named commit or mutate
    /// the ref. Each later operation must perform its own current checks. This
    /// operation does not add a distributed freshness guarantee to its backend.
    ///
    /// # Errors
    /// Rejects malformed names, invalid or expired credentials, current ACL or
    /// home denial, invalid historical evidence and backend failures. Absence
    /// never substitutes for a denied or failed read.
    pub async fn ref_head(
        &self,
        reference: &str,
        token: &[u8],
        surface: &str,
    ) -> Result<Option<RefRecord>, Error> {
        let authorized = self
            .coordinator
            .guard()
            .authorize(reference, token, Verb::Read, &[], surface)
            .await?;
        Ok(authorized.record().cloned())
    }
}
