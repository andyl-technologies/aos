//! Resolves requested paths to canonical root authorization units.

use super::{TreeEvidence, invalid};
use crate::store::StoreFailure;

pub(crate) fn contains_root(ancestor: &[u8], path: &[u8]) -> bool {
    ancestor == b"/"
        || ancestor == path
        || path
            .strip_prefix(ancestor)
            .is_some_and(|tail| tail.starts_with(b"/"))
}

impl TreeEvidence {
    pub(crate) fn containing_root(
        &self,
        path: &[u8],
        minimum: u64,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.policy_path(path, minimum)?;
        self.occurrences(minimum)?
            .into_iter()
            .filter(|root| contains_root(&root.path, path))
            .max_by_key(|root| root.path.len())
            .map(|root| root.path)
            .ok_or_else(invalid)
    }
}
