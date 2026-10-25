//! Bounds only persistent compact journal backing under the actual byte ceiling.
//!
//! Both namespaces own separate map keys and identity hashes. All complete
//! request/response banks share one unrecycled canonical-byte limit. Content,
//! received/generated quarantine, connection owners and materialization remain
//! independent components; this quote cannot admit the complete SDK or Source.

use super::{CompactClientCustody, CompactClientOriginal, CompactJson, Id, ProviderError};
use crate::retained_metadata::requested_storage::tree_storage_data;
use std::mem::{align_of, size_of};

impl CompactClientCustody {
    /// Bounds future persistent journal backing at the unchanged local ceilings.
    ///
    /// Complete request and response banks share the one canonical-byte quota.
    /// Constructors refuse any Vec capacity differing from their exact measured
    /// demand, so the nine-times grammar bound covers actual retained capacities.
    /// Each endpoint can fill its own map, including unresolved failed sends.
    /// Map nodes, duplicate map IDs and identity hash strings are separate terms.
    /// No discount is taken for current use, negotiated entries or equal values.
    ///
    /// The caller admits this fixed arithmetic separately. Content reservations,
    /// original owners, all received/generated failure prefixes, encoding and
    /// materialization are excluded and require independent admission. This DATA
    /// result grants no allocation, Source, native or lifetime quota rights.
    ///
    /// # Errors
    /// Refuses unsupported tree layouts, arithmetic overflow or backing above
    /// the independent supplied restriction.
    pub fn journal_retained_storage_data(&self, maximum: usize) -> Result<usize, ProviderError> {
        let entries = self.maximum_requests.checked_mul(2).ok_or_else(refused)?;
        let banks = CompactJson::maximum_storage_bytes(self.maximum_bytes, maximum)?;
        let trees = tree_storage_data(
            2,
            entries,
            size_of::<Id>() + size_of::<CompactClientOriginal>(),
            align_of::<(Id, CompactClientOriginal)>(),
        )?;
        // request_hash creates these exact algorithm/domain/hex strings. A map
        // key is a fresh Id clone, independent of the ID sealed into its bank.
        let identity =
            crucible_node_format::MAX_ID_BYTES + "blake3-256".len() + "cnp.request.v1".len() + 64;
        let identities = entries.checked_mul(identity).ok_or_else(refused)?;
        banks
            .checked_add(trees)
            .and_then(|bytes| bytes.checked_add(identities))
            .filter(|&bytes| bytes <= maximum)
            .ok_or_else(refused)
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("compact SDK journal backing projection")
}
