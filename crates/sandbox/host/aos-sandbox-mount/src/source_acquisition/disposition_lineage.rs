//! Exact immutable-ID preserving references at one Reserved→Consumed cut.
//!
//! An initial root and tail name the same record. Replacing its sole stored
//! revision therefore advances both references; a later attempt advances only
//! its exact tail. No foreign or inferred historical reference is repaired.

use super::format::state_error;
use super::model::{
    ProviderAttemptStateV2, QueryLineageV2, RecordRefV2, SourceProviderQueryAttemptV2,
};
use crate::Result;

pub(super) fn advance_consumed_lineage(
    lineage: &mut QueryLineageV2,
    predecessor: &SourceProviderQueryAttemptV2,
    consumed: &SourceProviderQueryAttemptV2,
    successor: RecordRefV2,
) -> Result<()> {
    let previous = RecordRefV2 {
        id: predecessor.attempt_id,
        revision: predecessor.revision,
        record_digest: predecessor.record_digest,
    };
    let exact_successor = RecordRefV2 {
        id: consumed.attempt_id,
        revision: consumed.revision,
        record_digest: consumed.record_digest,
    };
    // Reconstruct only the exact Reserved record: all signed request, intent,
    // session, attempt/owner and predecessor-witness fields remain identical.
    let mut reconstructed = consumed.clone();
    reconstructed.revision = predecessor.revision;
    reconstructed.record_digest = predecessor.record_digest;
    reconstructed.state = ProviderAttemptStateV2::Reserved;
    if predecessor.revision != 1
        || consumed.revision != 2
        || !matches!(predecessor.state, ProviderAttemptStateV2::Reserved)
        || !matches!(
            consumed.state,
            ProviderAttemptStateV2::DispositionConsumed { .. }
        )
        || reconstructed != *predecessor
        || successor != exact_successor
        || lineage.tail != previous
        || lineage.root.id != predecessor.lineage_root_attempt_id
        || (lineage.root.id == previous.id && lineage.root != previous)
    {
        return Err(state_error(
            "consumed disposition does not replace its exact lineage predecessor",
        ));
    }
    if lineage.root == previous {
        lineage.root = successor;
    }
    lineage.tail = successor;
    Ok(())
}
