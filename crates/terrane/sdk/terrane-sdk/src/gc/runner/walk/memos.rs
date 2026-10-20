//! Retains advisory Memos with independently reached output Nodes (DRV-19).
//!
//! A selected catalog row supplies ordinary record bytes only. Neither its
//! recipe key nor its claimed result introduces a root, recipe operand, history
//! or Chunk edge. Matching records inherit the genuine Node's proof position;
//! collecting a Memo never selects a derivation result for serving.

use super::{CollectionError, Expansion, WITNESS, history};
use crate::bucket::BucketBinding;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::guard::Guard;
use crate::pack::EntryKind;
use crate::store::{Clock, ContentStore, ContentValidator, LocalFs};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::gc::ProofContext;
use terrane_format::identity::Digest;

/// Associates actual selected Memos with already authenticated Node occurrences.
///
/// # Errors
/// Preserves selected-inventory, canonical-record, physical-content and Session
/// failures. No traversal marks are applied until the enclosing expansion passes.
pub(super) async fn expand<F, B, V, C>(
    guard: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    expansion: &mut Expansion,
) -> Result<(), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let mut outputs: BTreeMap<Digest, BTreeSet<(u8, ProofContext)>> = BTreeMap::new();
    for object in &expansion.objects {
        if object.kind == EntryKind::Node as u8
            && let Some(context) = &object.proof_context
        {
            // ROOT and INDEX describe Node roles. Only witness/full visitation
            // carries over to the associated kind-9 metadata record.
            outputs
                .entry(object.hash)
                .or_default()
                .insert((object.flags & WITNESS, context.clone()));
        }
    }

    if outputs.is_empty() {
        return Ok(());
    }

    for (identity, record) in guard.store().memo_records().await? {
        let Some(contexts) = outputs.get(&record.result_root()) else {
            continue;
        };

        // Inspection cached verified bytes but did not retain this identity.
        // This ordinary metadata read records the matching physical association
        // without changing mandatory recipe evaluation or current authority.
        guard.store().get(&identity, None).await?;
        let hash = identity.terrane_v1_digest().map_err(history::invalid)?;
        for (flags, context) in contexts {
            expansion.object(EntryKind::Memo as u8, hash, *flags, context);
        }
    }
    Ok(())
}
