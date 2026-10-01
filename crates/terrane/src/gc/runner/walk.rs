//! Expands actual authenticated commit contexts without reading chunk plaintext.

use super::{CollectionError, denied};
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::store::{Clock, Store};
use std::collections::BTreeSet;
use terrane_core::gc::{
    ExpandedContext, ExpandedObject, GcState, ParentCutoff, Pending, ProofContext,
};
use terrane_core::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_core::manifest::Manifest;
use terrane_core::tree_format::{ContentRef, EntryKind};

/// Authenticates one complete signed context before mutating its traversal claims.
///
/// # Errors
/// Rejects stale proof positions, malformed content metadata and unverified history.
pub(crate) async fn expand<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    state: &mut GcState,
    marks: &mut BTreeSet<Digest>,
) -> Result<(), CollectionError> {
    let pending = state.pending.first().cloned().ok_or_else(denied)?;
    if pending.kind != 3 || pending.proof_context.is_some() {
        return Err(denied().into());
    }
    let verified = guard
        .verified_tree_observed(pending.hash, observation.tracked(consumed))
        .await?;
    let witness = pending.is_witness()
        || pending.is_parent()
            && !pending
                .parent_cutoff
                .allows(verified.commit.commit().timestamp);
    let covered = if witness {
        state
            .objects
            .binary_search(&ExpandedObject {
                kind: 3,
                hash: pending.hash,
                flags: 8,
                proof_context: None,
            })
            .is_ok()
    } else {
        state.expanded.iter().any(|context| {
            context.commit == pending.hash
                && context.proof_context.is_none()
                && context.parent_cutoff.covers(pending.parent_cutoff)
        })
    };
    if covered {
        state.pending.remove(0);
        return Ok(());
    }

    let mut additions = BTreeSet::from([pending.hash]);
    additions.extend(verified.evidence.nodes.keys().copied());
    let mut objects = Vec::new();
    for occurrence in verified
        .evidence
        .occurrences(guard.config().min_chunk_size)?
    {
        let proof_context = ProofContext::new(pending.hash, occurrence.root, occurrence.path)?;
        let tree = verified
            .evidence
            .tree(occurrence.root, guard.config().min_chunk_size)?;
        for node in tree.nodes() {
            objects.push(ExpandedObject {
                kind: 2,
                hash: node.identity(),
                flags: if node.identity() == occurrence.root {
                    2
                } else {
                    0
                } | if witness { 8 } else { 0 },
                proof_context: Some(proof_context.clone()),
            });
        }
        let mut files = Vec::new();
        for item in tree.iter() {
            let mut entries = vec![&item.entry];
            while let Some(entry) = entries.pop() {
                match &entry.kind {
                    EntryKind::File { content, .. } => files.push(*content),
                    EntryKind::Conflict { candidates, base } => {
                        entries.extend(candidates);
                        if let Some(Some(base)) = base {
                            entries.push(base);
                        }
                    }
                    _ => {}
                }
            }
        }
        // Tree values hold local Rc nodes. Drop them before the next async read.
        drop(tree);
        for content in files {
            match content {
                ContentRef::Inline(hash) if !witness => {
                    additions.insert(hash);
                }
                ContentRef::Inline(_) => {}
                ContentRef::Manifest(hash) => {
                    let identity = TERRANE_V1
                        .from_digest(IdentityKind::Manifest, &hash)
                        .map_err(|_| denied())?;
                    let bytes = guard.store().get(&identity, None).await?;
                    let manifest =
                        Manifest::decode_verified(&bytes, &guard.config().chunk_profile, &identity)
                            .map_err(|_| denied())?;
                    additions.insert(hash);
                    if !witness {
                        additions.extend(manifest.chunks.into_iter().map(|chunk| chunk.digest));
                    }
                }
            }
        }
    }

    let mut next = verified
        .commit
        .commit()
        .parents
        .iter()
        .map(|hash| Pending {
            kind: 3,
            hash: *hash,
            parent_cutoff: pending.parent_cutoff,
            flags: if witness { 8 } else { 1 },
            proof_context: None,
        })
        .collect::<Vec<_>>();
    next.extend(
        terrane_core::provenance::source_commit_references(&verified.commit).map(|hash| Pending {
            kind: 3,
            hash,
            parent_cutoff: ParentCutoff::RootsOnly,
            flags: 8,
            proof_context: None,
        }),
    );

    // Every fallible read and historical check completes before frontier mutation.
    state.pending.remove(0);
    state.pending.extend(next);
    marks.extend(additions);
    state.objects.extend(objects);
    if witness {
        state.objects.push(ExpandedObject {
            kind: 3,
            hash: pending.hash,
            flags: 8,
            proof_context: None,
        });
    } else if let Some(context) = state
        .expanded
        .iter_mut()
        .find(|context| context.commit == pending.hash && context.proof_context.is_none())
    {
        context.parent_cutoff = pending.parent_cutoff;
    } else {
        state.expanded.push(ExpandedContext {
            commit: pending.hash,
            parent_cutoff: pending.parent_cutoff,
            proof_context: None,
        });
    }
    state.expanded.sort_by_key(|context| context.commit);
    state.objects.sort();
    state.objects.dedup();
    Ok(())
}
