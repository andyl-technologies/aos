//! Expands complete authenticated metadata under exact root occurrences.
//!
//! Initial marking, checkpoint replay and fresh reconciliation use this same
//! expansion. It reads manifests and metadata packs, never data-chunk bodies.
//! Frontier and completion claims change only after the complete step succeeds.

mod attributes;
mod history;
mod indexes;
mod memos;

#[cfg(test)]
mod tests;

use super::{CollectionError, denied};
use crate::bucket::BucketBinding;
use crate::bucket::publication::collection_observation::MetadataStore;
use crate::guard::{ConsumedResolver, Guard, HistoryObservation};
use crate::selected_bridge::QualifiedCollectionRoots;
use crate::store::{Clock, ContentStore, ContentValidator, LocalFs};
use std::collections::{BTreeMap, BTreeSet};
use terrane_format::gc::{
    ExpandedContext, ExpandedObject, GcState, ParentCutoff, Pending, ProofContext,
};
use terrane_format::identity::{Digest, IdentityKind, TERRANE_V1};
use terrane_format::manifest::Manifest;
use terrane_format::tree_format::ContentRef;

const PARENT: u8 = 1;
const ROOT: u8 = 2;
const INDEX: u8 = 4;
const WITNESS: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisitMode {
    Full,
    Witness,
}

impl VisitMode {
    fn flags(self) -> u8 {
        match self {
            Self::Full => 0,
            Self::Witness => WITNESS,
        }
    }
}

/// Buffers one fallible expansion without altering persisted traversal claims.
#[derive(Default)]
struct Expansion {
    marks: BTreeSet<Digest>,
    objects: Vec<ExpandedObject>,
    contexts: Vec<ExpandedContext>,
    pending: Vec<Pending>,
}

impl Expansion {
    fn object(&mut self, kind: u8, hash: Digest, flags: u8, context: &ProofContext) {
        self.marks.insert(hash);
        self.objects.push(ExpandedObject {
            kind,
            hash,
            flags,
            proof_context: Some(context.clone()),
        });
    }

    fn witness(&mut self, hash: Digest, context: ProofContext) {
        self.pending.push(Pending {
            kind: 3,
            hash,
            parent_cutoff: ParentCutoff::RootsOnly,
            flags: WITNESS,
            proof_context: Some(context),
        });
    }

    fn complete(&mut self, pending: &Pending, context: Option<ProofContext>, mode: VisitMode) {
        match mode {
            VisitMode::Witness => self.objects.push(ExpandedObject {
                kind: 3,
                hash: pending.hash,
                flags: WITNESS,
                proof_context: context,
            }),
            VisitMode::Full => self.contexts.push(ExpandedContext {
                commit: pending.hash,
                parent_cutoff: pending.parent_cutoff,
                proof_context: context,
            }),
        }
    }

    fn apply(self, state: &mut GcState, marks: &mut BTreeSet<Digest>) {
        state.pending.remove(0);
        state.pending.extend(self.pending);
        marks.extend(self.marks);
        state.objects.extend(self.objects);
        state.objects.sort();
        state.objects.dedup();

        for incoming in self.contexts {
            merge_context(&mut state.expanded, incoming);
        }
        state.expanded.sort_by(|left, right| {
            (left.commit, &left.proof_context).cmp(&(right.commit, &right.proof_context))
        });
    }
}

fn merge_context(contexts: &mut Vec<ExpandedContext>, incoming: ExpandedContext) {
    if let Some(previous) = contexts.iter_mut().find(|previous| {
        previous.commit == incoming.commit && previous.proof_context == incoming.proof_context
    }) {
        if incoming.parent_cutoff.covers(previous.parent_cutoff) {
            previous.parent_cutoff = incoming.parent_cutoff;
        }
    } else {
        contexts.push(incoming);
    }
}

fn covered(state: &GcState, pending: &Pending, context: &ProofContext, mode: VisitMode) -> bool {
    match mode {
        VisitMode::Witness => state
            .objects
            .binary_search(&ExpandedObject {
                kind: 3,
                hash: pending.hash,
                flags: WITNESS,
                proof_context: Some(context.clone()),
            })
            .is_ok(),
        VisitMode::Full => state.expanded.iter().any(|previous| {
            previous.commit == pending.hash
                && previous.proof_context.as_ref() == Some(context)
                && previous.parent_cutoff.covers(pending.parent_cutoff)
        }),
    }
}

/// Authenticates one exact frontier item before acknowledging its complete edges.
///
/// # Errors
/// Refuses invalid proof positions, incomplete selected catalog/history/index
/// evidence, malformed manifests or side attribution, and changed held inputs.
/// Every lower verifier failure remains the source of its typed store error.
pub(crate) async fn expand<F, B, V, C>(
    guard: &Guard<MetadataStore<'_, '_, F, B, V>, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    root_histories: &QualifiedCollectionRoots<'_>,
    state: &mut GcState,
    marks: &mut BTreeSet<Digest>,
) -> Result<(), CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    root_histories.check_binding(observation, consumed)?;
    consumed.check_guard(guard)?;
    let pending = state.pending.first().cloned().ok_or_else(denied)?;
    if pending.kind != 3 {
        return Err(denied().into());
    }
    let view = match root_histories.history(&pending.hash)? {
        Some(verified) => history::retained_scoped(guard, verified)?,
        None => {
            history::acquire_scoped(
                guard,
                consumed,
                observation,
                pending.hash,
                root_histories.contextual_layer(&pending.hash)?,
            )
            .await?
        }
    };
    let mode = if pending.is_witness()
        || pending.is_parent()
            && !pending
                .parent_cutoff
                .allows(view.verified().tree().commit.commit().timestamp)
    {
        VisitMode::Witness
    } else {
        VisitMode::Full
    };
    let occurrences = history::select(&view.occurrences, pending.proof_context.as_ref())?;
    let mut expansion = Expansion::default();
    let mut targets = Vec::new();
    let mut expanded_any = false;
    let mut schedule_edges = false;
    let mut manifests = BTreeMap::new();

    for occurrence in occurrences {
        // Context-free legacy completion never authorizes a certified cut or
        // suppresses verification of a present canonical occurrence.
        if covered(state, &pending, &occurrence.context, mode) {
            continue;
        }
        schedule_edges = true;
        if mode == VisitMode::Full {
            let own_metadata_complete = state.expanded.iter().any(|previous| {
                previous.commit == pending.hash
                    && previous.proof_context.as_ref() == Some(&occurrence.context)
            });
            if own_metadata_complete {
                // Full completion authenticates this exact occurrence's own
                // metadata independently of parent-cutoff progress. The fresh
                // completed view still supplies newly eligible dependency edges.
                expansion.complete(&pending, Some(occurrence.context.clone()), mode);
                continue;
            }
        }
        let mut prepared = occurrence.clone();
        history::prepare_metadata(guard, view.verified(), &mut prepared)?;
        let occurrence = &prepared;
        expanded_any = true;
        expansion.marks.insert(pending.hash);
        for (node, is_root) in &occurrence.nodes {
            expansion.object(
                2,
                *node,
                mode.flags() | if *is_root { ROOT } else { 0 },
                &occurrence.context,
            );
            targets.push(attributes::Target::metadata(*node, occurrence));
        }
        let first_auxiliary = expansion.objects.len();
        indexes::expand(guard, occurrence, mode, &mut expansion).await?;
        targets.extend(
            expansion.objects[first_auxiliary..]
                .iter()
                .map(|object| attributes::Target::metadata(object.hash, occurrence)),
        );
        for file in &occurrence.files {
            match file.content {
                ContentRef::Inline(hash) => {
                    if mode == VisitMode::Full {
                        expansion.object(0, hash, 0, &occurrence.context);
                    }
                }
                ContentRef::Manifest(hash) => {
                    let identity = TERRANE_V1
                        .from_digest(IdentityKind::Manifest, &hash)
                        .map_err(history::invalid)?;
                    if let std::collections::btree_map::Entry::Vacant(entry) = manifests.entry(hash)
                    {
                        let bytes = guard.store().get(&identity, None).await?;
                        let manifest = Manifest::decode_verified(
                            &bytes,
                            &guard.config().chunk_profile,
                            &identity,
                        )
                        .map_err(|source| history::corrupt(identity.clone(), source))?;
                        entry.insert(manifest);
                    }
                    let manifest = manifests.get(&hash).ok_or_else(denied)?;
                    expansion.object(1, hash, mode.flags(), &occurrence.context);
                    if mode == VisitMode::Full {
                        for chunk in &manifest.chunks {
                            expansion.object(0, chunk.digest, 0, &occurrence.context);
                            targets.push(attributes::Target::manifest_member(
                                chunk.digest,
                                occurrence,
                                file,
                            ));
                        }
                    }
                }
            };
            targets.push(attributes::Target::entry(occurrence, file));
            if mode == VisitMode::Full {
                for dictionary in &file.dictionaries {
                    expansion.object(0, *dictionary, 0, &occurrence.context);
                    targets.push(attributes::Target::dictionary(
                        *dictionary,
                        occurrence,
                        file,
                    ));
                }
            }
        }
        targets.push(attributes::Target::metadata(pending.hash, occurrence));
        expansion.complete(&pending, Some(occurrence.context.clone()), mode);
    }

    if expanded_any {
        let records = guard.store().attribute_records().await?;
        attributes::expand(
            guard,
            attributes::Inputs {
                consumed,
                observation,
                view: &view,
                root_histories,
                records: &records,
            },
            targets,
            mode,
            &mut expansion,
        )
        .await?;
        memos::expand(guard, &mut expansion).await?;
    }
    if schedule_edges {
        history::schedule(&view.edges, &pending, mode, &mut expansion);
    }
    if pending.proof_context.is_none() {
        // This aggregate row is a replay observation only. Coverage checks use
        // each present occurrence above, never this context-free row.
        expansion.complete(&pending, None, mode);
    }
    root_histories.check_binding(observation, consumed)?;
    expansion.apply(state, marks);
    Ok(())
}
