//! Reconstructs complete canonical auxiliary data from immutable namespace inputs.

use std::collections::{BTreeMap, BTreeSet};

use terrane_format::identity::{Digest, IdentityKind};
use terrane_format::indexing::{
    IndexEvaluationRecipe, IndexRoots, carrier::SemanticContext, completion, evaluation::IndexData,
    incremental, maintenance,
};
use terrane_format::properties::{PropertyName, RootLayer, Value};
use terrane_format::tree_format::EntryKind;

use crate::guard::{AuthorizedSnapshot, Guard, StagedUpload};
use crate::indexing::LoadedSource;
use crate::repository::PreparedTree;
use crate::store::{Clock, Store, StoreFailure};

use super::{failure, index_failure};

/// Owns one exhaustive canonical reconstruction and its actual immutable binding.
pub(super) struct Candidate {
    /// Identifies the independently authenticated namespace owner.
    pub(super) owner: Digest,
    /// Retains the actual owner-local binding, including its genuine absence.
    pub(super) bound: Option<Digest>,
    /// Owns the independently reconstructed canonical I/P/G closure.
    pub(super) data: IndexData,
    /// Records exhaustive source preparation independently of rebuilding.
    pub(super) preparation: incremental::PreparationWork,
    /// Records full rebuilding work separately from ordinary incremental work.
    pub(super) construction: maintenance::ConstructionWork,
    /// Records complete canonical closure materialization.
    pub(super) export: maintenance::ExportWork,
    /// Names every missing-value descendant occurrence covered by the gap tree.
    pub(super) missing: Vec<Vec<u8>>,
}

/// Reconstructs each applicable owner from its independently selected namespace.
///
/// # Errors
/// Preserves namespace, selected-profile and policy failures; refuses unavailable
/// coverage, unsupported occurrence shapes, invalid inline values and work limits.
pub(super) fn evaluate<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    snapshot: &AuthorizedSnapshot,
    source: &LoadedSource,
    attribute: &str,
) -> Result<(Vec<Candidate>, crate::indexing::Reconstruction), StoreFailure> {
    let minimum = guard.config().min_chunk_size;
    let sources = source.sources().map_err(index_failure)?;
    let profile = crate::guard::history::completion::profile_inputs(
        guard,
        &snapshot.commit,
        &snapshot.interpretation,
    )?;
    let context = SemanticContext::new(
        profile.property_revision,
        profile.attribute_revision,
        profile.tree_revision,
    )
    .map_err(failure)?;
    let arena = maintenance::ByteArena::new(usize::MAX).map_err(failure)?;
    let mut owners = BTreeMap::<Digest, Vec<Vec<u8>>>::new();
    let occurrences = snapshot.evidence.occurrences(minimum)?;
    for occurrence in &occurrences {
        let layers = occurrence
            .layers
            .iter()
            .map(|(properties, overrides)| RootLayer {
                properties,
                overrides,
            })
            .collect::<Vec<_>>();
        let policy = snapshot
            .interpretation
            .resolve(&layers, guard.defaults_for(&snapshot.evidence))?;
        let tree = sources
            .trees
            .get(&occurrence.root)
            .ok_or_else(crate::guard::invalid)?;
        let bindings = bindings(tree.props().unwrap_or_default())?;
        let required = matches!(policy.get(PropertyName::Index), Some(Value::Names(names)) if names.contains(&attribute));
        if !required && bindings.get(attribute).is_none() {
            continue;
        }
        owners
            .entry(occurrence.root)
            .or_default()
            .push(occurrence.path.clone());
    }
    let mut result = Vec::new();
    for (owner, owner_paths) in owners {
        let mut missing = Vec::new();
        for occurrence in &occurrences {
            let included = owner_paths.iter().any(|prefix| {
                prefix == b"/"
                    || occurrence.path == *prefix
                    || occurrence
                        .path
                        .strip_prefix(prefix.as_slice())
                        .is_some_and(|suffix| suffix.starts_with(b"/"))
            });
            if !included {
                continue;
            }
            let tree = sources
                .trees
                .get(&occurrence.root)
                .ok_or_else(crate::guard::invalid)?;
            for item in tree.iter() {
                if matches!(item.entry.kind, EntryKind::File { .. })
                    && !item.entry.attrs.iter().any(|value| value.name == attribute)
                {
                    let mut path = occurrence.path.clone();
                    if path != b"/" {
                        path.push(b'/');
                    }
                    path.extend_from_slice(&item.key);
                    missing.push(path);
                }
            }
        }
        missing.sort();
        missing.dedup();
        let tree = sources
            .trees
            .get(&owner)
            .ok_or_else(crate::guard::invalid)?;
        let bound = bindings(tree.props().unwrap_or_default())?.get(attribute);
        let recipe = IndexEvaluationRecipe::new(owner, attribute).map_err(failure)?;
        let prepared = incremental::PreparedSource::new(&recipe, &sources.trees, minimum, context)
            .map_err(|error| match error {
                terrane_format::indexing::evaluation::Error::Incomplete => {
                    crate::store::StoreFailure::with_source(
                        crate::store::StoreErrorKind::Unsupported,
                        error,
                    )
                }
                other => failure(other),
            })?;
        let (rebuilt, construction) = maintenance::rebuild(
            &recipe, &prepared, &arena, minimum, context,
        )
        .map_err(|error| match error {
            maintenance::Error::Evaluation(
                terrane_format::indexing::evaluation::Error::Incomplete,
            ) => crate::store::StoreFailure::with_source(
                crate::store::StoreErrorKind::Unsupported,
                error,
            ),
            other => failure(other),
        })?;
        let (data, export) = rebuilt.materialize().map_err(failure)?;
        result.push(Candidate {
            owner,
            bound,
            data,
            preparation: prepared.preparation_work(),
            construction,
            export,
            missing,
        });
    }
    if result.is_empty() {
        return Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported));
    }
    Ok((result, sources.work))
}

fn bindings<'a>(
    properties: &[terrane_format::tree_format::Property<'a>],
) -> Result<IndexRoots<'a>, StoreFailure> {
    properties
        .iter()
        .find(|property| property.name == "index-roots")
        .map(|property| IndexRoots::decode_binding(property.value))
        .transpose()
        .map_err(failure)
        .map(Option::unwrap_or_default)
}

/// Replaces selected bindings while preserving the authenticated namespace shape.
///
/// # Errors
/// Rejects unavailable namespace roots, unsupported selected semantics, invalid
/// canonical completion, contradictory replacement graphs and encoding limits.
pub(super) fn corrected<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    snapshot: &AuthorizedSnapshot,
    source: &LoadedSource,
    attribute: &str,
    candidates: &[Candidate],
) -> Result<(PreparedTree, crate::indexing::Reconstruction), StoreFailure> {
    let minimum = guard.config().min_chunk_size;
    let sources = source.sources().map_err(index_failure)?;
    let profile = crate::guard::history::completion::profile_inputs(
        guard,
        &snapshot.commit,
        &snapshot.interpretation,
    )?;
    let context = SemanticContext::new(
        profile.property_revision,
        profile.attribute_revision,
        profile.tree_revision,
    )
    .map_err(failure)?;
    let arena = maintenance::ByteArena::new(usize::MAX).map_err(failure)?;
    let mut graph = sources.trees;
    let mut order = snapshot
        .evidence
        .occurrences(minimum)?
        .into_iter()
        .map(|occurrence| (occurrence.path.len(), occurrence.root))
        .collect::<Vec<_>>();
    order.sort_by(|left, right| right.cmp(left));
    let mut visited = BTreeSet::new();
    let mut replacements = BTreeMap::new();
    let mut nodes = BTreeMap::new();
    for (_, owner) in order {
        if !visited.insert(owner) {
            continue;
        }
        let tree = graph.get(&owner).ok_or_else(crate::guard::invalid)?;
        let changes = tree
            .iter()
            .filter_map(|item| {
                let mut entry = item.entry.clone();
                if let EntryKind::Tree { root, .. } = &mut entry.kind
                    && let Some(replacement) = replacements.get(root)
                    && root != replacement
                {
                    *root = *replacement;
                    Some((item.key.clone(), Some(entry)))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let current = if changes.is_empty() {
            owner
        } else {
            let edited = tree.edit_entries(&changes).map_err(failure)?;
            for node in &edited.emitted {
                nodes.insert(node.identity(), node.encoded().to_vec());
            }
            let root = edited.tree.root_identity();
            graph.insert(root, edited.tree);
            root
        };
        let current =
            if let Some(candidate) = candidates.iter().find(|candidate| candidate.owner == owner) {
                let selections = [completion::Selection {
                    attribute,
                    data: &candidate.data,
                }];
                let completed = completion::complete(
                    current,
                    &graph,
                    &selections,
                    &arena,
                    minimum,
                    context,
                    completion::MemoPolicy::Omit,
                )
                .map_err(failure)?;
                for node in &completed.owner.emitted {
                    nodes.insert(node.identity(), node.encoded().to_vec());
                }
                nodes.extend(
                    candidate
                        .data
                        .nodes
                        .iter()
                        .map(|(identity, bytes)| (*identity, bytes.clone())),
                );
                let root = completed.owner.tree.root_identity();
                graph.insert(root, completed.owner.tree);
                root
            } else {
                current
            };
        replacements.insert(owner, current);
    }
    let root = replacements
        .get(&snapshot.evidence.root)
        .copied()
        .ok_or_else(crate::guard::invalid)?;
    let mut prepared = PreparedTree::from_tree(graph.get(&root).ok_or_else(crate::guard::invalid)?)
        .map_err(failure)?;
    let existing = prepared
        .uploads
        .iter()
        .filter_map(|upload| match upload {
            StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            } => Some(bytes.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    prepared.uploads.extend(
        nodes
            .into_values()
            .filter(|bytes| !existing.contains(bytes))
            .map(|bytes| StagedUpload::Meta {
                kind: IdentityKind::Node,
                bytes,
            }),
    );
    Ok((prepared, sources.work))
}
