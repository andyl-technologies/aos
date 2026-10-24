//! Captures complete Guard history and canonical owned occurrence data.

use super::{CollectionError, Expansion, PARENT, Pending, ProofContext, VisitMode, WITNESS};
use crate::guard::{
    CollectionOccurrence, CompletedCollectionHistory, ConsumedResolver, Guard, HistoryObservation,
    SelectedReadInterpretation, VerifiedCollectionTree,
};
use crate::indexing::SemanticRevisions;
use crate::store::{Clock, CorruptSubject, InvalidReason, Store, StoreErrorKind, StoreFailure};
use terrane_format::derived::{AttributeName, AttributeValue};
use terrane_format::identity::{Digest, Identity};
use terrane_format::properties::RootLayer;
use terrane_format::provenance::{EntryLocation, VerifiedDisclosureBatch};
use terrane_format::tree_format::{ContentRef, EntryKind};

/// Owns paths and metadata so no Rc-backed Tree crosses a later await.
#[derive(Clone)]
pub(super) struct Occurrence {
    /// Exact verified destination/root/absolute occurrence.
    pub(super) context: ProofContext,
    /// Effective domain under this view's retained interpretation.
    pub(super) domain: String,
    /// Selected property and explicitly implemented native codec revisions.
    pub(super) revisions: SemanticRevisions,
    /// Explicit namespace use established by the owning completed signed history.
    pub(super) usage: terrane_format::tree_format::TreeUse,
    /// Physical namespace nodes and their root placements after metadata preparation.
    pub(super) nodes: Vec<(Digest, bool)>,
    /// Exact local attribute-to-index bindings after metadata preparation.
    pub(super) bindings: Vec<(String, Digest)>,
    /// Complete file and conflict-candidate edges after metadata preparation.
    pub(super) files: Vec<File>,
}

/// Owns a file edge and only format-declared inline dictionary references.
#[derive(Clone)]
pub(super) struct File {
    /// Actual typed inline Chunk or Manifest edge.
    pub(super) content: ContentRef,
    /// Registered zstd-dictionary digest values; arbitrary hashes are inert.
    pub(super) dictionaries: Vec<Digest>,
    /// Complete canonical root-relative file location.
    pub(super) location: EntryLocation,
}

/// Keeps the opaque verifier result through every collection-only classification.
pub(super) struct View<'history> {
    /// Opaque completed Guard evidence, retained without authority conversion.
    verified: ViewEvidence<'history>,
    /// Every actual occurrence resolved by the Guard's selected interpretation.
    pub(super) occurrences: Vec<Occurrence>,
    /// Closed dependency plan copied only from completed Guard evidence.
    pub(super) edges: Edges,
}

/// Keeps independently rooted evidence borrowed and fresh dependency evidence owned.
enum ViewEvidence<'history> {
    Retained(&'history VerifiedCollectionTree),
    Fresh(Box<VerifiedCollectionTree>),
}

impl ViewEvidence<'_> {
    fn get(&self) -> &VerifiedCollectionTree {
        match self {
            Self::Retained(verified) => verified,
            Self::Fresh(verified) => verified,
        }
    }
}

impl View<'_> {
    /// Borrows the completed actual verifier result without relabeling its scope.
    pub(super) fn verified(&self) -> &VerifiedCollectionTree {
        self.verified.get()
    }
}

/// Owns dependency positions derived solely from completed signed histories.
pub(super) struct Edges {
    parents: Vec<(Digest, ProofContext)>,
    witnesses: Vec<(Digest, ProofContext)>,
    /// Final batch whose exact occurrence audit cuts completed.
    pub(super) disclosure: Option<VerifiedDisclosureBatch>,
}

/// Loads one view and resolves every actual occurrence under its own interpretation.
///
/// # Errors
/// Preserves complete Guard refusals and rejects incomplete dependencies or
/// invalid canonical occurrence/path evidence before scheduling anything.
pub(super) async fn acquire_scoped<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    commit: Digest,
    layer_root: Option<Digest>,
) -> Result<View<'static>, CollectionError> {
    let observation = match layer_root {
        Some(root) => observation.overlay_layer(commit, root),
        None => observation,
    };
    let verified = guard
        .verified_collection_tree_observed(commit, observation.tracked(consumed))
        .await?;
    prepare(guard, ViewEvidence::Fresh(Box::new(verified)))
}

/// Resolves occurrences from a genuinely qualified root's retained own-scope history.
///
/// # Errors
/// Rejects incomplete dependencies, inconsistent interpretation or canonical positions;
/// the caller first checks the same held root carrier, Session and resolver.
pub(super) fn retained_scoped<'history, S: Store, C: Clock>(
    guard: &Guard<S, C>,
    verified: &'history VerifiedCollectionTree,
) -> Result<View<'history>, CollectionError> {
    prepare(guard, ViewEvidence::Retained(verified))
}

/// Loads complete producer metadata for side-record attribution.
///
/// # Errors
/// Preserves scoped history verification and own metadata decoding failures.
pub(super) async fn acquire<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    consumed: &ConsumedResolver,
    observation: HistoryObservation<'_>,
    commit: Digest,
    layer_root: Option<Digest>,
) -> Result<View<'static>, CollectionError> {
    let view = acquire_scoped(guard, consumed, observation, commit, layer_root).await?;
    prepare_all_metadata(guard, view)
}

/// Prepares complete independently rooted producer metadata for attribution.
///
/// # Errors
/// Preserves scoped history validation and own metadata decoding failures.
pub(super) fn retained<'history, S: Store, C: Clock>(
    guard: &Guard<S, C>,
    verified: &'history VerifiedCollectionTree,
) -> Result<View<'history>, CollectionError> {
    prepare_all_metadata(guard, retained_scoped(guard, verified)?)
}

fn prepare_all_metadata<'history, S: Store, C: Clock>(
    guard: &Guard<S, C>,
    mut view: View<'history>,
) -> Result<View<'history>, CollectionError> {
    for occurrence in &mut view.occurrences {
        prepare_metadata(guard, view.verified.get(), occurrence)?;
    }
    Ok(view)
}

/// Resolves authenticated scope before enumerating any own occurrence metadata.
fn prepare<'history, S: Store, C: Clock>(
    guard: &Guard<S, C>,
    verified: ViewEvidence<'history>,
) -> Result<View<'history>, CollectionError> {
    let evidence = verified.get();
    let commit = evidence.tree().commit.identity();
    let completed: &CompletedCollectionHistory = evidence.completed();
    let dependencies = completed
        .dependencies(commit)
        .ok_or_else(|| missing(MissingProof::CompletedDependencies(commit)))?;
    let edges = Edges {
        parents: dependencies
            .parents()
            .iter()
            .map(|hash| dependency_position(evidence, *hash).map(|context| (*hash, context)))
            .collect::<Result<Vec<_>, _>>()?,
        witnesses: dependencies
            .witnesses()
            .iter()
            .map(|hash| dependency_position(evidence, *hash).map(|context| (*hash, context)))
            .collect::<Result<Vec<_>, _>>()?,
        disclosure: dependencies.disclosure().cloned(),
    };
    let selected: Vec<CollectionOccurrence> = guard.collection_occurrences(evidence)?;
    let mut occurrences = Vec::with_capacity(selected.len());
    for selected in selected {
        let root = selected.root();
        let context = ProofContext::new(commit, root, selected.path().to_vec())?;
        let property = match selected.interpretation() {
            SelectedReadInterpretation::Legacy => 3,
            SelectedReadInterpretation::Recorded(entry) => entry.revision(),
        };
        // Attribute 2 and tree 1 are the native executable carrier profile.
        // The property interpretation is the one selected for this exact view.
        let revisions = SemanticRevisions {
            property,
            attribute: 2,
            tree: 1,
        };
        occurrences.push(Occurrence {
            context,
            domain: selected.domain().to_owned(),
            revisions,
            usage: evidence.tree().evidence.root_usage(root),
            nodes: Vec::new(),
            bindings: Vec::new(),
            files: Vec::new(),
        });
    }
    occurrences.sort_by(|left, right| left.context.cmp(&right.context));
    if occurrences.is_empty()
        || occurrences
            .windows(2)
            .any(|pair| pair[0].context == pair[1].context)
    {
        return Err(invalid(MissingProof::CanonicalOccurrence).into());
    }
    Ok(View {
        verified,
        occurrences,
        edges,
    })
}

/// Enumerates own metadata only after exact occurrence completion is checked.
///
/// # Errors
/// Preserves tree decoding failures and rejects malformed local index bindings
/// or declared dictionary values in the completed owning history.
pub(super) fn prepare_metadata<S: Store, C: Clock>(
    guard: &Guard<S, C>,
    verified: &VerifiedCollectionTree,
    occurrence: &mut Occurrence,
) -> Result<(), CollectionError> {
    let evidence = verified;
    let commit = evidence.tree().commit.identity();
    let root = *occurrence.context.root();
    let tree = evidence
        .tree()
        .evidence
        .tree(root, guard.config().min_chunk_size)?;
    let nodes = tree
        .nodes()
        .map(|node| (node.identity(), node.identity() == root))
        .collect();
    let path = evidence.tree().evidence.policy_path(
        occurrence.context.absolute_path(),
        guard.config().min_chunk_size,
    )?;
    let layers = path
        .iter()
        .map(|(properties, overrides)| RootLayer {
            properties,
            overrides,
        })
        .collect::<Vec<_>>();
    let interpretation = evidence
        .completed()
        .history()
        .property_selection(commit)
        .map_err(invalid)?;
    let effective = interpretation
        .resolve(&layers, guard.defaults_for(&evidence.tree().evidence))
        .map_err(invalid)?;
    // Owner-local bindings exist only when the independently selected revision
    // gives them behavior. Canonical preserved bytes do not become pointers.
    let bindings = effective
        .active_index_roots()
        .map(|roots| {
            roots
                .as_bindings()
                .iter()
                .map(|binding| (binding.attribute.to_owned(), binding.node))
                .collect()
        })
        .unwrap_or_default();
    let mut files = Vec::new();
    for item in tree.iter() {
        let mut entries = vec![&item.entry];
        while let Some(entry) = entries.pop() {
            match &entry.kind {
                EntryKind::File { content, .. } => files.push(File {
                    content: *content,
                    dictionaries: entry
                        .attrs
                        .iter()
                        .filter(|attribute| {
                            attribute.name == AttributeName::ZstdDictionary.as_str()
                        })
                        .map(|attribute| {
                            match AttributeValue::decode(
                                AttributeName::ZstdDictionary,
                                attribute.value,
                            ) {
                                Ok(AttributeValue::ZstdDictionary(hash)) => Ok(hash),
                                Ok(_) => {
                                    Err(invalid(terrane_format::derived::Error::InvalidProvenance))
                                }
                                Err(source) => Err(invalid(source)),
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    location: EntryLocation {
                        commit,
                        root,
                        path: item.key.clone(),
                    },
                }),
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
    occurrence.nodes = nodes;
    occurrence.bindings = bindings;
    occurrence.files = files;
    Ok(())
}

/// Selects an actual canonical root and all complete graft descendants.
///
/// # Errors
/// Rejects a forged destination, physical root or absolute occurrence path.
pub(super) fn select<'a>(
    occurrences: &'a [Occurrence],
    requested: Option<&ProofContext>,
) -> Result<Vec<&'a Occurrence>, StoreFailure> {
    let Some(requested) = requested else {
        return Ok(occurrences.iter().collect());
    };
    if !occurrences
        .iter()
        .any(|occurrence| occurrence.context == *requested)
    {
        return Err(invalid(MissingProof::CanonicalOccurrence));
    }
    Ok(occurrences
        .iter()
        .filter(|occurrence| {
            occurrence.context.destination() == requested.destination()
                && below(
                    requested.absolute_path(),
                    occurrence.context.absolute_path(),
                )
        })
        .collect())
}

fn below(parent: &[u8], child: &[u8]) -> bool {
    parent == b"/"
        || parent == child
        || child
            .strip_prefix(parent)
            .is_some_and(|rest| rest.starts_with(b"/"))
}

/// Schedules only completed dependency positions, retaining each view's own batch.
pub(super) fn schedule(
    edges: &Edges,
    pending: &Pending,
    mode: VisitMode,
    expansion: &mut Expansion,
) {
    expansion
        .pending
        .extend(edges.parents.iter().map(|(hash, context)| Pending {
            kind: 3,
            hash: *hash,
            parent_cutoff: pending.parent_cutoff,
            flags: if mode == VisitMode::Witness {
                WITNESS
            } else {
                PARENT
            },
            // A separately reached commit verifies its own complete canonical view.
            // Never label it with this destination's disclosure batch position.
            proof_context: Some(context.clone()),
        }));
    for (witness, context) in &edges.witnesses {
        expansion.witness(*witness, context.clone());
    }
}

fn dependency_position(
    verified: &VerifiedCollectionTree,
    identity: Digest,
) -> Result<ProofContext, CollectionError> {
    let signed = verified
        .completed()
        .history()
        .commit(&identity)
        .ok_or_else(|| missing(MissingProof::CompletedDependencies(identity)))?;
    // The signed dependency completed its own original root scope. Its root
    // occurrence is canonical `/`; expansion independently rechecks that exact
    // occurrence and its own final batch before using any persisted claim.
    Ok(ProofContext::new(
        identity,
        signed.commit().tree,
        b"/".to_vec(),
    )?)
}

/// Describes absent scoped proof without relabeling raw catalog data as authority.
#[derive(Debug)]
pub(super) enum MissingProof {
    /// A dependency was not present in the completed opaque history.
    CompletedDependencies(Digest),
    /// A requested proof position has no actual canonical occurrence.
    CanonicalOccurrence,
    /// A catalog-only claim lacks an independently completed producer occurrence.
    AttributeProducerOccurrence {
        /// Exact inspected Attribute identity.
        record: Digest,
        /// Untrusted claimed producer, which has not been probed on this edge.
        producer: Digest,
    },
    /// A declared object edge lacks independent proof for a claimed audit producer.
    AttributeProducerDeclaredEdge {
        /// Exact inspected Attribute identity.
        record: Digest,
        /// Actual manifest member or dictionary object, independently encountered.
        object: Digest,
        /// Untrusted claimed producer, which has not been probed on this edge.
        producer: Digest,
        /// Actual consuming occurrence whose completed batch names that audit source.
        context: ProofContext,
    },
}

impl std::fmt::Display for MissingProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CompletedDependencies(commit) => write!(
                formatter,
                "completed collection dependencies absent for {commit:02x?}"
            ),
            Self::CanonicalOccurrence => {
                formatter.write_str("canonical collection occurrence absent")
            }
            Self::AttributeProducerOccurrence { record, producer } => write!(
                formatter,
                "independent attribute producer occurrence proof absent for record {record:02x?}, producer {producer:02x?}"
            ),
            Self::AttributeProducerDeclaredEdge {
                record,
                object,
                producer,
                context,
            } => write!(
                formatter,
                "independent declared-object producer proof absent for record {record:02x?}, object {object:02x?}, producer {producer:02x?}, occurrence {context:?}"
            ),
        }
    }
}

impl std::error::Error for MissingProof {}

/// Preserves a typed incomplete-proof refusal and its original subject.
pub(super) fn missing(source: MissingProof) -> StoreFailure {
    StoreFailure::with_source(StoreErrorKind::Unavailable { retry_after: None }, source)
}

/// Preserves an ordinary malformed-input cause without changing denial semantics.
pub(super) fn invalid(source: impl std::error::Error + Send + Sync + 'static) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Invalid(InvalidReason::MalformedRequest),
        source,
    )
}

/// Preserves the independently requested identity and original verifier cause.
pub(super) fn corrupt(
    identity: Identity,
    source: impl std::error::Error + Send + Sync + 'static,
) -> StoreFailure {
    StoreFailure::with_source(
        StoreErrorKind::Corrupt(CorruptSubject::Identity(identity)),
        source,
    )
}
