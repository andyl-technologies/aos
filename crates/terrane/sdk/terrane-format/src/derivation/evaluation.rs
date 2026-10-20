//! Replays immutable T1 recipes using their owning algebra and index evaluators.
//!
//! Each replay resolves actual immutable operands and freshly binds recorded
//! provenance and ownership configuration. Results own complete canonical Node
//! closures; no entry, domain or temporary decoded-recipe borrow escapes.
//! Successful replay establishes an immutable relationship, never current
//! serving, producer, policy, admission or publication authority.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::algebra::{self, MergePolicy, OperationDomains, Recipe, Roots};
use crate::identity::{Digest, IdentityError, IdentityKind, TERRANE_V1};
use crate::indexing::{self, IndexEvaluationRecipe, carrier::SemanticContext};
use crate::tree_builder::Tree;
use crate::tree_format::{self, Entry, EntryKind, TreeUse};

/// A mandatory recipe, immutable input or checked-evidence failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvaluationError {
    /// Canonical recipe framing is malformed.
    Encoding(crate::cbor::Error),
    /// A retained operation or index specialization is not executable in T1.
    Unsupported(String),
    /// The owning algebra recipe codec rejected the recorded arguments.
    Recipe(algebra::RecipeError),
    /// The closed index recipe codec rejected the recorded arguments.
    IndexRecipe(indexing::Error),
    /// An immutable operand or reached graft is unavailable.
    MissingRoot(Digest),
    /// An operand's actual identity, tree use or chunk geometry differs.
    Input(Digest),
    /// The owning namespace evaluator rejected the operation or evidence.
    Algebra(algebra::Error),
    /// The owning complete index evaluator rejected the operation or context.
    Index(indexing::evaluation::Error),
    /// Domain-separated identity calculation failed.
    Identity(IdentityError),
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => error.fmt(formatter),
            Self::Unsupported(operation) => write!(formatter, "unsupported T1 recipe: {operation}"),
            Self::Recipe(error) => error.fmt(formatter),
            Self::IndexRecipe(error) => error.fmt(formatter),
            Self::MissingRoot(_) => formatter.write_str("missing immutable recipe input"),
            Self::Input(_) => formatter.write_str("immutable recipe input context mismatch"),
            Self::Algebra(error) => error.fmt(formatter),
            Self::Index(error) => error.fmt(formatter),
            Self::Identity(error) => error.fmt(formatter),
        }
    }
}

impl core::error::Error for EvaluationError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Encoding(error) => Some(error),
            Self::Recipe(error) => Some(error),
            Self::IndexRecipe(error) => Some(error),
            Self::Algebra(error) => Some(error),
            Self::Index(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

/// Supplies independently resolved fold preprocessing witnesses.
///
/// The owning binding API replays exclusions and compares the complete filtered
/// operand and recorded configuration. These ordinary witnesses carry no trust.
#[derive(Clone, Copy)]
pub struct FoldReplay<'a> {
    /// Original incoming root named by the genuinely checked signed evaluator.
    pub original: Digest,
    /// Ordered paths restored from the recorded merge base.
    pub excluded: &'a [Vec<u8>],
    /// Independently resolved ownership of the original incoming root, if needed.
    pub domains: Option<&'a OperationDomains>,
}

/// Resolves original occurrences and projected overlay policy independently.
///
/// Implementations select the complete immutable property interpretation,
/// original view defaults, and governing policy outside the recipe and Memo.
/// Source resolution follows the original graft path, including overrides;
/// result resolution applies that view's interpretation to the emitted layers.
/// Returning a policy copies checked context and grants no current authority.
/// Callers retain responsibility for current authorization and must reject
/// unavailable or unvalidated policy evidence on every invocation.
pub trait OverlayReplayContext {
    /// Resolves policy at a root occurrence in an original input view.
    ///
    /// `at` is empty for the view root and names the full graft occurrence
    /// otherwise. Equal target hashes at different paths remain distinct.
    ///
    /// # Errors
    /// Returns the owning algebra error when the original interpretation,
    /// occurrence, governing policy or required evidence cannot be validated.
    ///
    /// # Panics
    /// Implementations may propagate panics from their policy providers.
    fn source_policy(
        &self,
        original_view: &Digest,
        at: &[u8],
    ) -> Result<algebra::OverlayPolicy, algebra::Error>;

    /// Resolves projected root layers under the original top view's context.
    ///
    /// # Errors
    /// Returns the owning algebra error when emitted properties, inheritance
    /// or independently selected interpretation and policy cannot be validated.
    ///
    /// # Panics
    /// Implementations may propagate panics from their policy providers.
    fn result_policy(
        &self,
        original_view: &Digest,
        layers: &[crate::properties::RootLayer<'_>],
    ) -> Result<algebra::OverlayPolicy, algebra::Error>;
}

/// Supplies actual immutable inputs and independently checked execution context.
///
/// Trees are keyed by their actual Node roots. Provenance contexts come from
/// the existing checked-history APIs in `[ours, theirs]` order. Serialized
/// recipe evidence cannot supply either these evaluators or resolved domains.
pub struct EvaluationInputs<'t, 'a> {
    /// Closed graph of canonical namespace roots, including reached grafts.
    pub trees: &'t BTreeMap<Digest, Tree<'a>>,
    /// Independently selected immutable chunk geometry.
    pub minimum: u64,
    /// Checked supported property, attribute and tree semantic revisions.
    pub context: SemanticContext,
    /// Independently resolved ownership matching the recorded domain registry.
    pub domains: Option<&'t OperationDomains>,
    /// Genuine checked-history evaluators in merge-side order.
    pub provenance: &'t [crate::provenance::TrustContext],
    /// Optional independently supplied fold preprocessing witnesses.
    pub fold: Option<FoldReplay<'t>>,
    /// Independent occurrence and result policy required by grafted overlays.
    /// Flat legacy overlays preserve their existing context and exact identities.
    pub overlay: Option<&'t dyn OverlayReplayContext>,
}

/// Reports selected counters exposed by the owning algorithms.
///
/// Index verification retains its separate physical reconstruction traces;
/// overlay reports input graph admission only. Recipe hashing, fold rebinding,
/// encoding, closure traversal and advisory record/map cloning are not
/// comprehensively measured here. These reports establish no total replay,
/// copy-work or incremental complexity bound.
#[derive(Clone, Debug)]
pub enum EvaluationWork {
    /// Complete index construction and independent exhaustive verification.
    Index {
        /// Construction event counts from the existing index evaluator.
        construction: indexing::evaluation::Work,
        /// Independent relationships and separate physical reconstruction work.
        verification: indexing::evaluation::Verification,
    },
    /// Persistent graft mutation, including hard-link preparation and admission.
    Graft {
        /// Persistent mutation events reported by the owning graft implementation.
        mutation: crate::tree_builder::Work,
        /// Hard-link member-index reads during preparation.
        preparation_reads: usize,
        /// Root-graph admission events reported independently of mutation.
        admission: algebra::GraphWork,
    },
    /// Input graph admission during ordered overlay materialization.
    Overlay {
        /// Complete source graph admission events.
        admission: algebra::GraphWork,
    },
    /// Existing recursive merge mutation and input graph admission.
    Merge {
        /// Persistent mutation events reported by the owning merge implementation.
        mutation: crate::tree_builder::Work,
        /// Root-graph admission events reported independently of mutation.
        admission: algebra::GraphWork,
        /// Merkle nodes expanded by the owning merge implementation.
        expanded_nodes: usize,
        /// Unchanged subtrees reused by the owning merge implementation.
        reused_subtrees: usize,
    },
}

/// Owns one replay result and every Node needed to reconstruct that result.
///
/// Namespace closures include physical nodes and reachable graft/conflict roots;
/// index closures include primary, gap and hierarchical occurrence carriers.
/// Referenced file Chunks/Manifests remain content references, not Node bytes.
#[derive(Clone, Debug)]
pub struct Evaluation {
    /// Recipe lookup key, distinct from the immutable Memo record identity.
    pub recipe_hash: Digest,
    /// Actual canonical resulting Node root.
    pub root: Digest,
    /// Complete canonical resulting Node closure indexed by actual identities.
    pub nodes: BTreeMap<Digest, Vec<u8>>,
    /// Selected owning counters with the scope described by [`EvaluationWork`].
    pub work: EvaluationWork,
    /// Distinct namespace roots traversed while copying the output closure.
    pub closure_roots: usize,
    /// Unique final retained Node bytes in the owned output closure.
    pub closure_bytes: usize,
}

struct Resolved<'t, 'a>(&'t EvaluationInputs<'t, 'a>);

impl<'a> Roots<'a> for Resolved<'_, 'a> {
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>> {
        self.0.trees.get(identity).filter(|tree| {
            tree.min_chunk_size() == self.0.minimum && tree.usage() != TreeUse::Index
        })
    }
}

fn tree<'t, 'a>(
    inputs: &'t EvaluationInputs<'_, 'a>,
    root: Digest,
) -> Result<&'t Tree<'a>, EvaluationError> {
    let tree = inputs
        .trees
        .get(&root)
        .ok_or(EvaluationError::MissingRoot(root))?;
    if tree.root_identity() != root
        || tree.min_chunk_size() != inputs.minimum
        || tree.usage() == TreeUse::Index
    {
        return Err(EvaluationError::Input(root));
    }
    Ok(tree)
}

fn operation(encoded: &[u8]) -> Result<&str, EvaluationError> {
    let mut decoder = crate::cbor::Decoder::new(encoded);
    let fields = decoder.map(3).map_err(EvaluationError::Encoding)?;
    if fields < 2 || decoder.uint().map_err(EvaluationError::Encoding)? != 1 {
        return Err(EvaluationError::Encoding(crate::cbor::Error::NonCanonical));
    }
    decoder
        .text(encoded.len())
        .map_err(EvaluationError::Encoding)
}

/// Re-evaluates a decoded T1 recipe with fresh immutable and evidence checks.
///
/// Retained historical index recipes and later algebra/realization operations
/// are rejected as unsupported executable inputs without changing data validity.
///
/// # Errors
/// Rejects malformed or unsupported recipes, missing/mismatched operands,
/// incomplete graphs, invalid contexts, unavailable or different checked
/// provenance/domain evidence, and errors from the owning semantic evaluators.
///
/// # Panics
/// Propagates panics from the supplied overlay policy context.
pub fn evaluate(
    encoded: &[u8],
    inputs: &EvaluationInputs<'_, '_>,
) -> Result<Evaluation, EvaluationError> {
    let name = operation(encoded)?;
    let recipe_hash = TERRANE_V1
        .calculate(IdentityKind::Memo, encoded)
        .and_then(|identity| identity.terrane_v1_digest())
        .map_err(EvaluationError::Identity)?;

    if name == "index" {
        let recipe = IndexEvaluationRecipe::decode(encoded).map_err(|error| {
            // Historical retained index recipes remain ordinary valid data.
            if error == indexing::Error::Schema {
                EvaluationError::Unsupported(String::from("index specialization"))
            } else {
                EvaluationError::IndexRecipe(error)
            }
        })?;
        let data =
            indexing::evaluation::construct(&recipe, inputs.trees, inputs.minimum, inputs.context)
                .map_err(EvaluationError::Index)?;
        let verification = indexing::evaluation::verify(
            &recipe,
            inputs.trees,
            inputs.minimum,
            inputs.context,
            &data,
        )
        .map_err(EvaluationError::Index)?;
        let closure_bytes = data.nodes.values().map(Vec::len).sum();
        return Ok(Evaluation {
            recipe_hash,
            root: data.root,
            nodes: data.nodes,
            work: EvaluationWork::Index {
                construction: data.work,
                verification,
            },
            closure_roots: 0,
            closure_bytes,
        });
    }
    if !matches!(name, "graft" | "overlay" | "merge") {
        return Err(EvaluationError::Unsupported(String::from(name)));
    }

    let mut owned = Recipe::decode(encoded).map_err(EvaluationError::Recipe)?;
    let recorded_domains = match owned.as_recipe() {
        Recipe::OverlayWithDomains { .. } => true,
        Recipe::Graft { domains, .. } | Recipe::Merge { domains, .. } => domains.is_some(),
        Recipe::Overlay(_) => false,
    };
    if recorded_domains {
        owned = owned
            .bind_domains(
                inputs
                    .domains
                    .ok_or(EvaluationError::Recipe(algebra::RecipeError::Schema))?,
            )
            .map_err(EvaluationError::Recipe)?;
    }
    if let Recipe::Merge {
        base,
        theirs,
        policies,
        ..
    } = owned.as_recipe()
        && policies.iter().any(|policy| {
            matches!(
                policy,
                MergePolicy::PreferTrusted | MergePolicy::PreferNewer
            )
        })
    {
        owned = if let Some(fold) = inputs.fold {
            let base = tree(inputs, base)?;
            let original = tree(inputs, fold.original)?;
            let filtered = tree(inputs, theirs)?;
            match fold.domains {
                Some(domains) => owned.bind_fold_verified_with_domains(
                    inputs.provenance.to_vec(),
                    base,
                    original,
                    filtered,
                    fold.excluded,
                    domains,
                ),
                None => owned.bind_fold_verified(
                    inputs.provenance.to_vec(),
                    base,
                    original,
                    filtered,
                    fold.excluded,
                ),
            }
        } else {
            owned.bind_verified(inputs.provenance.to_vec())
        }
        .map_err(EvaluationError::Recipe)?;
    }
    // Binding may authenticate evidence but must never alter recorded semantics.
    if owned.as_recipe().encode() != encoded {
        return Err(EvaluationError::Recipe(algebra::RecipeError::Schema));
    }

    let roots = Resolved(inputs);
    let mut graph = algebra::RootGraph::new();
    let (result, derived, work) = match owned.as_recipe() {
        Recipe::Graft {
            parent,
            target,
            at,
            entry,
            replace,
            domains,
        } => {
            let parent = tree(inputs, parent)?;
            tree(inputs, target)?;
            let entry = tree_format::decode_entry_bytes(entry, inputs.minimum)
                .map_err(|error| EvaluationError::Algebra(algebra::Error::Key(error)))?;
            let prepared = match domains {
                Some(domains) => {
                    algebra::prepare_graft_with_domains(parent, at, &entry, replace, domains)
                }
                None => algebra::prepare_graft(parent, at, &entry, replace),
            }
            .map_err(EvaluationError::Algebra)?;
            let result = prepared
                .materialize(parent, &roots, &mut graph)
                .map_err(EvaluationError::Algebra)?;
            let work = EvaluationWork::Graft {
                mutation: result.mutation,
                preparation_reads: prepared.hardlink_index_reads(),
                admission: result.admission,
            };
            // Prepared hard-link bytes are borrowed; copy the complete closure
            // before preparation and decoded-entry owners leave this scope.
            return namespace_output(recipe_hash, &result.tree, &[], inputs, work);
        }
        Recipe::Overlay(identities)
        | Recipe::OverlayWithDomains {
            roots: identities, ..
        } => {
            let domains = if let Recipe::OverlayWithDomains { domains, .. } = owned.as_recipe() {
                Some(domains)
            } else {
                None
            };
            let layers = identities
                .iter()
                .map(|root| tree(inputs, *root))
                .collect::<Result<Vec<_>, _>>()?;
            let mut admission = algebra::GraphWork::default();
            for layer in &layers {
                let work = graph
                    .admit(layer, &roots)
                    .map_err(EvaluationError::Algebra)?;
                admission.roots += work.roots;
                admission.nodes += work.nodes;
            }
            let overlay = algebra::Overlay::new(&layers);
            if layers.iter().any(|layer| {
                layer
                    .iter()
                    .any(|item| matches!(item.entry.kind, EntryKind::Tree { .. }))
            }) {
                let context = inputs
                    .overlay
                    .ok_or(EvaluationError::Algebra(algebra::Error::Boundary))?;
                let prepared = overlay
                    .prepare_with_roots(
                        &roots,
                        domains,
                        |view, at| context.source_policy(view, at),
                        |view, layers| context.result_policy(view, layers),
                    )
                    .map_err(EvaluationError::Algebra)?;
                let result = prepared.materialize().map_err(EvaluationError::Algebra)?;
                if result.recipe != encoded {
                    return Err(EvaluationError::Recipe(algebra::RecipeError::Schema));
                }

                // Preparation owns projected properties and synthesized targets.
                // Copy every reachable child before that owner leaves this scope.
                return namespace_output(
                    recipe_hash,
                    &result.tree,
                    &result.grafts,
                    inputs,
                    EvaluationWork::Overlay { admission },
                );
            }
            let result = match domains {
                Some(domains) => overlay.materialize_with_domains(domains),
                None => overlay.materialize(),
            }
            .map_err(EvaluationError::Algebra)?;
            (result, Vec::new(), EvaluationWork::Overlay { admission })
        }
        Recipe::Merge {
            base,
            ours,
            theirs,
            policies,
            trust,
            domains,
        } => {
            let base = tree(inputs, base)?;
            let ours = tree(inputs, ours)?;
            let theirs = tree(inputs, theirs)?;
            let result = match domains {
                Some(domains) => algebra::merge_certified_with_domains(
                    base, ours, theirs, policies, trust, &roots, &mut graph, domains,
                ),
                None => algebra::merge_certified(
                    base, ours, theirs, policies, trust, &roots, &mut graph,
                ),
            }
            .map_err(EvaluationError::Algebra)?;
            let work = EvaluationWork::Merge {
                mutation: result.mutation_work,
                admission: result.admission_work,
                expanded_nodes: result.expanded_nodes,
                reused_subtrees: result.reused_subtrees,
            };
            (result.tree, result.derived_roots, work)
        }
    };
    namespace_output(recipe_hash, &result, &derived, inputs, work)
}

fn entry_roots(entry: &Entry<'_>, roots: &mut Vec<Digest>) {
    // Full conflict bases are byte-bounded, independently of graft depth.
    // Keep their traversal on the heap, matching the owning entry parser.
    let mut entries = alloc::vec![entry];
    while let Some(entry) = entries.pop() {
        match &entry.kind {
            EntryKind::Tree { root, .. } => roots.push(*root),
            EntryKind::Conflict { candidates, base } => {
                if let Some(Some(base)) = base {
                    entries.push(base);
                }
                entries.extend(candidates.iter().rev());
            }
            _ => {}
        }
    }
}

fn namespace_output(
    recipe_hash: Digest,
    result: &Tree<'_>,
    derived: &[Tree<'_>],
    inputs: &EvaluationInputs<'_, '_>,
    work: EvaluationWork,
) -> Result<Evaluation, EvaluationError> {
    let mut nodes = BTreeMap::new();
    let mut visited = BTreeSet::new();
    let mut pending = alloc::vec![result.root_identity()];
    while let Some(root) = pending.pop() {
        if !visited.insert(root) {
            continue;
        }
        let current = if root == result.root_identity() {
            result
        } else if let Some(tree) = derived.iter().find(|tree| tree.root_identity() == root) {
            tree
        } else {
            tree(inputs, root)?
        };
        for node in current.nodes() {
            nodes.insert(node.identity(), node.encoded().to_vec());
        }
        for item in current.iter() {
            entry_roots(&item.entry, &mut pending);
        }
    }
    let closure_bytes = nodes.values().map(Vec::len).sum();
    Ok(Evaluation {
        recipe_hash,
        root: result.root_identity(),
        nodes,
        work,
        closure_roots: visited.len(),
        closure_bytes,
    })
}
