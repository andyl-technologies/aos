//! Completes selected ordinary immutable owner bindings before detached associations.
//!
//! Every selected exact index closure is independently checked against candidate
//! entries, then bound in one persistent owner mutation. Recipes and optional
//! common Memos name that final owner. Reports describe ordinary immutable data;
//! missing values remain gaps, and unselected bindings are preserved, not verified.
//! Current policy, producer evidence, authority and publication are separate.
//!
//! ```text
//! candidate entries -> I/P/G -> completed owner R -> Q(R,A)/q -> optional Memo(q,I)
//! ```

mod bindings;

#[cfg(test)]
mod model;

#[cfg(test)]
mod tests;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::fmt;

use super::{
    IndexEvaluationRecipe, carrier::SemanticContext, evaluation, incremental, lookup, maintenance,
};
use crate::{
    derivation::Memo,
    identity::{Digest, IdentityError, IdentityKind, TERRANE_V1},
    tree_builder::{Mutation, Tree},
};

/// Selects one registered attribute and its untrusted exact index closure.
#[derive(Clone, Copy, Debug)]
pub struct Selection<'input> {
    /// Registered value attribute, without implied current requirements.
    pub attribute: &'input str,
    /// Exact primary, occurrence and gap Node closure to check independently.
    pub data: &'input evaluation::IndexData,
}

/// Selects whether completion exports optional common Memo data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoPolicy {
    /// Exports only the detached registered recipe association.
    Omit,
    /// Also exports the unchanged common Memo form and its record identity.
    Include,
}

/// Owns optional common Memo bytes, distinct from the recipe lookup key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoAssociation {
    /// Existing common Memo data claim, without authority.
    pub memo: Memo,
    /// Canonical encoded Memo bytes.
    pub bytes: Vec<u8>,
    /// Immutable identity of the encoded Memo record.
    pub identity: Digest,
}

/// Owns a checked selected immutable association for the final owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Association {
    /// Registered attribute name, owned independently of selection inputs.
    pub attribute: String,
    /// Independently checked index result I, never the owner R.
    pub index: Digest,
    /// Canonical registered recipe Q naming the final owner.
    pub recipe_bytes: Vec<u8>,
    /// Existing Memo-domain recipe lookup key q.
    pub recipe_hash: Digest,
    /// Optional common Memo data, formed only after owner binding.
    pub memo: Option<MemoAssociation>,
}

/// Separates full source checks, verification and loading for one selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checks {
    /// Reachable source checks before mutation, including structural wrappers.
    pub source: incremental::PreparationWork,
    /// Independent exact closure verification against the candidate owner.
    pub before: evaluation::Verification,
    /// Actual final-owner binding verification and auxiliary loading.
    pub after: lookup::Preparation,
}

/// Counts completion operations separately from incremental discovery/update work.
///
/// These are scoped byte/handle/operation counts, not total CPU, allocation or
/// DRV-29 incremental bounds. Root mutation retains the editor's own full work.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Work {
    /// Existing owner wrapper bytes decoded during merging, excluding source checks.
    pub binding_bytes_decoded: usize,
    /// Canonical value-map bytes encoded for validation and wrapping.
    pub binding_value_bytes_encoded: usize,
    /// Canonical wrapper bytes encoded, including the codec's second value encoding.
    pub binding_bytes_encoded: usize,
    /// New stable property payload bytes copied into the caller arena.
    pub arena_bytes_copied: usize,
    /// Full supplied graph Tree handles cloned, including unrelated supplied roots.
    pub graph_handles_copied: usize,
    /// Completed owner handles cloned for temporary final graph insertion.
    pub owner_handles_copied: usize,
    /// Actual emitted root Node bytes, including all entries and properties.
    pub owner_bytes_emitted: usize,
    /// Actual emitted Node identity preimages including domain and NUL.
    pub owner_bytes_hashed: usize,
    /// Attribute name bytes copied into owned association reports.
    pub attribute_bytes_copied: usize,
    /// Registered recipe bytes encoded once per selection.
    pub recipe_bytes_encoded: usize,
    /// Recipe lookup identity preimage bytes including Memo domain and NUL.
    pub recipe_bytes_hashed: usize,
    /// Optional common Memo bytes encoded once per selection.
    pub memo_bytes_encoded: usize,
    /// Optional Memo record identity preimage bytes including domain and NUL.
    pub memo_bytes_hashed: usize,
    /// Full independently measured checks in canonical attribute-key order.
    pub checks: Vec<Checks>,
}

/// Owns the persistent completed owner and detached selected associations.
#[derive(Clone, Debug)]
pub struct Completion<'value> {
    /// Root-property mutation sharing unchanged physical descendants with S.
    pub owner: Mutation<'value>,
    /// Selected associations in canonical encoded attribute-key order.
    pub associations: Vec<Association>,
    /// Full completion work, independent of existing incremental counters.
    pub work: Work,
}

/// Refuses invalid selections, unsupported sources and divergent exact closures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Empty selection batches have no completion contract.
    EmptySelection,
    /// An attribute was selected more than once.
    DuplicateSelection,
    /// A recipe name or owner binding failed its existing codec contract.
    Binding(super::Error),
    /// Reachable source validation failed before any mutation.
    Source(evaluation::Error),
    /// An exact selected index closure failed independent verification.
    Index(evaluation::Error),
    /// The persistent owner property mutation failed physical validation.
    Owner(crate::tree_format::Error),
    /// Stable property storage refused allocation or its payload budget.
    Arena(maintenance::Error),
    /// Final actual binding verification or auxiliary loading failed.
    FinalBinding(evaluation::Error),
    /// A registered identity calculation failed.
    Identity(IdentityError),
    /// A supplied key already names incompatible completed-owner bytes/context.
    GraphCollision,
    /// A completion count overflowed its addressable operation range.
    Limit,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySelection => formatter.write_str("empty owner completion selection"),
            Self::DuplicateSelection => formatter.write_str("duplicate owner completion selection"),
            Self::Binding(error) => write!(formatter, "owner completion binding: {error}"),
            Self::Source(error) => write!(formatter, "owner completion source: {error}"),
            Self::Index(error) => write!(formatter, "owner completion index: {error}"),
            Self::Owner(error) => write!(formatter, "owner completion mutation: {error}"),
            Self::Arena(error) => write!(formatter, "owner completion storage: {error}"),
            Self::FinalBinding(error) => write!(formatter, "completed owner verification: {error}"),
            Self::Identity(error) => write!(formatter, "owner completion identity: {error}"),
            Self::GraphCollision => formatter.write_str("conflicting completed owner graph entry"),
            Self::Limit => formatter.write_str("owner completion counter overflow"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Binding(error) => Some(error),
            Self::Source(error) | Self::Index(error) | Self::FinalBinding(error) => Some(error),
            Self::Owner(error) => Some(error),
            Self::Arena(error) => Some(error),
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

fn add(counter: &mut usize, amount: usize) -> Result<(), Error> {
    *counter = counter.checked_add(amount).ok_or(Error::Limit)?;
    Ok(())
}

fn identity(bytes: &[u8]) -> Result<Digest, Error> {
    TERRANE_V1
        .calculate(IdentityKind::Memo, bytes)
        .and_then(|identity| identity.terrane_v1_digest())
        .map_err(Error::Identity)
}

/// Completes one immutable owner with a nonempty batch of checked selected indexes.
///
/// Candidate S, graph and index data remain immutable. The arena is monotone:
/// successful property copies need not roll back if a later phase refuses.
/// Existing maintenance snapshots remain bound to their original source; later
/// re-preparation for R is a separate operation. Equivalent source namespaces
/// may share index bytes because the result encodes no owner back-reference.
///
/// # Errors
/// Rejects empty/duplicate/unregistered selections, missing or unsupported
/// source graphs, malformed existing wrappers, invalid exact I/P/G closures,
/// root payload/geometry limits, stable allocation refusal, conflicting graph
/// insertion, identity failures and operation-count overflow.
pub fn complete<'value>(
    candidate: Digest,
    graph: &BTreeMap<Digest, Tree<'value>>,
    selections: &[Selection<'_>],
    arena: &'value maintenance::ByteArena,
    minimum: u64,
    context: SemanticContext,
    memos: MemoPolicy,
) -> Result<Completion<'value>, Error> {
    let selections = bindings::ordered(selections)?;
    let owner = graph
        .get(&candidate)
        .ok_or(Error::Source(evaluation::Error::MissingSource))?;
    let mut checks = Vec::with_capacity(selections.len());
    for selection in &selections {
        // This temporary selector is not an exported completed-owner recipe.
        let recipe =
            IndexEvaluationRecipe::new(candidate, selection.attribute).map_err(Error::Binding)?;
        let source = incremental::PreparedSource::new(&recipe, graph, minimum, context)
            .map_err(Error::Source)?;
        let before = evaluation::verify(&recipe, graph, minimum, context, selection.data)
            .map_err(Error::Index)?;
        checks.push((source.preparation_work(), before));
    }

    let mut work = Work::default();
    let properties = bindings::merge(owner, &selections, arena, &mut work)?;
    let owner = owner
        .with_properties(Some(properties))
        .map_err(Error::Owner)?;
    for node in &owner.emitted {
        add(&mut work.owner_bytes_emitted, node.encoded().len())?;
        add(&mut work.owner_bytes_hashed, node.encoded().len())?;
        add(&mut work.owner_bytes_hashed, b"terrane-node-v1\0".len())?;
    }
    let root = owner.tree.root_identity();
    let mut completed_graph = graph.clone();
    work.graph_handles_copied = graph.len();
    if let Some(existing) = completed_graph.get(&root) {
        if existing.root_identity() != root
            || existing.root().encoded() != owner.tree.root().encoded()
            || existing.usage() != owner.tree.usage()
            || existing.min_chunk_size() != owner.tree.min_chunk_size()
        {
            return Err(Error::GraphCollision);
        }
    } else {
        completed_graph.insert(root, owner.tree.clone());
        work.owner_handles_copied = 1;
    }

    let mut associations = Vec::with_capacity(selections.len());
    for (selection, (source, before)) in selections.iter().zip(checks) {
        let recipe =
            IndexEvaluationRecipe::new(root, selection.attribute).map_err(Error::Binding)?;
        let prepared =
            lookup::Prepared::prepare(recipe, &completed_graph, minimum, context, selection.data)
                .map_err(Error::FinalBinding)?;
        work.checks.push(Checks {
            source,
            before,
            after: prepared.preparation().clone(),
        });
        drop(prepared);

        let recipe_bytes = recipe.encode();
        let recipe_hash = identity(&recipe_bytes)?;
        add(&mut work.recipe_bytes_encoded, recipe_bytes.len())?;
        add(&mut work.recipe_bytes_hashed, recipe_bytes.len())?;
        add(&mut work.recipe_bytes_hashed, b"terrane-memo-v1\0".len())?;
        let memo = if memos == MemoPolicy::Include {
            let memo = Memo::new(recipe_hash, selection.data.root);
            let bytes = memo.encode();
            let identity = identity(&bytes)?;
            add(&mut work.memo_bytes_encoded, bytes.len())?;
            add(&mut work.memo_bytes_hashed, bytes.len())?;
            add(&mut work.memo_bytes_hashed, b"terrane-memo-v1\0".len())?;
            Some(MemoAssociation {
                memo,
                bytes,
                identity,
            })
        } else {
            None
        };
        add(&mut work.attribute_bytes_copied, selection.attribute.len())?;
        associations.push(Association {
            attribute: selection.attribute.into(),
            index: selection.data.root,
            recipe_bytes,
            recipe_hash,
            memo,
        });
    }

    Ok(Completion {
        owner,
        associations,
        work,
    })
}
