//! Composes root namespaces and preserves graft authority boundaries.

mod graft;
mod overlay;
mod subtree;

pub use graft::{
    GraftResult, PreparedGraft, graft, graft_certified, graft_certified_with_domains,
    graft_with_domains, prepare_graft, prepare_graft_with_domains,
};
pub use overlay::{MaterializedOverlay, Overlay, OverlayPolicy, PreparedOverlay};
pub use subtree::{
    PreparedFlatten, PreparedSplit, flatten, prepare_split, prepare_split_with_domains, split,
    split_with_domains,
};

use super::{GraphWork, OperationDomains, Recipe, RootGraph, domain};

use alloc::vec::Vec;

use crate::identity::Digest;
use crate::tree_builder::Tree;
use crate::tree_format::{self, Entry, EntryKind};

/// A malformed namespace or an unavailable graft target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The tree builder rejected an invalid result.
    Build(crate::tree_builder::Error),
    /// The requested path violates the tree key grammar.
    Key(tree_format::Error),
    /// The requested entry is absent or has the wrong type.
    Structure,
    /// A graft would retain conflicting inline descendants.
    InlineChildren,
    /// A referenced root was unavailable to the pure resolver.
    MissingRoot,
    /// A resolver returned bytes whose root identity differs from the target.
    RootIdentity,
    /// Commit binding requires a root not present in the graph registry.
    UncertifiedRoot,
    /// Graft references contain a cycle or exceed the nesting limit.
    Cycle,
    /// Flattening would erase an authority boundary.
    Boundary,
    /// Explicit conflict policy rejected an unresolved value.
    Conflict,
    /// Typed root properties changed incompatibly and require caller resolution.
    RootPropertiesConflict(super::RootPropertiesConflict),
    /// A root edit lacks a consistent effective disclosure-domain binding.
    DomainContext(super::DomainError),
    /// Trust-sensitive policy lacks matching verified provenance context.
    Trust(super::TrustError),
}

impl From<crate::tree_builder::Error> for Error {
    fn from(error: crate::tree_builder::Error) -> Self {
        Self::Build(error)
    }
}

fn beneath(key: &[u8], prefix: &[u8]) -> bool {
    key.starts_with(prefix) && key.get(prefix.len()) == Some(&b'/')
}

/// Resolves immutable graft targets without performing I/O.
pub trait Roots<'a> {
    /// Returns a previously loaded root, or reports its absence.
    fn resolve(&self, identity: &Digest) -> Option<&Tree<'a>>;
}

/// Rejects cyclic root references and excessive nested-root depth.
///
/// # Errors
/// Returns `MissingRoot` for an unavailable target and `Cycle` for a cycle
/// or a path beyond the specification's 64-graft-edge nesting limit.
pub fn validate_acyclic<'a>(root: &Tree<'a>, roots: &impl Roots<'a>) -> Result<(), Error> {
    super::RootGraph::new().admit(root, roots)?;
    Ok(())
}

/// Resolves a path across nested grafts, honoring the nesting limit.
///
/// # Errors
/// Returns `MissingRoot` for an unavailable target, a key error for malformed
/// input, or `Cycle` when the target chain repeats or exceeds its depth limit.
pub fn lookup<'t, 'a>(
    tree: &'t Tree<'a>,
    key: &[u8],
    roots: &'t impl Roots<'a>,
) -> Result<Option<&'t Entry<'a>>, Error> {
    tree_format::validate_key(key).map_err(Error::Key)?;
    let mut current = tree;
    let mut remainder = key;
    let mut visited = Vec::new();

    loop {
        if visited.contains(&current.root_identity())
            || visited.len() > tree_format::MAX_GRAFT_DEPTH
        {
            return Err(Error::Cycle);
        }
        visited.push(current.root_identity());
        let mut crossing = None;
        for (index, byte) in remainder.iter().enumerate() {
            if *byte == b'/'
                && let Some(Entry {
                    kind: EntryKind::Tree { root, .. },
                    ..
                }) = current.get(&remainder[..index])
            {
                crossing = Some((*root, index + 1));
                break;
            }
        }
        match crossing {
            None => return Ok(current.get(remainder)),
            Some((root, offset)) => {
                current = roots.resolve(&root).ok_or(Error::MissingRoot)?;
                if current.root_identity() != root {
                    return Err(Error::RootIdentity);
                }
                remainder = &remainder[offset..];
            }
        }
    }
}

/// A canonical materialized composite retaining its recomputation recipe.
#[derive(Clone, Debug)]
pub struct MaterializedRoot<'a> {
    /// Canonical tree ready for immutable publication.
    pub tree: Tree<'a>,
    /// Canonical operation and semantic inputs.
    pub recipe: Vec<u8>,
}

impl MaterializedRoot<'_> {
    /// Records the root, recipe, and certified conflict profile on an unsigned commit.
    ///
    /// # Errors
    /// Returns `UncertifiedRoot` if the composite root has not been admitted to
    /// the supplied graph registry with its immutable graft targets.
    pub fn bind_commit(
        &self,
        commit: &mut crate::refs::Commit,
        graph: &super::RootGraph,
    ) -> Result<(), Error> {
        let conflicted = graph
            .conflicted(&self.tree.root_identity())
            .ok_or(Error::UncertifiedRoot)?;
        commit.tree = self.tree.root_identity();
        commit.profile_pair.recipe = Some(self.recipe.clone());
        commit.profile_pair.conflicted = Some(conflicted);
        commit.provenance.source = crate::refs::CommitSource::Derived;
        commit.signature = None;
        Ok(())
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Build(error) | Self::Key(error) => error.fmt(formatter),
            Self::Structure => formatter.write_str("invalid namespace structure"),
            Self::InlineChildren => {
                formatter.write_str("graft replacement requires removal of inline children")
            }
            Self::MissingRoot => formatter.write_str("referenced root is unavailable"),
            Self::UncertifiedRoot => formatter.write_str("root graph has not been certified"),
            Self::RootIdentity => formatter.write_str("resolved root has another identity"),
            Self::Cycle => {
                formatter.write_str("root graph contains a cycle or exceeds its nesting limit")
            }
            Self::Boundary => formatter.write_str("flattening would cross an authority boundary"),
            Self::Conflict => formatter.write_str("explicit merge policy rejected a conflict"),
            Self::RootPropertiesConflict(_) => {
                formatter.write_str("root properties require explicit conflict resolution")
            }
            Self::Trust(error) => error.fmt(formatter),
            Self::DomainContext(error) => error.fmt(formatter),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Build(error) | Self::Key(error) => Some(error),
            Self::Trust(error) => Some(error),
            Self::DomainContext(error) => Some(error),
            _ => None,
        }
    }
}
