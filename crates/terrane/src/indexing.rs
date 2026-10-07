//! Loads owner-bound immutable index data through read-only content operations.
//!
//! [`load_source`] acquires namespace bytes independently of index availability
//! for explicit initialization or loss/divergence rebuilding. [`load`] retains
//! raw namespace and auxiliary bytes; [`Loaded::sources`]
//! reconstructs caller-owned borrowed namespace trees; [`Loaded::prepare`]
//! checks their complete immutable relationship before indexed queries run.
//! These stages establish no current producer, trust or authorization proof.
//!
//! ```text
//! selected owner -> index-roots[attribute] -> primary -> routes / gaps
//! raw closure -> borrowed source map -> Prepared -> immutable candidates
//! ```

mod loading;
mod sources;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use terrane_core::chunking::CDC_1M_MIN;
use terrane_core::identity::Digest;
use terrane_core::indexing::IndexEvaluationRecipe;
use terrane_core::indexing::carrier::SemanticContext;
use terrane_core::indexing::evaluation::{self, IndexData};
use terrane_core::indexing::lookup::Prepared;
use terrane_core::tree_builder::Tree;

use crate::store::{StoreErrorKind, StoreFailure};

pub use loading::{load, load_source};
pub use sources::{Reconstruction, Sources};

/// Supplies independently selected semantic revisions for active interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticRevisions {
    /// Recorded property vocabulary revision.
    pub property: u64,
    /// Recorded attribute vocabulary revision.
    pub attribute: u64,
    /// Recorded physical tree revision.
    pub tree: u64,
}

/// Distinguishes incomplete evidence, invalid data and unsupported interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// A binding or required immutable evidence is unavailable.
    Incomplete,
    /// Supplied immutable bytes or relationships fail validation.
    Invalid,
    /// The selected semantic or physical profile is unsupported.
    Unsupported,
    /// A store operation failed for another typed reason.
    Store,
}

/// Retains a failed operation's subject and its original diagnostic source.
#[derive(Debug)]
pub enum Error {
    /// A requested Node could not be read.
    Store {
        /// Independently requested Node digest.
        node: Digest,
        /// Original store failure and attached diagnostic.
        failure: StoreFailure,
    },
    /// The owner has no local binding for the selected attribute.
    MissingBinding(Digest),
    /// The caller selected an unsupported semantic or chunk profile.
    Unsupported,
    /// An immutable check failed for the named Node.
    Invalid {
        /// Node being checked, when the operation has a single subject.
        node: Digest,
        /// Original pure validation error.
        failure: evaluation::Error,
    },
}

impl Error {
    /// Returns the stable outcome without interpreting diagnostic strings.
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Store { failure, .. } => match failure.kind() {
                StoreErrorKind::Absent(_) | StoreErrorKind::Unavailable { .. } => {
                    ErrorKind::Incomplete
                }
                StoreErrorKind::Unsupported => ErrorKind::Unsupported,
                StoreErrorKind::Corrupt(_) | StoreErrorKind::Invalid(_) => ErrorKind::Invalid,
                _ => ErrorKind::Store,
            },
            Self::MissingBinding(_) => ErrorKind::Incomplete,
            Self::Unsupported => ErrorKind::Unsupported,
            Self::Invalid { failure, .. } => match failure {
                evaluation::Error::Incomplete
                | evaluation::Error::MissingSource
                | evaluation::Error::MissingNode => ErrorKind::Incomplete,
                _ => ErrorKind::Invalid,
            },
        }
    }

    /// Returns the independently requested or checked Node subject.
    pub fn subject(&self) -> Option<Digest> {
        match self {
            Self::Store { node, .. } | Self::Invalid { node, .. } | Self::MissingBinding(node) => {
                Some(*node)
            }
            Self::Unsupported => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store { failure, .. } => write!(formatter, "immutable index evidence: {failure}"),
            Self::MissingBinding(_) => {
                formatter.write_str("owner-local index binding is incomplete")
            }
            Self::Unsupported => formatter.write_str("unsupported immutable index context"),
            Self::Invalid { failure, .. } => failure.fmt(formatter),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store { failure, .. } => Some(failure),
            Self::Invalid { failure, .. } => Some(failure),
            _ => None,
        }
    }
}

fn invalid(node: Digest, failure: impl Into<evaluation::Error>) -> Error {
    Error::Invalid {
        node,
        failure: failure.into(),
    }
}

fn increment(counter: &mut usize, amount: usize, node: Digest) -> Result<(), Error> {
    *counter = counter
        .checked_add(amount)
        .ok_or_else(|| invalid(node, evaluation::Error::Limit))?;
    Ok(())
}

/// Counts actual store loading operations separately from subsequent verification.
///
/// These event counts do not measure total CPU, allocation or incremental work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Loading {
    /// Whole-Node store reads; cached bytes avoid only this operation.
    pub gets: usize,
    /// Bytes returned by successful store reads.
    pub fetched_bytes: usize,
    /// Identity checks, including repeated contextual Node visits.
    pub identity_checks: usize,
    /// Physical Node decodes, including repeated roles and placements.
    pub node_decodes: usize,
    /// Namespace root occurrences scheduled, including sibling sharing.
    pub namespace_roots: usize,
    /// Contextual auxiliary Node validation calls.
    pub carrier_checks: usize,
}

/// Owns reached immutable namespace bytes independently of auxiliary indexes.
///
/// The selected owner, context and geometry describe ordinary immutable data.
/// Store permissions still apply; this value grants no authorization and proves
/// no index relationship, current occurrence coverage or producer trust. Trees
/// reconstructed from it borrow the raw bytes, with no self-referential storage.
pub struct LoadedSource {
    owner: Digest,
    context: SemanticContext,
    minimum: u64,
    namespace: BTreeMap<Digest, Vec<u8>>,
    roots: BTreeSet<Digest>,
    loading: Loading,
}

impl LoadedSource {
    /// Returns actual namespace acquisition events, excluding reconstruction.
    pub fn loading(&self) -> Loading {
        self.loading
    }

    /// Returns the independently selected owning root.
    pub fn owner(&self) -> Digest {
        self.owner
    }
}

/// Owns fetched bytes without borrowing its reconstructed or prepared views.
pub struct Loaded {
    source: LoadedSource,
    attribute: String,
    index: IndexData,
    loading: Loading,
}

impl Loaded {
    /// Returns namespace and auxiliary acquisition events from bound loading.
    pub fn loading(&self) -> Loading {
        self.loading
    }

    /// Returns the independently selected owning root.
    pub fn owner(&self) -> Digest {
        self.source.owner
    }

    /// Returns the owner-bound primary Node identity.
    pub fn index_root(&self) -> Digest {
        self.index.root
    }

    /// Exhaustively verifies the relationship before preparing immutable queries.
    ///
    /// The caller owns `sources` separately from the raw closure. The returned
    /// preparation retains independent source-value and borrowed-map lifetimes.
    /// Preparation reports its own verification and loading work; later query
    /// C/P/W work is reported by the existing pure query APIs.
    ///
    /// # Errors
    /// Rejects incomplete sources or owner bindings, divergent relationships,
    /// invalid geometry, roles, values, routes and missing or extra occurrences.
    pub fn prepare<'data, 'value>(
        &'data self,
        sources: &'data BTreeMap<Digest, Tree<'value>>,
    ) -> Result<Prepared<'data, 'value>, Error> {
        let recipe = IndexEvaluationRecipe::new(self.source.owner, &self.attribute)
            .map_err(|error| invalid(self.source.owner, error))?;
        Prepared::prepare(
            recipe,
            sources,
            self.source.minimum,
            self.source.context,
            &self.index,
        )
        .map_err(|error| invalid(self.source.owner, error))
    }
}
