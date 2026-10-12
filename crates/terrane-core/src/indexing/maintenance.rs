//! Owns repeatable maintenance of ordinary immutable index data.
//!
//! Preparation, incremental updates, initialization, explicit rebuilding and
//! closure export have distinct accounting. Maintained states retain canonical
//! route Trees and stable borrowed bytes across successive updates. Their
//! contextual primary, occurrence and gap roles remain ordinary data contracts.
//!
//! The caller owns the stable byte arena. Balanced persistent maps share old
//! route models and exact reachable closure without copying whole generations.

mod accounting;
mod closure;
mod persistent;
mod prepare;
mod routes;
mod storage;
mod temporary;
mod update;

#[cfg(test)]
mod tests;

pub use accounting::{
    BatchWork, ExportWork, MapWork, PreparationWork, PublicationWork, StagingWork, TemporaryWork,
    UpdateWork,
};
pub use prepare::{ConstructionKind, ConstructionWork, initialize, prepare, rebuild};
pub use storage::ByteArena;
pub use update::{update, update_with_publication};

use alloc::{collections::BTreeMap, rc::Rc, string::String, vec::Vec};
use core::fmt;

use super::{
    carrier::{Role, SemanticContext},
    evaluation,
    incremental::{FileState, PreparedSource, SourceLookup},
};
use crate::{identity::Digest, tree_builder::Tree};
use persistent::Map;

/// A rejected immutable maintenance operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Independent source, relationship or canonical validation failed.
    Evaluation(evaluation::Error),
    /// Supplied discovery, recipe or graph belongs to another source selection.
    Binding,
    /// A contradictory transition disagrees with retained ordinary state.
    Transition,
    /// Stable storage could not accommodate a canonical byte payload.
    Allocation,
    /// An operation counter or protocol resource limit was exceeded.
    Limit,
}

impl From<evaluation::Error> for Error {
    fn from(error: evaluation::Error) -> Self {
        Self::Evaluation(error)
    }
}

impl From<crate::tree_format::Error> for Error {
    fn from(error: crate::tree_format::Error) -> Self {
        Self::Evaluation(error.into())
    }
}

impl From<super::Error> for Error {
    fn from(error: super::Error) -> Self {
        Self::Evaluation(error.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluation(error) => error.fmt(formatter),
            Self::Binding => formatter.write_str("mismatched immutable maintenance binding"),
            Self::Transition => formatter.write_str("contradictory immutable route transition"),
            Self::Allocation => formatter.write_str("stable index byte allocation refused"),
            Self::Limit => formatter.write_str("index maintenance resource limit exceeded"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Evaluation(error) => Some(error),
            Self::Binding | Self::Transition | Self::Allocation | Self::Limit => None,
        }
    }
}

/// A complete immutable value/object predicate, retaining actual absence.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Predicate {
    /// Actual regular-file Chunk or Manifest identity.
    pub object: Digest,
    /// Canonical selected inline value, with absence represented separately.
    pub value: Option<Vec<u8>>,
}

impl From<&FileState> for Predicate {
    fn from(state: &FileState) -> Self {
        Self {
            object: state.object(),
            value: state.value.clone(),
        }
    }
}

/// Identifies a contextual auxiliary tree without flattening local graft hops.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Coordinate {
    /// The selected attribute's primary candidate tree.
    Primary,
    /// The selected attribute's missing-object tree.
    Gap,
    /// One predicate's local route reached through ordered graft keys.
    Route {
        /// Exact value/object membership predicate.
        predicate: Predicate,
        /// Root-local graft keys; source identities are diagnostic fields.
        hops: Vec<Vec<u8>>,
    },
}

impl Coordinate {
    fn role(&self) -> Role {
        match self {
            Self::Primary => Role::Primary,
            Self::Gap => Role::Gap,
            Self::Route { predicate, .. } if predicate.value.is_some() => Role::PresentRoute,
            Self::Route { .. } => Role::MissingRoute,
        }
    }
}

/// An exact contextual row or named structural-binding transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteChange {
    /// Local tree supplying the row or binding.
    pub coordinate: Coordinate,
    /// Local row key, or registered property name for a binding.
    pub key: Vec<u8>,
    /// Previous complete row/binding model.
    pub old: Option<RouteValue>,
    /// Replacement complete row/binding model.
    pub new: Option<RouteValue>,
    /// Independently resolved previous namespace source root for route rows.
    pub old_source: Option<Digest>,
    /// Independently resolved replacement namespace source root for route rows.
    pub new_source: Option<Digest>,
}

/// Complete specialized-row or detached-binding data, without authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteValue {
    /// A type-7 row containing exactly O and an optional structural pointer.
    Row {
        /// Actual regular-file content identity.
        object: Digest,
        /// Nonempty child route, absent for terminals.
        route: Option<Digest>,
    },
    /// A named binding's canonical pointer payload.
    Binding {
        /// Canonical encoded property wrapper or selected owner binding value.
        bytes: Vec<u8>,
    },
}

/// Contains only newly emitted canonical bytes needed by an updated index.
///
/// Nodes reused from the checked previous closure and unreachable intermediate
/// outputs are excluded. This ordinary byte payload grants no publication or
/// relationship authority; callers still independently verify the full result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Publication {
    /// Reachable newly emitted Node identities and their canonical bytes.
    pub nodes: Vec<(Digest, Vec<u8>)>,
    /// Actual candidate selection, map lookup and byte-copy work.
    pub work: PublicationWork,
}

/// Retains a checked ordinary immutable index and its exact reachable closure.
///
/// Cloning a state shares balanced map roots and canonical Tree subtrees. The
/// state shares a selected reachable source snapshot and borrows caller-owned arena;
/// it establishes no signing, producer, policy, memo or publication authority.
#[derive(Clone, Debug)]
pub struct PreparedIndex<'graph, 'epoch> {
    owner: Digest,
    attribute: String,
    minimum: u64,
    context: SemanticContext,
    sources: SourceLookup<'graph, 'epoch>,
    arena: &'epoch ByteArena,
    primary: Rc<Tree<'epoch>>,
    gap: Option<Rc<Tree<'epoch>>>,
    routes: Map<Coordinate, Rc<Tree<'epoch>>>,
    closure: Map<Digest, closure::Record<'epoch>>,
}

impl PreparedIndex<'_, '_> {
    /// Returns the current detached primary Node identity.
    pub fn root(&self) -> Digest {
        self.primary.root_identity()
    }

    /// Returns the independently selected namespace owner.
    pub fn owner(&self) -> Digest {
        self.owner
    }

    /// Encodes the selected detached owner-local noninherited binding.
    pub fn owner_binding(&self) -> Vec<u8> {
        owner_binding(&self.attribute, self.root())
    }

    /// Returns reachable physical-node count without materializing the closure.
    pub fn node_count(&self) -> usize {
        self.closure.len()
    }

    /// Returns contextual route-map cardinality and balanced height.
    pub fn route_map_shape(&self) -> (usize, usize) {
        (self.routes.len(), self.routes.height())
    }

    /// Returns exact closure-map cardinality and balanced height.
    pub fn closure_map_shape(&self) -> (usize, usize) {
        (self.closure.len(), self.closure.height())
    }

    /// Copies the exact reachable canonical closure for independent verification.
    ///
    /// This exhaustive export is suitable for independent completion checks and
    /// explicit initialization or rebuild. Existing-index publication uses
    /// [`update_with_publication`] to avoid exporting reused nodes again.
    ///
    /// # Errors
    /// Rejects export counter overflow.
    pub fn materialize(&self) -> Result<(evaluation::IndexData, ExportWork), Error> {
        let mut nodes = BTreeMap::new();
        let mut work = ExportWork::default();
        let mut overflow = false;
        self.closure.visit(&mut |digest, record| {
            let bytes = record.node.encoded();
            match (
                work.nodes.checked_add(1),
                work.bytes.checked_add(bytes.len()),
            ) {
                (Some(count), Some(length)) => {
                    work.nodes = count;
                    work.bytes = length;
                }
                _ => overflow = true,
            }
            nodes.insert(*digest, bytes.to_vec());
        });
        if overflow {
            return Err(Error::Limit);
        }
        Ok((
            evaluation::IndexData {
                root: self.root(),
                nodes,
                work: evaluation::Work::default(),
            },
            work,
        ))
    }
}

fn owner_binding(attribute: &str, root: Digest) -> Vec<u8> {
    let mut bytes = Vec::new();
    crate::cbor::write_map(&mut bytes, 2);
    crate::cbor::write_text(&mut bytes, "value");
    crate::cbor::write_map(&mut bytes, 1);
    crate::cbor::write_text(&mut bytes, attribute);
    crate::cbor::write_argument(&mut bytes, 3, 64);
    for byte in root {
        bytes.push(b"0123456789abcdef"[usize::from(byte >> 4)]);
        bytes.push(b"0123456789abcdef"[usize::from(byte & 15)]);
    }
    crate::cbor::write_text(&mut bytes, "inherit");
    bytes.push(0xf4);
    bytes
}

fn selected(source: &PreparedSource<'_, '_>, owner: Digest, attribute: &str) -> Result<(), Error> {
    if source.root() != owner || source.attribute() != attribute {
        return Err(Error::Binding);
    }
    Ok(())
}
