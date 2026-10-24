//! Groups genuine source transitions and propagates one batch per local route.
//!
//! Only expanded DataChange rows and genuinely changed continuation roots
//! enter temporary grouping. Each contributes at most two local edits plus a
//! protocol-bounded hop chain. The depth-selection scans run at most once per
//! permitted hop depth; operations/comparisons/visits are reported explicitly.
//! If n bounds entries in every relevant namespace Tree and D bounds graft
//! depth, expanded occurrences are at most sum(n^i, i=0..D+1). Predicates are
//! bounded by participating occurrences, so contextual route population is at
//! most their product: logarithmic route/temporary searches cost O(D log n),
//! independently of snapshot history and unrelated supplied roots. Physical
//! staging/closure uses fixed-width digest keys; closure.rs states its concrete
//! per-edge height/probe/copy bound and stream-byte ownership.

use alloc::{rc::Rc, vec::Vec};

use super::{
    BatchWork, Coordinate, Error, Predicate, PreparedIndex, Publication, RouteChange, RouteValue,
    UpdateWork, closure, routes, temporary::Ordered,
};
use crate::{
    identity::Digest,
    indexing::{
        IndexKey,
        carrier::{GapBinding, validate_node},
        incremental::{Address, Discovery, PopulationMode, SourceLookup},
    },
    tree_builder::Tree,
    tree_format::{Entry, Property, TreeUse},
};

#[derive(Default)]
struct Edit {
    old: Option<RouteValue>,
    new: Option<RouteValue>,
}

type Edits = Ordered<Vec<u8>, Edit>;
type Groups = Ordered<Coordinate, Edits>;
type Staged<'a> = Ordered<Digest, closure::Record<'a>>;
type StagedUpdate<'graph, 'epoch> = (PreparedIndex<'graph, 'epoch>, UpdateWork, Staged<'epoch>);

#[cfg(test)]
mod publication_tests;

fn insert(
    groups: &mut Groups,
    coordinate: Coordinate,
    key: Vec<u8>,
    old: Option<RouteValue>,
    new: Option<RouteValue>,
) -> Result<(), Error> {
    let entry = groups
        .entry(coordinate)
        .or_default()
        .entry(key)
        .or_default();
    if let Some(old) = old {
        if entry.old.as_ref().is_some_and(|previous| *previous != old) {
            return Err(Error::Transition);
        }
        entry.old = Some(old);
    }
    if let Some(new) = new {
        if entry.new.as_ref().is_some_and(|previous| *previous != new) {
            return Err(Error::Transition);
        }
        entry.new = Some(new);
    }
    Ok(())
}

fn terminal(
    groups: &mut Groups,
    address: &Address,
    predicate: Predicate,
    added: bool,
) -> Result<(), Error> {
    let (last, parents) = address.split_last().ok_or(Error::Transition)?;
    let value = RouteValue::Row {
        object: predicate.object,
        route: None,
    };
    insert(
        groups,
        Coordinate::Route {
            predicate,
            hops: parents.iter().map(|hop| hop.key.clone()).collect(),
        },
        last.key.clone(),
        (!added).then_some(value.clone()),
        added.then_some(value),
    )
}

fn empty<'a>(minimum: u64, work: &mut UpdateWork) -> Result<Tree<'a>, Error> {
    let tree = Tree::build(Vec::new(), None, minimum, TreeUse::Index)?;
    super::accounting::add(&mut work.empty_trees, 1)?;
    super::accounting::add(&mut work.empty_bytes_encoded, tree.root().encoded().len())?;
    super::accounting::add(
        &mut work.empty_bytes_hashed,
        tree.root().encoded().len() + b"terrane-node-v1\0".len(),
    )?;
    Ok(tree)
}

#[allow(
    clippy::too_many_arguments,
    reason = "a batch retains exact old/new source association and staged closure"
)]
fn batch<'a>(
    coordinate: &Coordinate,
    tree: &Tree<'a>,
    edits: Edits,
    state: &PreparedIndex<'_, 'a>,
    old_sources: &SourceLookup<'_, 'a>,
    new_sources: &SourceLookup<'_, 'a>,
    owner: Digest,
    staged: &mut Ordered<Digest, closure::Record<'a>>,
    work: &mut UpdateWork,
) -> Result<Rc<Tree<'a>>, Error> {
    work.temporary.combine(edits.work()?)?;
    let mut changes: Vec<(Vec<u8>, Option<Entry<'a>>)> = Vec::new();
    let (old_source, new_source) = if let Coordinate::Route { hops, .. } = coordinate {
        (
            routes::resolve(old_sources, state.owner, hops, state.minimum, work)?,
            routes::resolve(new_sources, owner, hops, state.minimum, work)?,
        )
    } else {
        (None, None)
    };
    for (key, edit) in edits {
        let actual = routes::value(state.context, routes::auxiliary(tree, &key, work)?)?;
        if actual != edit.old {
            return Err(Error::Transition);
        }
        if edit.old == edit.new {
            continue;
        }
        let replacement = edit
            .new
            .as_ref()
            .map(|value| routes::entry(state.arena, value, work))
            .transpose()?;
        work.routes.push(RouteChange {
            coordinate: coordinate.clone(),
            key: key.clone(),
            old: edit.old,
            new: edit.new,
            old_source,
            new_source,
        });
        changes.push((key, replacement));
    }
    if changes.is_empty() {
        return Ok(Rc::new(tree.clone()));
    }
    let result = tree.edit_entries(&changes)?;
    for node in &result.emitted {
        work.staging
            .combine(closure::stage(Rc::clone(node), state.context, staged)?)?;
    }
    validate(state.context, coordinate, &result.tree, work)?;
    work.batches.push(BatchWork {
        coordinate: coordinate.clone(),
        edits: changes.len(),
        work: result.work,
    });
    Ok(Rc::new(result.tree))
}

/// Maintains a valid existing index from privately bound immutable discovery.
///
/// Each affected predicate/local-hop tree receives one sorted entry batch.
/// New physical references are installed before previous edges retire, retaining
/// unchanged physical closure even when canonical ancestors are reparented.
/// Discovery retains exact privately bound selected source snapshots. Root
/// lookups and affected-path diagnostics are measured separately from B and
/// cannot include unrelated supplied graph roots. No source is re-prepared.
/// Changed A-to-I output bindings count one route delta; an unchanged I counts
/// zero even if the completed owner and detached recipe identity change.
///
/// # Errors
/// Rejects mismatched owners/attributes/contexts/profiles/geometry/mode, missing
/// affected source paths, contradictory transitions, invalid canonical rows,
/// failed arena allocation and resource limits. The old snapshot is immutable.
pub fn update<'new_graph, 'epoch>(
    old: &PreparedIndex<'_, 'epoch>,
    discovery: &Discovery<'new_graph, 'epoch>,
) -> Result<(PreparedIndex<'new_graph, 'epoch>, UpdateWork), Error> {
    apply(old, discovery, PopulationMode::Existing)
}

/// Maintains an existing index and selects its bounded immutable publication.
///
/// Selection visits only identities emitted by this update's canonical batches
/// and gap-property mutation. Final reachability excludes intermediate roots;
/// previous-closure membership excludes bytes already retained. Both lookups
/// are measured, and neither closure is enumerated. Full independent validation
/// remains the caller's responsibility, using [`PreparedIndex::materialize`].
///
/// # Errors
/// Rejects the same invalid inputs as [`update`], and publication counter or
/// map-work overflow. The previous snapshot remains immutable.
pub fn update_with_publication<'new_graph, 'epoch>(
    old: &PreparedIndex<'_, 'epoch>,
    discovery: &Discovery<'new_graph, 'epoch>,
) -> Result<(PreparedIndex<'new_graph, 'epoch>, UpdateWork, Publication), Error> {
    let (state, work, staged) = apply_staged(old, discovery, PopulationMode::Existing)?;
    let publication = publication(old, &state, staged)?;
    Ok((state, work, publication))
}

// Each staged identity needs one final-closure get and at most one previous-
// closure get. The fixed-width digest AVL bound in closure.rs gives at most
// 514 probes/comparisons per get, so at most 1028 per candidate, with no path
// copies or edge descent. Byte copies are a subset of actual emitted canonical
// payloads; staging deduplicates repeated emission and final reachability drops
// intermediates. No population-sized enumeration is hidden in selection.
fn publication(
    old: &PreparedIndex<'_, '_>,
    state: &PreparedIndex<'_, '_>,
    staged: Staged<'_>,
) -> Result<Publication, Error> {
    let mut result = Publication::default();
    for (identity, _) in staged {
        super::accounting::add(&mut result.work.candidates, 1)?;
        let Some(record) = state.closure.get(&identity, &mut result.work.maps) else {
            super::accounting::add(&mut result.work.discarded, 1)?;
            continue;
        };
        if old.closure.get(&identity, &mut result.work.maps).is_some() {
            super::accounting::add(&mut result.work.reused, 1)?;
            continue;
        }

        let bytes = record.node.encoded();
        super::accounting::add(&mut result.work.nodes, 1)?;
        super::accounting::add(&mut result.work.bytes, bytes.len())?;
        result.nodes.push((identity, bytes.to_vec()));
    }
    result.work.maps.checked()?;
    Ok(result)
}

/// Applies bound discovery in the requested maintenance or initialization mode.
///
/// The previous snapshot remains immutable; successful arena copies are monotone
/// even if later validation fails. Deferred map-count overflow is checked before
/// returning the new snapshot and its work.
///
/// # Errors
/// Rejects mismatched discovery bindings or mode, unavailable or invalid source
/// paths, contradictory transitions, invalid canonical carrier/tree data,
/// arena allocation refusal and resource or accounting limits.
pub(super) fn apply<'new_graph, 'epoch>(
    old: &PreparedIndex<'_, 'epoch>,
    discovery: &Discovery<'new_graph, 'epoch>,
    mode: PopulationMode,
) -> Result<(PreparedIndex<'new_graph, 'epoch>, UpdateWork), Error> {
    let (state, work, _) = apply_staged(old, discovery, mode)?;
    Ok((state, work))
}

fn apply_staged<'new_graph, 'epoch>(
    old: &PreparedIndex<'_, 'epoch>,
    discovery: &Discovery<'new_graph, 'epoch>,
    mode: PopulationMode,
) -> Result<StagedUpdate<'new_graph, 'epoch>, Error> {
    let binding = discovery.sources();
    if binding.old_root() != old.owner
        || binding.attribute() != old.attribute
        || binding.context() != old.context
        || binding.minimum() != old.minimum
        || binding.profile() != crate::indexing::INDEX_EVALUATION_PROFILE
        || binding.mode() != mode
    {
        return Err(Error::Binding);
    }
    let mut work = UpdateWork {
        mode,
        delta_input: discovery.delta_input(),
        delta_data: discovery.delta_data(),
        discovery: discovery.work(),
        boundaries: discovery.boundaries().to_vec(),
        streams: discovery.streams().to_vec(),
        initialization: discovery.initialization().clone(),
        discovery_source_lookups: discovery.source_lookup_work(),
        ..UpdateWork::default()
    };
    routes::resolve(&old.sources, old.owner, &[], old.minimum, &mut work)?;
    routes::resolve(
        discovery.old_lookup(),
        binding.old_root(),
        &[],
        old.minimum,
        &mut work,
    )?;
    routes::resolve(
        discovery.new_lookup(),
        binding.new_root(),
        &[],
        old.minimum,
        &mut work,
    )?;
    let before_payload = old.arena.payload_bytes();
    let mut groups = Groups::new();
    for change in discovery.data() {
        if let (Some(state), Some(address)) = (&change.old, &change.old_address) {
            terminal(&mut groups, address, Predicate::from(state), false)?;
        }
        if let (Some(state), Some(address)) = (&change.new, &change.new_address) {
            terminal(&mut groups, address, Predicate::from(state), true)?;
        }
    }
    let mut routes = old.routes.clone();
    let mut staged = Ordered::new();
    let mut primary_edits = Edits::new();
    let mut gap_edits = Edits::new();
    while !groups.is_empty() {
        // Only changed coordinates are inspected; at most the fixed wire
        // graft-depth limit of distinct depths can occur.
        let depth = groups
            .keys()
            .filter_map(|coordinate| match coordinate {
                Coordinate::Route { hops, .. } => Some(hops.len()),
                _ => None,
            })
            .max()
            .ok_or(Error::Transition)?;
        let mut coordinates = Vec::new();
        for coordinate in groups.keys() {
            super::accounting::add(&mut work.temporary.scans, 2)?;
            if matches!(coordinate, Coordinate::Route { hops, .. } if hops.len() == depth) {
                coordinates.push(coordinate.clone());
            }
        }
        for coordinate in coordinates {
            let edits = groups.remove(&coordinate).ok_or(Error::Transition)?;
            let previous = routes.get(&coordinate, &mut work.maps).cloned();
            let baseline = match &previous {
                Some(tree) => Rc::clone(tree),
                None => Rc::new(empty(old.minimum, &mut work)?),
            };
            let tree = batch(
                &coordinate,
                &baseline,
                edits,
                old,
                discovery.old_lookup(),
                discovery.new_lookup(),
                binding.new_root(),
                &mut staged,
                &mut work,
            )?;
            let previous_root = previous.as_ref().map(|tree| tree.root_identity());
            let root = (!tree.is_empty()).then(|| tree.root_identity());
            if previous_root == root {
                continue;
            }
            if root.is_some() {
                routes.insert(coordinate.clone(), tree, &mut work.maps);
            } else {
                routes.remove(&coordinate, &mut work.maps);
            }
            let Coordinate::Route {
                predicate,
                mut hops,
            } = coordinate
            else {
                return Err(Error::Transition);
            };
            let previous_row = previous_root.map(|route| RouteValue::Row {
                object: predicate.object,
                route: Some(route),
            });
            let row = root.map(|route| RouteValue::Row {
                object: predicate.object,
                route: Some(route),
            });
            if let Some(key) = hops.pop() {
                insert(
                    &mut groups,
                    Coordinate::Route { predicate, hops },
                    key,
                    previous_row,
                    row,
                )?;
            } else {
                let key = predicate
                    .value
                    .as_ref()
                    .map(|value| IndexKey::new(value, predicate.object).map(|key| key.encode()))
                    .transpose()?
                    .unwrap_or_else(|| predicate.object.to_vec());
                let edits = if predicate.value.is_some() {
                    &mut primary_edits
                } else {
                    &mut gap_edits
                };
                if edits
                    .insert(
                        key,
                        Edit {
                            old: previous_row,
                            new: row,
                        },
                    )
                    .is_some()
                {
                    return Err(Error::Transition);
                }
            }
        }
    }
    let gap = if gap_edits.is_empty() {
        old.gap.clone()
    } else {
        let baseline = match &old.gap {
            Some(tree) => Rc::clone(tree),
            None => Rc::new(empty(old.minimum, &mut work)?),
        };
        let tree = batch(
            &Coordinate::Gap,
            &baseline,
            gap_edits,
            old,
            discovery.old_lookup(),
            discovery.new_lookup(),
            binding.new_root(),
            &mut staged,
            &mut work,
        )?;
        (!tree.is_empty()).then_some(tree)
    };
    let mut primary = batch(
        &Coordinate::Primary,
        &old.primary,
        primary_edits,
        old,
        discovery.old_lookup(),
        discovery.new_lookup(),
        binding.new_root(),
        &mut staged,
        &mut work,
    )?;
    let old_gap = old.gap.as_ref().map(|tree| tree.root_identity());
    let new_gap = gap.as_ref().map(|tree| tree.root_identity());
    if old_gap != new_gap {
        let old_bytes = old_gap.map(|root| GapBinding::new(root).encode_binding());
        let new_bytes = new_gap.map(|root| GapBinding::new(root).encode_binding());
        super::accounting::add(
            &mut work.structural_bytes_encoded,
            old_bytes.as_ref().map_or(0, Vec::len),
        )?;
        super::accounting::add(
            &mut work.structural_bytes_encoded,
            new_bytes.as_ref().map_or(0, Vec::len),
        )?;
        let properties = new_bytes
            .as_ref()
            .map(|bytes| {
                old.arena.copy(bytes).map(|value| {
                    alloc::vec![Property {
                        name: "index-gaps",
                        value
                    }]
                })
            })
            .transpose()?;
        let result = primary.with_properties(properties)?;
        for node in &result.emitted {
            work.staging
                .combine(closure::stage(Rc::clone(node), old.context, &mut staged)?)?;
        }
        primary = Rc::new(result.tree);
        work.batches.push(BatchWork {
            coordinate: Coordinate::Primary,
            edits: 0,
            work: result.work,
        });
        work.routes.push(RouteChange {
            coordinate: Coordinate::Primary,
            key: b"index-gaps".to_vec(),
            old: old_bytes.map(|bytes| RouteValue::Binding { bytes }),
            new: new_bytes.map(|bytes| RouteValue::Binding { bytes }),
            old_source: None,
            new_source: None,
        });
    }
    // Entry batches already validate their primary output. Only a changed gap
    // property creates a distinct final root that still needs a carrier check.
    if old_gap != new_gap && primary.root_identity() != old.root() {
        validate(old.context, &Coordinate::Primary, &primary, &mut work)?;
    }
    let new_root = primary.root_identity();
    let mut closure = old.closure.clone();
    if new_root != old.root() {
        let mut closure_work = closure::Work::default();
        closure::add(new_root, &mut closure, &staged, &mut closure_work)?;
        closure::remove(old.root(), &mut closure, &mut closure_work)?;
        work.maps.combine(closure_work.maps);
        work.closure_maps = closure_work.maps;
        work.closure_edges = closure_work.edges;
        work.closure_added = closure_work.added;
        work.closure_removed = closure_work.removed;
    }
    if new_root != old.root() || mode == PopulationMode::NewlyEnabled {
        // Preserve the registered owner-local wrapper and lowercase hex;
        // other owner bindings belong to their own independent maintenance.
        let previous = (mode == PopulationMode::Existing)
            .then(|| super::owner_binding(&old.attribute, old.root()));
        let replacement = super::owner_binding(&old.attribute, new_root);
        super::accounting::add(
            &mut work.structural_bytes_encoded,
            previous.as_ref().map_or(0, Vec::len),
        )?;
        super::accounting::add(&mut work.structural_bytes_encoded, replacement.len())?;
        work.routes.push(RouteChange {
            coordinate: Coordinate::Primary,
            key: old.attribute.as_bytes().to_vec(),
            old: previous.map(|bytes| RouteValue::Binding { bytes }),
            new: Some(RouteValue::Binding { bytes: replacement }),
            old_source: (mode == PopulationMode::Existing).then_some(old.owner),
            new_source: Some(binding.new_root()),
        });
    }
    work.delta_route = work.routes.len();
    work.arena_bytes = old.arena.payload_bytes() - before_payload;
    work.temporary.combine(groups.work()?)?;
    work.staging_maps = staged.work()?;
    work.temporary.combine(work.staging_maps)?;
    work.maps.checked()?;
    let state = PreparedIndex {
        owner: binding.new_root(),
        attribute: old.attribute.clone(),
        minimum: old.minimum,
        context: old.context,
        sources: discovery.new_lookup().clone(),
        arena: old.arena,
        primary,
        gap,
        routes,
        closure,
    };
    Ok((state, work, staged))
}

fn validate(
    context: crate::indexing::carrier::SemanticContext,
    coordinate: &Coordinate,
    tree: &Tree<'_>,
    work: &mut UpdateWork,
) -> Result<(), Error> {
    super::accounting::add(&mut work.carrier_nodes, 1)?;
    if let crate::tree_format::NodeItems::Leaf(rows) = tree.root().items() {
        super::accounting::add(&mut work.carrier_rows, rows.len())?;
    }
    validate_node(context, coordinate.role(), tree.root().node(), true)?;
    Ok(())
}
