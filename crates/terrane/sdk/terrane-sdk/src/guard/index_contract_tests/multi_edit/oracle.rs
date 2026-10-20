//! Checks literal TREE-35 rows and immutable closure differences independently.
//!
//! Namespace File entries provide the expected value/object/address table. The
//! actual auxiliary rows are decoded directly, without evaluation, carrier
//! classification, discovery, editing or publication routines.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Coordinate, MINIMUM, Model, REPEATS, TestResult, auxiliary, invalid, leaves, physical, source,
    tree,
};

use terrane_format::{
    identity::Digest,
    indexing::{IndexKey, evaluation::IndexData},
    tree_builder::Tree,
    tree_format::{self, ContentRef, Entry, EntryKind, NodeItems, TreeUse},
};

type Rows = BTreeMap<(Vec<u8>, Digest), BTreeSet<Vec<Vec<u8>>>>;

/// Retains independent closure changes, including actual outgoing edge multiplicity.
pub(super) struct Closure {
    /// Complete old immutable identities, used only by the independent test oracle.
    pub(super) old: BTreeSet<Digest>,
    /// Complete new immutable identities, used only by the independent test oracle.
    pub(super) new: BTreeSet<Digest>,
    /// New identities that sparse maintenance must emit, in digest order.
    pub(super) added: Vec<Digest>,
    /// Old identities that final reachability must retire.
    pub(super) removed: BTreeSet<Digest>,
    /// Exact payload bytes belonging to the newly reachable identities.
    pub(super) bytes: usize,
    /// Complete final closure bytes retained solely for independent validation.
    pub(super) total_bytes: usize,
    /// Outgoing references of added and retired nodes, counting repeated edges.
    pub(super) edges: usize,
}

/// Derives sparse output from independent complete canonical old/new node sets.
///
/// # Errors
/// Preserves physical decoding errors.
///
/// # Panics
/// Panics if a fixture unexpectedly contains a root property or G binding.
pub(super) fn closure(old: &IndexData, new: &IndexData) -> TestResult<Closure> {
    let before = old.nodes.keys().copied().collect::<BTreeSet<_>>();
    let after = new.nodes.keys().copied().collect::<BTreeSet<_>>();
    let added = after.difference(&before).copied().collect::<Vec<_>>();
    let removed = before.difference(&after).copied().collect::<BTreeSet<_>>();
    let mut bytes = 0;
    let mut edges = 0;
    for (data, changed, added_nodes) in [
        (old, removed.iter().copied().collect::<Vec<_>>(), false),
        (new, added.clone(), true),
    ] {
        for root in changed {
            let payload = data.nodes.get(&root).ok_or_else(invalid)?;
            if added_nodes {
                bytes += payload.len();
            }
            let node = tree_format::decode_node_for(payload, true, MINIMUM, TreeUse::Index)?;
            assert!(
                node.props.as_ref().is_none_or(|props| props.is_empty()),
                "fixture has no G binding"
            );
            edges += match node.items {
                NodeItems::Internal(children) => children.len(),
                NodeItems::Leaf(items) => items
                    .iter()
                    .filter(|item| !item.entry.attrs.is_empty())
                    .count(),
            };
        }
    }
    Ok(Closure {
        old: before,
        new: after,
        added,
        removed,
        bytes,
        total_bytes: new.nodes.values().map(Vec::len).sum(),
        edges,
    })
}

fn namespace(
    model: &Model,
    root: Digest,
    path: &mut Vec<Vec<u8>>,
    rows: &mut Rows,
    n: &mut usize,
    level: &mut u8,
) -> TestResult {
    let source = tree(&model.sources, root, TreeUse::Ordinary)?;
    *n = (*n).max(usize::try_from(source.len())?);
    *level = (*level).max(source.root().level());
    for item in source.iter() {
        path.push(item.key.clone());
        match &item.entry.kind {
            EntryKind::Tree { root, .. } => namespace(model, *root, path, rows, n, level)?,
            EntryKind::File {
                content: ContentRef::Inline(object),
                ..
            } => {
                assert_eq!(item.entry.attrs.len(), 1);
                assert_eq!(item.entry.attrs[0].name, "uid");
                rows.entry((item.entry.attrs[0].value.to_vec(), *object))
                    .or_default()
                    .insert(path.clone());
            }
            _ => return Err("unexpected population namespace entry".into()),
        }
        path.pop();
    }
    Ok(())
}

fn pointer(entry: &Entry<'_>, object: Digest) -> TestResult<Option<Digest>> {
    let EntryKind::Index { targets } = &entry.kind else {
        return Err("TREE-35 requires a typed Index row".into());
    };
    assert_eq!(targets, &[object]);
    assert!(!entry.xattrs_present && entry.xattrs.is_empty() && entry.provenance.is_none());
    assert_eq!(entry.attrs_present, !entry.attrs.is_empty());
    if entry.attrs.is_empty() {
        return Ok(None);
    }
    assert_eq!(entry.attrs.len(), 1);
    assert_eq!(entry.attrs[0].name, "index.occurrences");
    let bytes = entry.attrs[0].value;
    assert_eq!(bytes.len(), 34);
    assert_eq!(&bytes[..2], &[0x58, 0x20]);
    Ok(Some(bytes[2..].try_into()?))
}

fn routes(
    data: &IndexData,
    root: Digest,
    object: Digest,
    path: &mut Vec<Vec<u8>>,
    result: &mut BTreeSet<Vec<Vec<u8>>>,
) -> TestResult {
    let items = leaves(&data.nodes, root, TreeUse::Index)?;
    assert!(!items.is_empty());
    for item in items {
        assert!(!item.key.is_empty() && !item.key.contains(&b'/'));
        path.push(item.key);
        if let Some(child) = pointer(&item.entry, object)? {
            routes(data, child, object, path, result)?;
        } else {
            assert!(
                result.insert(path.clone()),
                "one terminal per actual local occurrence"
            );
        }
        path.pop();
    }
    Ok(())
}

/// Compares complete literal file occurrences against typed primary and route rows.
///
/// Returns the actual largest namespace cardinality and physical source level.
/// These are independent fixture bounds, rather than counters from maintenance.
///
/// # Errors
/// Preserves source/key/physical decoding failures and rejects unexpected row kinds.
/// # Panics
/// Panics for divergent value/object membership, route placement or row metadata.
pub(super) fn rows(model: &Model, owner: Digest, data: &IndexData) -> TestResult<(usize, u8)> {
    let mut expected = Rows::new();
    let mut n = 0;
    let mut level = 0;
    namespace(
        model,
        owner,
        &mut Vec::new(),
        &mut expected,
        &mut n,
        &mut level,
    )?;
    let mut actual = Rows::new();
    for item in leaves(&data.nodes, data.root, TreeUse::Index)? {
        let key = IndexKey::decode(&item.key)?;
        let root = pointer(&item.entry, key.object())?.ok_or_else(invalid)?;
        let mut paths = BTreeSet::new();
        routes(data, root, key.object(), &mut Vec::new(), &mut paths)?;
        assert!(
            actual
                .insert((key.value().to_vec(), key.object()), paths)
                .is_none()
        );
    }
    assert_eq!(
        actual, expected,
        "literal file/value/object occurrences define TREE-35 rows"
    );
    Ok((n, level))
}

/// Retains independent logical, physical, closure and fixture-size expectations.
pub(super) struct ExpectedWork {
    /// Counts changed entries and individual root bindings after graft descent.
    pub(super) input: usize,
    /// Counts genuine changed file values or occurrence memberships.
    pub(super) data: usize,
    /// Counts changed logical auxiliary rows and the owner binding.
    pub(super) route: usize,
    /// Predicts physical serialization for each affected auxiliary coordinate.
    pub(super) batches: BTreeMap<Coordinate, physical::ExpectedBatch>,
    /// Records canonical identities present on both sides of a local coordinate.
    pub(super) reused: BTreeSet<Digest>,
    /// Predicts namespace occurrence streams and divergence/ordinary events.
    pub(super) source: source::Expected,
    /// Predicts exact final closure identity, byte and edge changes.
    pub(super) closure: Closure,
    /// Largest actual namespace or auxiliary entry cardinality on either side.
    pub(super) n: usize,
    /// Greatest actual physical namespace root level on either side.
    pub(super) source_level: u8,
    /// Greatest actual physical auxiliary root level on either side.
    pub(super) auxiliary_level: u8,
    /// Greatest actual local route graft-hop count on either side.
    pub(super) max_hops: usize,
    /// Predicts the separate native containing-root graft replacement batch.
    pub(super) propagation: Option<physical::ExpectedBatch>,
}

/// Derives all owner expectations from independently canonical old/new models.
///
/// # Errors
/// Preserves source, row, physical and contextual coordinate decoding failures.
///
/// # Panics
/// Panics for unexpected fixture kinds, divergent literal rows or graft edits.
pub(super) fn expected_work(old: &Model, new: &Model) -> TestResult<BTreeMap<bool, ExpectedWork>> {
    let mut result = BTreeMap::new();
    for root in [true, false] {
        let before = if root { old.root } else { old.child };
        let after = if root { new.root } else { new.child };
        let compared = if root {
            new.maintenance_root
        } else {
            new.maintenance_child
        };
        let (input, data) = source_delta(old, before, new, compared)?;
        let source = source::expected(old, before, new, compared)?;
        let old_data = old.indexes.get(&before).ok_or_else(invalid)?;
        let new_data = new.indexes.get(&after).ok_or_else(invalid)?;
        let (old_n, old_level) = rows(old, before, old_data)?;
        let (new_n, new_level) = rows(new, after, new_data)?;
        let mut n = old_n.max(new_n);
        let source_level = old_level.max(new_level);
        let mut auxiliary_level = 0;
        let mut max_hops = 0;
        let closure = closure(old_data, new_data)?;
        let propagation = if root {
            let candidate = new.tree.tree()?;
            let updated = tree(&new.sources, compared, TreeUse::Ordinary)?;
            let edits = updated
                .iter()
                .filter(|item| candidate.get(&item.key) != Some(&item.entry))
                .map(|item| (item.key.clone(), Some(item.entry.clone())))
                .collect::<Vec<_>>();
            assert_eq!(
                edits.len(),
                REPEATS,
                "only completed child graft targets propagate"
            );
            Some(physical::expected(&candidate, &updated, &edits)?)
        } else {
            None
        };
        let old_coordinates = auxiliary(old_data)?;
        let new_coordinates = auxiliary(new_data)?;
        let coordinates = old_coordinates
            .keys()
            .chain(new_coordinates.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut route = usize::from(old_data.root != new_data.root);
        let mut batches = BTreeMap::new();
        let mut reused = BTreeSet::new();
        for coordinate in coordinates {
            if let Coordinate::Route { hops, .. } = &coordinate {
                max_hops = max_hops.max(hops.len());
            }
            let empty = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Index)?;
            let old_tree = old_coordinates
                .get(&coordinate)
                .map(|root| tree(&old_data.nodes, *root, TreeUse::Index))
                .transpose()?
                .unwrap_or_else(|| empty.clone());
            let new_tree = new_coordinates
                .get(&coordinate)
                .map(|root| tree(&new_data.nodes, *root, TreeUse::Index))
                .transpose()?
                .unwrap_or_else(|| empty.clone());
            n = n
                .max(usize::try_from(old_tree.len())?)
                .max(usize::try_from(new_tree.len())?);
            auxiliary_level = auxiliary_level
                .max(old_tree.root().level())
                .max(new_tree.root().level());
            let old_entries = old_tree
                .iter()
                .map(|item| (item.key.clone(), item.entry.clone()))
                .collect::<BTreeMap<_, _>>();
            let new_entries = new_tree
                .iter()
                .map(|item| (item.key.clone(), item.entry.clone()))
                .collect::<BTreeMap<_, _>>();
            let keys = old_entries
                .keys()
                .chain(new_entries.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            let edits = keys
                .into_iter()
                .filter(|key| old_entries.get(key) != new_entries.get(key))
                .map(|key| {
                    let value = new_entries.get(&key).cloned();
                    (key, value)
                })
                .collect::<Vec<_>>();
            route += edits.len();
            let old_nodes = old_tree
                .nodes()
                .map(|node| node.identity())
                .collect::<BTreeSet<_>>();
            reused.extend(
                new_tree
                    .nodes()
                    .map(|node| node.identity())
                    .filter(|identity| old_nodes.contains(identity)),
            );
            if !edits.is_empty() {
                batches.insert(
                    coordinate,
                    physical::expected(&old_tree, &new_tree, &edits)?,
                );
            }
        }
        result.insert(
            root,
            ExpectedWork {
                input,
                data,
                route,
                batches,
                reused,
                source,
                closure,
                n,
                source_level,
                auxiliary_level,
                max_hops,
                propagation,
            },
        );
    }
    Ok(result)
}

fn source_delta(
    old: &Model,
    old_root: Digest,
    new: &Model,
    new_root: Digest,
) -> TestResult<(usize, usize)> {
    if old_root == new_root {
        return Ok((0, 0));
    }
    let before = tree(&old.sources, old_root, TreeUse::Ordinary)?;
    let after = tree(&new.sources, new_root, TreeUse::Ordinary)?;
    let properties = |tree: &Tree<'_>| {
        tree.props()
            .unwrap_or_default()
            .iter()
            .map(|property| (property.name.to_owned(), property.value.to_vec()))
            .collect::<BTreeMap<_, _>>()
    };
    let old_properties = properties(&before);
    let new_properties = properties(&after);
    let mut input = old_properties
        .keys()
        .chain(new_properties.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| old_properties.get(*key) != new_properties.get(*key))
        .count();
    let mut data = 0;
    let old_entries = before
        .iter()
        .map(|item| (item.key.clone(), item.entry.clone()))
        .collect::<BTreeMap<_, _>>();
    let new_entries = after
        .iter()
        .map(|item| (item.key.clone(), item.entry.clone()))
        .collect::<BTreeMap<_, _>>();
    for key in old_entries
        .keys()
        .chain(new_entries.keys())
        .collect::<BTreeSet<_>>()
    {
        let left = old_entries.get(key);
        let right = new_entries.get(key);
        if left == right {
            continue;
        }
        input += 1;
        match (
            left.map(|entry| &entry.kind),
            right.map(|entry| &entry.kind),
        ) {
            (
                Some(EntryKind::Tree { root: left, .. }),
                Some(EntryKind::Tree { root: right, .. }),
            ) => {
                let child = source_delta(old, *left, new, *right)?;
                input += child.0;
                data += child.1;
            }
            (Some(EntryKind::File { .. }), _) | (_, Some(EntryKind::File { .. })) => data += 1,
            _ => {}
        }
    }
    Ok((input, data))
}
