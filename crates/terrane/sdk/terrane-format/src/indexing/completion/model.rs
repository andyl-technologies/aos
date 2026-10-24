//! Builds independent raw CBOR oracles for finite ordinary namespaces and indexes.
//!
//! The small oracle emits leaf Nodes directly from logical rows. The internal
//! owner witness encodes typed child descriptors and an independently assembled
//! property map, without invoking production Node or owner-property encoders.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};

use crate::{
    cbor,
    identity::Digest,
    indexing::{carrier::SemanticContext, evaluation::IndexData},
    tree_builder::Tree,
    tree_format::{
        Attribute, ContentRef, Entry, EntryKind, LeafItem, NodeItems, Property, TreeUse,
    },
};

/// Carries fixture construction failures as boxed typed errors.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn core::error::Error>>;
/// Maps fixture root identities to their immutable namespace Trees.
pub(super) type Graph<'a> = BTreeMap<Digest, Tree<'a>>;
/// Sets the fixture chunk minimum used by namespace Tree construction.
pub(super) const MINIMUM: u64 = 262_144;
/// Names the shared fixture file object.
pub(super) const OBJECT: Digest = [0x11; 32];
/// Names a distinct fixture object for disagreement witnesses.
pub(super) const OTHER: Digest = [0x22; 32];

/// Constructs the active fixture semantic revision tuple.
///
/// # Errors
/// Returns the semantic-context error if the fixture tuple is unsupported.
pub(super) fn context() -> TestResult<SemanticContext> {
    Ok(SemanticContext::new(3, 2, 1)?)
}

/// Hashes a literal domain, NUL separator and payload independently.
pub(super) fn hash(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// Builds an inline fixture file with optional matching uid and tag.a values.
pub(super) fn file(value: Option<&'static [u8]>) -> Entry<'static> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: 1,
            content: ContentRef::Inline(OBJECT),
            link_id: None,
        },
        attrs: value
            .map(|value| {
                alloc::vec![
                    Attribute { name: "uid", value },
                    Attribute {
                        name: "tag.a",
                        value
                    }
                ]
            })
            .unwrap_or_default(),
        attrs_present: value.is_some(),
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

/// Builds a bare fixture graft to the supplied namespace root.
pub(super) fn graft(root: Digest) -> Entry<'static> {
    Entry {
        kind: EntryKind::Tree { root, props: None },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

/// Copies a local key into a fixture leaf with the supplied entry.
pub(super) fn leaf(key: &[u8], entry: Entry<'static>) -> LeafItem<'static> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

/// Builds and inserts an ordinary fixture Tree, returning its root identity.
///
/// # Errors
/// Returns Tree construction errors for invalid rows, properties or resource limits.
pub(super) fn add<'a>(
    graph: &mut Graph<'a>,
    rows: Vec<LeafItem<'a>>,
    properties: Option<Vec<Property<'a>>>,
) -> TestResult<Digest> {
    let tree = Tree::build(rows, properties, MINIMUM, TreeUse::Ordinary)?;
    let root = tree.root_identity();
    graph.insert(root, tree);
    Ok(root)
}

/// Builds a repeated-graft namespace containing present and missing values.
///
/// # Errors
/// Returns construction errors from the child or owner Tree.
pub(super) fn fixture() -> TestResult<(Graph<'static>, Digest)> {
    let mut graph = Graph::new();
    let child = add(
        &mut graph,
        alloc::vec![leaf(b"p", file(Some(&[1]))), leaf(b"z", file(None))],
        None,
    )?;
    let owner = add(
        &mut graph,
        alloc::vec![
            leaf(b"a", graft(child)),
            leaf(b"b", graft(child)),
            leaf(b"c", file(Some(&[2])))
        ],
        None,
    )?;
    Ok((graph, owner))
}

fn text_key(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_text(&mut bytes, name);
    bytes
}

/// Assembles a noninherited attribute binding wrapper in encoded-key order.
pub(super) fn binding(bindings: &[(&str, Digest)]) -> Vec<u8> {
    let mut pairs = bindings.to_vec();
    pairs.sort_by_cached_key(|(name, _)| text_key(name));
    let mut bytes = alloc::vec![0xa2, 0x65, b'v', b'a', b'l', b'u', b'e'];
    cbor::write_map(&mut bytes, pairs.len());
    for (name, digest) in pairs {
        cbor::write_text(&mut bytes, name);
        let hex: alloc::string::String = digest
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect();
        cbor::write_text(&mut bytes, &hex);
    }
    bytes.extend_from_slice(&[0x67, b'i', b'n', b'h', b'e', b'r', b'i', b't', 0xf4]);
    bytes
}

/// Assembles a property map from raw payloads in encoded-key order.
pub(super) fn property_map(properties: &[Property<'_>]) -> Vec<u8> {
    let mut properties = properties.to_vec();
    properties.sort_by_cached_key(|property| text_key(property.name));
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, properties.len());
    for property in properties {
        cbor::write_text(&mut bytes, property.name);
        bytes.extend_from_slice(property.value);
    }
    bytes
}

fn namespace_entry(bytes: &mut Vec<u8>, entry: &Entry<'_>) {
    assert!(!entry.xattrs_present && entry.provenance.is_none());
    let fields = match entry.kind {
        EntryKind::File { link_id: None, .. } => 4,
        EntryKind::Tree { props: None, .. } | EntryKind::Directory { .. } => 2,
        _ => panic!("unsupported namespace oracle entry"),
    };
    cbor::write_map(bytes, fields + usize::from(entry.attrs_present));
    bytes.push(1);
    match entry.kind {
        EntryKind::File {
            mode,
            size,
            content: ContentRef::Inline(object),
            ..
        } => {
            bytes.extend_from_slice(&[1, 2]);
            cbor::write_uint(bytes, u64::from(mode));
            bytes.push(3);
            cbor::write_uint(bytes, size);
            bytes.extend_from_slice(&[4, 0x82, 0]);
            cbor::write_bytes(bytes, &object);
        }
        EntryKind::Directory { mode } => {
            bytes.extend_from_slice(&[2, 2]);
            cbor::write_uint(bytes, u64::from(mode));
        }
        EntryKind::Tree { root, .. } => {
            bytes.extend_from_slice(&[4, 6]);
            cbor::write_bytes(bytes, &root);
        }
        _ => panic!("unsupported namespace oracle content"),
    }
    if entry.attrs_present {
        bytes.push(9);
        let mut attributes = entry.attrs.clone();
        attributes.sort_by_cached_key(|attribute| text_key(attribute.name));
        cbor::write_map(bytes, attributes.len());
        for attribute in attributes {
            cbor::write_text(bytes, attribute.name);
            bytes.extend_from_slice(attribute.value);
        }
    }
}

/// Assembles a namespace root Node with the supplied property envelope.
///
/// # Panics
/// Panics for leaf entries with xattrs, provenance, hard links, manifests, graft
/// overrides or kinds outside the oracle's inline-file/directory/graft subset.
pub(super) fn namespace_wire(tree: &Tree<'_>, properties: Option<&[Property<'_>]>) -> Vec<u8> {
    let mut bytes = alloc::vec![if properties.is_some() { 0xa3 } else { 0xa2 }, 1];
    cbor::write_uint(&mut bytes, u64::from(tree.root().level()));
    bytes.push(2);
    match tree.root().items() {
        NodeItems::Leaf(items) => {
            cbor::write_array(&mut bytes, items.len());
            let mut previous: &[u8] = &[];
            for item in items {
                let prefix = previous
                    .iter()
                    .zip(&item.key)
                    .take_while(|(left, right)| left == right)
                    .count();
                bytes.push(0x83);
                cbor::write_bytes(&mut bytes, &item.key[prefix..]);
                cbor::write_uint(&mut bytes, prefix as u64);
                namespace_entry(&mut bytes, &item.entry);
                previous = &item.key;
            }
        }
        NodeItems::Internal(children) => {
            cbor::write_array(&mut bytes, children.len());
            for child in children {
                bytes.push(0x84);
                cbor::write_bytes(&mut bytes, &child.last_key);
                cbor::write_bytes(&mut bytes, &child.child);
                cbor::write_uint(&mut bytes, child.count);
                cbor::write_uint(&mut bytes, child.weight);
            }
        }
    }
    if let Some(properties) = properties {
        bytes.push(3);
        bytes.extend(property_map(properties));
    }
    bytes
}

/// Assembles an owner root Node with an explicit property map.
///
/// # Panics
/// Panics for leaf entries outside the namespace wire oracle's supported subset.
pub(super) fn owner_wire(tree: &Tree<'_>, properties: &[Property<'_>]) -> Vec<u8> {
    namespace_wire(tree, Some(properties))
}

/// Assembles the detached registered index recipe for an owner and attribute.
pub(super) fn recipe(owner: Digest, attribute: &str) -> Vec<u8> {
    let mut bytes = alloc::vec![
        0xa3, 1, 0x65, b'i', b'n', b'd', b'e', b'x', 2, 0x81, 0x58, 0x20
    ];
    bytes.extend(owner);
    bytes.extend_from_slice(&[
        3, 0xa2, 0x67, b'p', b'r', b'o', b'f', b'i', b'l', b'e', 0x70,
    ]);
    bytes.extend_from_slice(b"terrane-index/v1");
    bytes.push(0x69);
    bytes.extend_from_slice(b"attribute");
    cbor::write_text(&mut bytes, attribute);
    bytes
}

/// Assembles the common Memo record from recipe and index identities.
pub(super) fn memo(q: Digest, index: Digest) -> Vec<u8> {
    let mut bytes = alloc::vec![0xa2, 1, 0x58, 0x20];
    bytes.extend(q);
    bytes.extend_from_slice(&[2, 0x58, 0x20]);
    bytes.extend(index);
    bytes
}

#[derive(Clone)]
struct Row {
    key: Vec<u8>,
    object: Digest,
    route: Option<Digest>,
}

type Predicate = (Option<Vec<u8>>, Digest);

fn wire(rows: &[Row], gap: Option<Digest>) -> Vec<u8> {
    let mut bytes = alloc::vec![if gap.is_some() { 0xa3 } else { 0xa2 }, 1, 0, 2];
    cbor::write_array(&mut bytes, rows.len());
    let mut previous: &[u8] = &[];
    for row in rows {
        let prefix = previous
            .iter()
            .zip(&row.key)
            .take_while(|(left, right)| left == right)
            .count();
        cbor::write_array(&mut bytes, 3);
        cbor::write_bytes(&mut bytes, &row.key[prefix..]);
        cbor::write_uint(&mut bytes, prefix as u64);
        bytes.extend_from_slice(&[if row.route.is_some() { 0xa3 } else { 0xa2 }, 1, 7]);
        if let Some(route) = row.route {
            bytes.extend_from_slice(&[9, 0xa1, 0x71]);
            bytes.extend_from_slice(b"index.occurrences");
            cbor::write_bytes(&mut bytes, &route);
        }
        bytes.extend_from_slice(&[14, 0x81]);
        cbor::write_bytes(&mut bytes, &row.object);
        previous = &row.key;
    }
    if let Some(gap) = gap {
        bytes.extend_from_slice(&[3, 0xa1, 0x6a]);
        bytes.extend_from_slice(b"index-gaps");
        let wrapped = binding(&[]);
        // The gap wrapper's value is one hex text, not an attribute map.
        bytes.extend_from_slice(&wrapped[..7]);
        let hex: alloc::string::String = gap
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect();
        cbor::write_text(&mut bytes, &hex);
        bytes.extend_from_slice(&wrapped[8..]);
    }
    bytes
}

fn stage(nodes: &mut BTreeMap<Digest, Vec<u8>>, rows: &[Row], gap: Option<Digest>) -> Digest {
    let bytes = wire(rows, gap);
    let root = hash(b"terrane-node-v1", &bytes);
    nodes.insert(root, bytes);
    root
}

fn state(entry: &Entry<'_>, attribute: &str) -> Option<Predicate> {
    if let EntryKind::File { content, .. } = entry.kind {
        let object = match content {
            ContentRef::Inline(object) | ContentRef::Manifest(object) => object,
        };
        let value = entry
            .attrs
            .iter()
            .find(|value| value.name == attribute)
            .map(|value| value.value.to_vec());
        Some((value, object))
    } else {
        None
    }
}

fn inventory(
    graph: &Graph<'_>,
    root: Digest,
    attribute: &str,
    predicates: &mut BTreeSet<Predicate>,
) {
    for item in graph[&root].iter() {
        if let Some(predicate) = state(&item.entry, attribute) {
            predicates.insert(predicate);
        }
        if let EntryKind::Tree { root, .. } = item.entry.kind {
            inventory(graph, root, attribute, predicates);
        }
    }
}

fn route(
    graph: &Graph<'_>,
    root: Digest,
    attribute: &str,
    predicate: &Predicate,
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
) -> Option<Digest> {
    let mut rows = Vec::new();
    for item in graph[&root].iter() {
        if state(&item.entry, attribute).as_ref() == Some(predicate) {
            rows.push(Row {
                key: item.key.clone(),
                object: predicate.1,
                route: None,
            });
        } else if let EntryKind::Tree { root, .. } = item.entry.kind
            && let Some(child) = route(graph, root, attribute, predicate, nodes)
        {
            rows.push(Row {
                key: item.key.clone(),
                object: predicate.1,
                route: Some(child),
            });
        }
    }
    if rows.is_empty() {
        None
    } else {
        Some(stage(nodes, &rows, None))
    }
}

/// Builds literal index closure bytes by exhaustively expanding fixture grafts.
///
/// # Panics
/// Panics if a referenced source root is absent or an inventoried predicate has
/// no occurrence route; inputs must form a finite acyclic fixture graph.
pub(super) fn index(graph: &Graph<'_>, owner: Digest, attribute: &str) -> IndexData {
    let mut predicates = BTreeSet::new();
    inventory(graph, owner, attribute, &mut predicates);
    let mut nodes = BTreeMap::new();
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for predicate in predicates {
        let route = route(graph, owner, attribute, &predicate, &mut nodes);
        assert!(route.is_some());
        let mut key = predicate.0.clone().unwrap_or_default();
        key.extend(predicate.1);
        let row = Row {
            key,
            object: predicate.1,
            route,
        };
        if predicate.0.is_some() {
            present.push(row);
        } else {
            missing.push(row);
        }
    }
    present.sort_by(|left, right| left.key.cmp(&right.key));
    let gap = if missing.is_empty() {
        None
    } else {
        Some(stage(&mut nodes, &missing, None))
    };
    let root = stage(&mut nodes, &present, gap);
    IndexData {
        root,
        nodes,
        work: Default::default(),
    }
}

/// Counts supplied-byte checks for the repeated-graft fixture's literal leaves.
///
/// # Panics
/// Panics if the supplied closure does not contain exactly seven Nodes.
pub(super) fn fixture_physical_bytes(data: &IndexData) -> (usize, usize) {
    let repeated = (*b"pz")
        .into_iter()
        .map(|key| {
            wire(
                &[Row {
                    key: alloc::vec![key],
                    object: OBJECT,
                    route: None,
                }],
                None,
            )
            .len()
        })
        .sum::<usize>();
    assert_eq!(data.nodes.len(), 7);
    let visits = 9;
    let supplied = data.nodes.values().map(Vec::len).sum::<usize>() + repeated;
    (supplied * 2, supplied + visits * b"terrane-node-v1\0".len())
}
