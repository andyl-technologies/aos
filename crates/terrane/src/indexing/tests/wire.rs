//! Assembles literal Node entries, bindings and canonical physical grouping.
//!
//! Small relationship fixtures never call index construction. The independent
//! boundary model below follows the normative size/hash formula over raw items.

use super::*;
use terrane_core::cbor;

pub(super) const OBJECT: Digest = [7; 32];
const MANIFEST: Digest = [8; 32];
pub(super) const POPULATION: usize = 2048;
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

pub(super) fn hash(bytes: &[u8]) -> Digest {
    let mut input = b"terrane-node-v1\0".to_vec();
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

pub(super) fn store_node(nodes: &mut BTreeMap<Digest, Vec<u8>>, bytes: Vec<u8>) -> Digest {
    let digest = hash(&bytes);
    nodes.insert(digest, bytes);
    digest
}

pub(super) fn file(object: Digest, value: Option<u64>, size: u64, manifest: bool) -> Vec<u8> {
    let mut bytes = vec![if value.is_some() { 0xa5 } else { 0xa4 }, 1, 1, 2];
    cbor::write_uint(&mut bytes, 0o644);
    bytes.push(3);
    cbor::write_uint(&mut bytes, size);
    bytes.extend_from_slice(&[4, 0x82, u8::from(manifest)]);
    cbor::write_bytes(&mut bytes, &object);
    if let Some(value) = value {
        bytes.extend_from_slice(&[9, 0xa1]);
        cbor::write_text(&mut bytes, "uid");
        cbor::write_uint(&mut bytes, value);
    }
    bytes
}

pub(super) fn graft(root: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 4, 6];
    cbor::write_bytes(&mut bytes, &root);
    bytes
}

pub(super) fn terminal(object: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 7, 14, 0x81];
    cbor::write_bytes(&mut bytes, &object);
    bytes
}

fn forward(object: Digest, route: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa3, 1, 7, 9, 0xa1];
    cbor::write_text(&mut bytes, "index.occurrences");
    cbor::write_bytes(&mut bytes, &route);
    bytes.extend_from_slice(&[14, 0x81]);
    cbor::write_bytes(&mut bytes, &object);
    bytes
}

fn hex(digest: Digest) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn binding(name: &str, digest: Digest, attribute: bool) -> Vec<u8> {
    let mut bytes = vec![0xa1];
    cbor::write_text(&mut bytes, name);
    bytes.push(0xa2);
    cbor::write_text(&mut bytes, "value");
    if attribute {
        bytes.push(0xa1);
        cbor::write_text(&mut bytes, "uid");
    }
    cbor::write_text(&mut bytes, &hex(digest));
    cbor::write_text(&mut bytes, "inherit");
    bytes.push(0xf4);
    bytes
}

pub(super) fn gap_binding(digest: Digest) -> Vec<u8> {
    binding("index-gaps", digest, false)
}

fn leaf_item(key: &[u8], entry: &[u8], prior: &[u8]) -> Vec<u8> {
    let shared = key
        .iter()
        .zip(prior)
        .take_while(|(left, right)| left == right)
        .count();
    let mut bytes = vec![0x83];
    cbor::write_bytes(&mut bytes, &key[shared..]);
    cbor::write_uint(&mut bytes, shared as u64);
    bytes.extend_from_slice(entry);
    bytes
}

pub(super) fn leaf(rows: &[(Vec<u8>, Vec<u8>)], properties: Option<Vec<u8>>) -> Vec<u8> {
    let mut bytes = vec![if properties.is_some() { 0xa3 } else { 0xa2 }, 1, 0, 2];
    cbor::write_array(&mut bytes, rows.len());
    let mut prior: &[u8] = &[];
    for (key, entry) in rows {
        bytes.extend_from_slice(&leaf_item(key, entry, prior));
        prior = key;
    }
    if let Some(properties) = properties {
        bytes.push(3);
        bytes.extend(properties);
    }
    bytes
}

fn key(value: u8, object: Digest) -> Vec<u8> {
    let mut key = vec![value];
    key.extend_from_slice(&object);
    key
}

#[derive(Clone)]
pub(super) struct Fixture {
    pub nodes: BTreeMap<Digest, Vec<u8>>,
    pub owner: Digest,
    pub primary: Digest,
    pub child: Digest,
    pub present: Digest,
    pub gap: Digest,
    pub missing: Digest,
    pub owner_rows: Rows,
    pub expected_requests: BTreeSet<Digest>,
    present_rows: Rows,
    primary_rows: Rows,
    gap_rows: Rows,
}

impl Fixture {
    pub fn small() -> Self {
        let mut nodes = BTreeMap::new();
        let child = store_node(
            &mut nodes,
            leaf(
                &[
                    (b"a".to_vec(), file(OBJECT, Some(1), 10, false)),
                    (b"d".to_vec(), file(OBJECT, None, 10, false)),
                ],
                None,
            ),
        );
        let child_present =
            store_node(&mut nodes, leaf(&[(b"a".to_vec(), terminal(OBJECT))], None));
        let child_missing =
            store_node(&mut nodes, leaf(&[(b"d".to_vec(), terminal(OBJECT))], None));
        let present_rows = vec![
            (b"a".to_vec(), terminal(OBJECT)),
            (b"g".to_vec(), forward(OBJECT, child_present)),
            (b"h".to_vec(), forward(OBJECT, child_present)),
        ];
        let present = store_node(&mut nodes, leaf(&present_rows, None));
        let missing = store_node(
            &mut nodes,
            leaf(
                &[
                    (b"b".to_vec(), terminal(OBJECT)),
                    (b"g".to_vec(), forward(OBJECT, child_missing)),
                    (b"h".to_vec(), forward(OBJECT, child_missing)),
                ],
                None,
            ),
        );
        let manifest_route = store_node(
            &mut nodes,
            leaf(&[(b"c".to_vec(), terminal(MANIFEST))], None),
        );
        let gap_rows = vec![(OBJECT.to_vec(), forward(OBJECT, missing))];
        let gap = store_node(&mut nodes, leaf(&gap_rows, None));
        let primary_rows = vec![
            (key(1, OBJECT), forward(OBJECT, present)),
            (key(2, MANIFEST), forward(MANIFEST, manifest_route)),
        ];
        let primary = store_node(&mut nodes, leaf(&primary_rows, Some(gap_binding(gap))));
        let owner_rows = vec![
            (b"a".to_vec(), file(OBJECT, Some(1), 10, false)),
            (b"b".to_vec(), file(OBJECT, None, 10, false)),
            (b"c".to_vec(), file(MANIFEST, Some(2), MINIMUM + 1, true)),
            (b"g".to_vec(), graft(child)),
            (b"h".to_vec(), graft(child)),
        ];
        let owner = store_node(
            &mut nodes,
            leaf(&owner_rows, Some(binding("index-roots", primary, true))),
        );
        Self {
            nodes,
            owner,
            primary,
            child,
            present,
            gap,
            missing,
            owner_rows,
            expected_requests: BTreeSet::from([
                owner,
                child,
                primary,
                present,
                gap,
                missing,
                child_present,
                child_missing,
                manifest_route,
            ]),
            present_rows,
            primary_rows,
            gap_rows,
        }
    }

    pub fn empty() -> Self {
        let mut fixture = Self::small();
        fixture.primary = store_node(&mut fixture.nodes, leaf(&[], None));
        fixture.owner_rows.clear();
        fixture.rebuild_owner();
        fixture
    }

    pub fn empty_shared_contexts() -> Self {
        let mut fixture = Self::empty();
        fixture.owner_rows = vec![(b"g".to_vec(), graft(fixture.primary))];
        fixture.rebuild_owner();
        fixture.expected_requests = BTreeSet::from([fixture.owner, fixture.primary]);
        fixture
    }

    pub fn shared_roles() -> Self {
        let mut fixture = Self::empty();
        let present_source = store_node(
            &mut fixture.nodes,
            leaf(&[(b"a".to_vec(), file(OBJECT, Some(1), 10, false))], None),
        );
        let missing_source = store_node(
            &mut fixture.nodes,
            leaf(&[(b"a".to_vec(), file(OBJECT, None, 10, false))], None),
        );
        let shared = store_node(
            &mut fixture.nodes,
            leaf(&[(b"a".to_vec(), terminal(OBJECT))], None),
        );
        fixture.present = store_node(
            &mut fixture.nodes,
            leaf(&[(b"p".to_vec(), forward(OBJECT, shared))], None),
        );
        fixture.missing = store_node(
            &mut fixture.nodes,
            leaf(&[(b"m".to_vec(), forward(OBJECT, shared))], None),
        );
        fixture.gap_rows = vec![(OBJECT.to_vec(), forward(OBJECT, fixture.missing))];
        fixture.gap = store_node(&mut fixture.nodes, leaf(&fixture.gap_rows, None));
        fixture.primary_rows = vec![(key(1, OBJECT), forward(OBJECT, fixture.present))];
        fixture.owner_rows = vec![
            (b"m".to_vec(), graft(missing_source)),
            (b"p".to_vec(), graft(present_source)),
        ];
        fixture.child = shared;
        fixture.rebuild_primary();
        fixture.expected_requests = BTreeSet::from([
            fixture.owner,
            fixture.primary,
            present_source,
            missing_source,
            shared,
            fixture.present,
            fixture.missing,
            fixture.gap,
        ]);
        fixture
    }

    pub fn only_missing() -> Self {
        let mut fixture = Self::small();
        fixture.owner_rows = vec![(b"b".to_vec(), file(OBJECT, None, 10, false))];
        fixture.missing = store_node(
            &mut fixture.nodes,
            leaf(&[(b"b".to_vec(), terminal(OBJECT))], None),
        );
        fixture.gap_rows = vec![(OBJECT.to_vec(), forward(OBJECT, fixture.missing))];
        fixture.gap = store_node(&mut fixture.nodes, leaf(&fixture.gap_rows, None));
        fixture.primary_rows.clear();
        fixture.rebuild_primary();
        fixture
    }

    pub fn rebuild_owner(&mut self) {
        self.owner = build(
            &mut self.nodes,
            &self.owner_rows,
            Some(binding("index-roots", self.primary, true)),
        );
    }

    fn rebuild_primary(&mut self) {
        self.primary = build(
            &mut self.nodes,
            &self.primary_rows,
            Some(gap_binding(self.gap)),
        );
        self.rebuild_owner();
    }

    pub fn replace_child(&mut self, bytes: Vec<u8>) {
        self.child = store_node(&mut self.nodes, bytes);
        self.owner_rows[3].1 = graft(self.child);
        self.owner_rows[4].1 = graft(self.child);
        self.rebuild_owner();
    }

    pub fn replace_present_route(&mut self, bytes: Vec<u8>) {
        self.present = store_node(&mut self.nodes, bytes);
        self.primary_rows[0].1 = forward(OBJECT, self.present);
        self.rebuild_primary();
    }

    pub fn replace_gap(&mut self, bytes: Vec<u8>) {
        self.gap = store_node(&mut self.nodes, bytes);
        self.rebuild_primary();
    }

    pub fn diverge(&mut self, mutation: usize) {
        match mutation {
            0 => {
                self.primary_rows.remove(0);
                self.rebuild_primary();
            }
            1 => {
                self.primary_rows
                    .push((key(3, OBJECT), forward(OBJECT, self.present)));
                self.rebuild_primary();
            }
            2 => {
                self.present_rows.remove(2);
                self.replace_present_route(leaf(&self.present_rows, None));
            }
            3 => {
                self.present_rows.push((b"z".to_vec(), terminal(OBJECT)));
                self.replace_present_route(leaf(&self.present_rows, None));
            }
            4 => {
                self.present_rows[0].1 = terminal(MANIFEST);
                self.replace_present_route(leaf(&self.present_rows, None));
            }
            5 => {
                self.present_rows[0].1 = forward(OBJECT, self.present);
                self.replace_present_route(leaf(&self.present_rows, None));
            }
            6 => {
                self.primary_rows[0].0 = key(3, OBJECT);
                self.primary_rows.sort();
                self.rebuild_primary();
            }
            7 => {
                self.owner_rows[0].1 = file(MANIFEST, Some(1), MINIMUM + 1, true);
                self.rebuild_owner();
            }
            8 => {
                self.primary = store_node(&mut self.nodes, leaf(&self.primary_rows, None));
                self.rebuild_owner();
            }
            9 => {
                self.gap_rows
                    .push((MANIFEST.to_vec(), forward(MANIFEST, self.present)));
                self.gap = store_node(&mut self.nodes, leaf(&self.gap_rows, None));
                self.rebuild_primary();
            }
            10 => {
                let mut malformed = vec![0xa3, 1, 7, 9, 0xa1];
                cbor::write_text(&mut malformed, "index.occurrences");
                cbor::write_bytes(&mut malformed, &[3; 31]);
                malformed.extend_from_slice(&[14, 0x81]);
                cbor::write_bytes(&mut malformed, &OBJECT);
                self.present_rows[0].1 = malformed;
                self.replace_present_route(leaf(&self.present_rows, None));
            }
            11 => {
                let mut metadata = vec![0xa3, 1, 7, 10, 0xa0, 14, 0x81];
                cbor::write_bytes(&mut metadata, &OBJECT);
                self.present_rows[0].1 = metadata;
                self.replace_present_route(leaf(&self.present_rows, None));
            }
            12 => {
                let mut targets = vec![0xa2, 1, 7, 14, 0x82];
                cbor::write_bytes(&mut targets, &OBJECT);
                cbor::write_bytes(&mut targets, &MANIFEST);
                self.present_rows[0].1 = targets;
                self.replace_present_route(leaf(&self.present_rows, None));
            }
            13 => {
                let other = store_node(
                    &mut self.nodes,
                    leaf(
                        &[(b"a".to_vec(), file(MANIFEST, Some(1), MINIMUM + 1, true))],
                        None,
                    ),
                );
                self.owner_rows[3].1 = graft(other);
                self.rebuild_owner();
            }
            14 => {
                self.replace_gap(leaf(&[], None));
            }
            15 => {
                let mut entry = file(OBJECT, Some(1), 10, false);
                entry.pop();
                cbor::write_text(&mut entry, "wrong registered uid type");
                self.owner_rows[0].1 = entry;
                self.rebuild_owner();
            }
            _ => panic!("unknown divergence"),
        }
    }

    pub fn large() -> Self {
        let mut fixture = Self::small();
        fixture.owner_rows = (0..POPULATION)
            .map(|index| {
                (
                    format!("file{index:05}").into_bytes(),
                    file(OBJECT, Some(1), 10, false),
                )
            })
            .collect();
        fixture.present_rows = fixture
            .owner_rows
            .iter()
            .map(|(key, _)| (key.clone(), terminal(OBJECT)))
            .collect();
        fixture.present = build(&mut fixture.nodes, &fixture.present_rows, None);
        fixture.primary_rows = vec![(key(1, OBJECT), forward(OBJECT, fixture.present))];
        fixture.primary = store_node(&mut fixture.nodes, leaf(&fixture.primary_rows, None));
        fixture.rebuild_owner();
        fixture
    }

    pub fn internal_carriers() -> Self {
        let mut fixture = Self::empty();
        fixture.primary_rows.clear();
        fixture.gap_rows.clear();
        for index in 0..POPULATION {
            let mut object = OBJECT;
            object[..8].copy_from_slice(&(index as u64).to_be_bytes());
            let present_key = format!("present{index:05}").into_bytes();
            let missing_key = format!("missing{index:05}").into_bytes();
            fixture
                .owner_rows
                .push((present_key.clone(), file(object, Some(1), 10, false)));
            fixture
                .owner_rows
                .push((missing_key.clone(), file(object, None, 10, false)));
            let present = store_node(
                &mut fixture.nodes,
                leaf(&[(present_key, terminal(object))], None),
            );
            let missing = store_node(
                &mut fixture.nodes,
                leaf(&[(missing_key, terminal(object))], None),
            );
            fixture
                .primary_rows
                .push((key(1, object), forward(object, present)));
            fixture
                .gap_rows
                .push((object.to_vec(), forward(object, missing)));
        }
        fixture.owner_rows.sort();
        fixture.primary_rows.sort();
        fixture.gap_rows.sort();
        fixture.gap = build(&mut fixture.nodes, &fixture.gap_rows, None);
        fixture.rebuild_primary();
        fixture
    }

    pub fn change_namespace_child(&mut self, change: ChildChange) {
        self.owner = changed_internal(&mut self.nodes, self.owner, change);
    }

    pub fn change_route_child(&mut self, change: ChildChange) {
        self.present = changed_internal(&mut self.nodes, self.present, change);
        self.primary_rows[0].1 = forward(OBJECT, self.present);
        self.primary = store_node(&mut self.nodes, leaf(&self.primary_rows, None));
        self.rebuild_owner();
    }

    pub fn change_primary_child(&mut self, change: ChildChange) {
        self.primary = changed_internal(&mut self.nodes, self.primary, change);
        self.rebuild_owner();
    }

    pub fn change_gap_child(&mut self, change: ChildChange) {
        self.gap = changed_internal(&mut self.nodes, self.gap, change);
        self.rebuild_primary();
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ChildChange {
    Count,
    Weight,
    Separator,
    Level,
}

pub(super) fn changed_internal(
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
    root: Digest,
    change: ChildChange,
) -> Digest {
    let bytes = nodes[&root].clone();
    let node = decode_node_for(&bytes, true, MINIMUM, TreeUse::Index)
        .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
    let NodeItems::Internal(mut children) = node.items else {
        panic!("internal witness required")
    };
    let level = match change {
        ChildChange::Count => {
            children[0].count += 1;
            node.level
        }
        ChildChange::Weight => {
            children[0].weight += 1;
            node.level
        }
        ChildChange::Separator => {
            let last = children[0]
                .last_key
                .last_mut()
                .unwrap_or_else(|| panic!("nonempty separator required"));
            *last = last.wrapping_add(1);
            node.level
        }
        ChildChange::Level => node.level + 1,
    };
    let mut output = vec![if node.props.is_some() { 0xa3 } else { 0xa2 }, 1, level, 2];
    cbor::write_array(&mut output, children.len());
    for child in children {
        output.extend(reference(&Model {
            root: child.child,
            last: child.last_key,
            count: child.count,
            weight: child.weight,
        }));
    }
    if let Some(properties) = node.props {
        output.push(3);
        cbor::write_map(&mut output, properties.len());
        for property in properties {
            cbor::write_text(&mut output, property.name);
            output.extend_from_slice(property.value);
        }
    }
    store_node(nodes, output)
}

struct Model {
    root: Digest,
    last: Vec<u8>,
    count: u64,
    weight: u64,
}

fn reference(child: &Model) -> Vec<u8> {
    let mut bytes = vec![0x84];
    cbor::write_bytes(&mut bytes, &child.last);
    cbor::write_bytes(&mut bytes, &child.root);
    cbor::write_uint(&mut bytes, child.count);
    cbor::write_uint(&mut bytes, child.weight);
    bytes
}

fn cut(size: usize, stored: usize, full: &[u8]) -> u8 {
    let total = size + stored;
    if total > 65536 {
        return 1;
    }
    if total == 65536 {
        return 2;
    }
    if total < 4096 {
        return 0;
    }
    let base = if total >= 32768 {
        1 << 24
    } else {
        (1 << 20) + (total - 4096) * ((1 << 24) - (1 << 20)) / 28672
    };
    let threshold = (base as u64 * stored as u64 / 8).min(1 << 32);
    let hash = blake3::hash(full);
    let hash = u32::from_le_bytes(
        hash.as_bytes()[..4]
            .try_into()
            .unwrap_or_else(|error| panic!("fixture failed: {error:?}")),
    );
    if u64::from(hash) < threshold { 2 } else { 0 }
}

fn store_model(
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
    level: u8,
    items: &[Vec<u8>],
    last: Vec<u8>,
    count: u64,
    children_weight: u64,
) -> Model {
    let mut bytes = vec![0xa2, 1, level, 2];
    cbor::write_array(&mut bytes, items.len());
    for item in items {
        bytes.extend(item);
    }
    let weight = bytes.len() as u64 + children_weight;
    let root = store_node(nodes, bytes);
    Model {
        root,
        last,
        count,
        weight,
    }
}

pub(super) fn build(
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
    rows: &[(Vec<u8>, Vec<u8>)],
    props: Option<Vec<u8>>,
) -> Digest {
    if rows.is_empty() {
        return store_node(nodes, leaf(rows, props));
    }
    let mut leaves = Vec::new();
    let mut pending = Vec::new();
    let mut size = 0;
    let mut prior = Vec::new();
    for (key, entry) in rows {
        let full = leaf_item(key, entry, &[]);
        let stored = leaf_item(key, entry, &prior);
        let decision = cut(size, stored.len(), &full);
        if decision == 1 {
            leaves.push(store_model(
                nodes,
                0,
                &pending,
                prior.clone(),
                pending.len() as u64,
                0,
            ));
            pending.clear();
            size = 0;
        }
        let stored = if decision == 1 { full } else { stored };
        size += stored.len();
        pending.push(stored);
        prior = key.clone();
        if decision == 2 {
            leaves.push(store_model(
                nodes,
                0,
                &pending,
                prior.clone(),
                pending.len() as u64,
                0,
            ));
            pending.clear();
            size = 0;
            prior.clear();
        }
    }
    if !pending.is_empty() {
        leaves.push(store_model(
            nodes,
            0,
            &pending,
            prior,
            pending.len() as u64,
            0,
        ));
    }
    let mut level = 0;
    while leaves.len() > 1 {
        level += 1;
        let mut parents = Vec::new();
        pending.clear();
        size = 0;
        let mut count = 0;
        let mut weight = 0;
        let mut last = Vec::new();
        for child in leaves {
            let bytes = reference(&child);
            let decision = cut(size, bytes.len(), &bytes);
            if decision == 1 {
                parents.push(store_model(
                    nodes,
                    level,
                    &pending,
                    last.clone(),
                    count,
                    weight,
                ));
                pending.clear();
                size = 0;
                count = 0;
                weight = 0;
            }
            size += bytes.len();
            count += child.count;
            weight += child.weight;
            last = child.last;
            pending.push(bytes);
            if decision == 2 {
                parents.push(store_model(
                    nodes,
                    level,
                    &pending,
                    last.clone(),
                    count,
                    weight,
                ));
                pending.clear();
                size = 0;
                count = 0;
                weight = 0;
            }
        }
        if !pending.is_empty() {
            parents.push(store_model(nodes, level, &pending, last, count, weight));
        }
        leaves = parents;
    }
    let root = leaves
        .pop()
        .unwrap_or_else(|| panic!("nonempty modeled root required"))
        .root;
    if let Some(props) = props {
        let mut bytes = nodes[&root].clone();
        bytes[0] = 0xa3;
        bytes.push(3);
        bytes.extend(props);
        store_node(nodes, bytes)
    } else {
        root
    }
}

pub(super) fn check_cached_placement_and_limits() {
    // Branch-depth witnesses have valid individually canonical roots and no
    // unrelated malformed encoding. 64 graft hops remain legal; 65 fail.
    for depth in [63, 64] {
        let mut fixture = Fixture::empty();
        let mut child = store_node(&mut fixture.nodes, leaf(&[], None));
        for _ in 0..depth {
            child = store_node(
                &mut fixture.nodes,
                leaf(&[(b"g".to_vec(), graft(child))], None),
            );
        }
        fixture.owner_rows = vec![(b"g".to_vec(), graft(child))];
        fixture.rebuild_owner();
        // Outer owner contributes one hop; 64 is valid and 65 is rejected.
        if depth == 64 {
            assert_eq!(refused(fixture), ErrorKind::Invalid);
        } else {
            let store = ReadOnly::new(fixture.nodes);
            let raw = loaded(&store, fixture.owner);
            let source = raw
                .sources()
                .unwrap_or_else(|error| panic!("fixture failed: {error:?}"));
            assert!(raw.prepare(&source.trees).is_ok());
        }
    }
}
