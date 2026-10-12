//! Independently assembles source recurrences and containing auxiliary Nodes.
//!
//! Small reference trees fit one leaf; their wire models use integer fields
//! and maximal prefix compression directly, independently of production tree
//! and carrier encoders. Divergent witnesses are assembled as ordinary bytes.

#![allow(
    clippy::unwrap_used,
    reason = "independent test models must reproduce complete ordinary data"
)]

mod verification_work;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::IndexEvaluationRecipe;
use super::carrier::SemanticContext;
use super::evaluation::{self, Error, IndexData, Work};
use crate::cbor;
use crate::identity::{Digest, IdentityKind, TERRANE_V1};
use crate::tree_builder::Tree;
use crate::tree_format::{Attribute, ContentRef, Entry, EntryKind, LeafItem, TreeUse};

const MINIMUM: u64 = 262_144;
const ONE: Digest = [0x11; 32];
const TWO: Digest = [0x22; 32];
const THREE: Digest = [0x33; 32];

fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

fn node_id(bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(IdentityKind::Node, bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap()
}

fn file(object: Digest, value: Option<&[u8]>, manifest: bool) -> Entry<'_> {
    Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: if manifest { MINIMUM + 1 } else { 1 },
            content: if manifest {
                ContentRef::Manifest(object)
            } else {
                ContentRef::Inline(object)
            },
            link_id: None,
        },
        attrs: value
            .map(|value| alloc::vec![Attribute { name: "uid", value }])
            .unwrap_or_default(),
        attrs_present: value.is_some(),
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn graft(root: Digest) -> Entry<'static> {
    Entry {
        kind: EntryKind::Tree { root, props: None },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn leaf<'a>(key: &[u8], entry: Entry<'a>) -> LeafItem<'a> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

fn source_file_wire(object: Digest, value: Option<u8>, manifest: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, if value.is_some() { 5 } else { 4 });
    for (key, value) in [
        (1, 1),
        (2, 420),
        (3, if manifest { MINIMUM + 1 } else { 1 }),
    ] {
        cbor::write_uint(&mut bytes, key);
        cbor::write_uint(&mut bytes, value);
    }
    cbor::write_uint(&mut bytes, 4);
    cbor::write_array(&mut bytes, 2);
    cbor::write_uint(&mut bytes, u64::from(manifest));
    cbor::write_bytes(&mut bytes, &object);
    if let Some(value) = value {
        cbor::write_uint(&mut bytes, 9);
        cbor::write_map(&mut bytes, 1);
        cbor::write_text(&mut bytes, "uid");
        cbor::write_uint(&mut bytes, u64::from(value));
    }
    bytes
}

fn source_graft_wire(root: Digest) -> Vec<u8> {
    let mut bytes = alloc::vec![0xa2, 1, 4, 6];
    cbor::write_bytes(&mut bytes, &root);
    bytes
}

fn source_wire(entries: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut bytes = alloc::vec![0xa2, 1, 0, 2];
    cbor::write_array(&mut bytes, entries.len());
    let mut previous: &[u8] = &[];
    for (key, entry) in entries {
        let shared = previous
            .iter()
            .zip(*key)
            .take_while(|(left, right)| left == right)
            .count();
        cbor::write_array(&mut bytes, 3);
        cbor::write_bytes(&mut bytes, &key[shared..]);
        cbor::write_uint(&mut bytes, shared as u64);
        bytes.extend_from_slice(entry);
        previous = key;
    }
    bytes
}

fn sources() -> (Digest, BTreeMap<Digest, Tree<'static>>) {
    let child = Tree::build(
        alloc::vec![
            leaf(b"a", file(ONE, Some(b"\x01"), false)),
            leaf(b"b", file(ONE, None, false)),
            leaf(b"c", file(TWO, Some(b"\x02"), false)),
            leaf(b"d", file(THREE, None, true))
        ],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let child_wire = source_wire(&[
        (b"a", source_file_wire(ONE, Some(1), false)),
        (b"b", source_file_wire(ONE, None, false)),
        (b"c", source_file_wire(TWO, Some(2), false)),
        (b"d", source_file_wire(THREE, None, true)),
    ]);
    assert_eq!(child.root().encoded(), child_wire);
    let child_root = node_id(&child_wire);
    assert_eq!(child.root_identity(), child_root);
    let owner = Tree::build(
        alloc::vec![
            leaf(b"f", file(ONE, Some(b"\x01"), false)),
            leaf(b"g", graft(child_root)),
            leaf(b"h", graft(child_root)),
            leaf(b"m", file(ONE, None, false))
        ],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let owner_wire = source_wire(&[
        (b"f", source_file_wire(ONE, Some(1), false)),
        (b"g", source_graft_wire(child_root)),
        (b"h", source_graft_wire(child_root)),
        (b"m", source_file_wire(ONE, None, false)),
    ]);
    assert_eq!(owner.root().encoded(), owner_wire);
    let root = node_id(&owner_wire);
    assert_eq!(owner.root_identity(), root);
    (root, BTreeMap::from([(child_root, child), (root, owner)]))
}

#[derive(Clone)]
struct Row {
    key: Vec<u8>,
    object: Digest,
    pointer: Option<Vec<u8>>,
}

fn terminal(key: &[u8], object: Digest) -> Row {
    Row {
        key: key.to_vec(),
        object,
        pointer: None,
    }
}

fn forward(key: &[u8], object: Digest, route: Digest) -> Row {
    let mut value = Vec::new();
    cbor::write_bytes(&mut value, &route);
    Row {
        key: key.to_vec(),
        object,
        pointer: Some(value),
    }
}

// Direct integer-field assembly, including maximal prefix compression. This
// deliberately admits malformed rows that a production encoder would reject.
fn wire(rows: &[Row], gap: Option<Digest>) -> Vec<u8> {
    let mut out = Vec::new();
    cbor::write_map(&mut out, if gap.is_some() { 3 } else { 2 });
    cbor::write_uint(&mut out, 1);
    cbor::write_uint(&mut out, 0);
    cbor::write_uint(&mut out, 2);
    cbor::write_array(&mut out, rows.len());
    let mut previous: &[u8] = &[];
    for row in rows {
        let shared = previous
            .iter()
            .zip(&row.key)
            .take_while(|(left, right)| left == right)
            .count();
        cbor::write_array(&mut out, 3);
        cbor::write_bytes(&mut out, &row.key[shared..]);
        cbor::write_uint(&mut out, shared as u64);
        cbor::write_map(&mut out, if row.pointer.is_some() { 3 } else { 2 });
        cbor::write_uint(&mut out, 1);
        cbor::write_uint(&mut out, 7);
        if let Some(value) = &row.pointer {
            cbor::write_uint(&mut out, 9);
            cbor::write_map(&mut out, 1);
            cbor::write_text(&mut out, "index.occurrences");
            out.extend_from_slice(value);
        }
        cbor::write_uint(&mut out, 14);
        cbor::write_array(&mut out, 1);
        cbor::write_bytes(&mut out, &row.object);
        previous = &row.key;
    }
    if let Some(gap) = gap {
        cbor::write_uint(&mut out, 3);
        cbor::write_map(&mut out, 1);
        cbor::write_text(&mut out, "index-gaps");
        cbor::write_map(&mut out, 2);
        cbor::write_text(&mut out, "value");
        let hex: alloc::string::String = gap
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect();
        cbor::write_text(&mut out, &hex);
        cbor::write_text(&mut out, "inherit");
        out.push(0xf4);
    }
    out
}

fn add(nodes: &mut BTreeMap<Digest, Vec<u8>>, rows: &[Row], gap: Option<Digest>) -> Digest {
    let bytes = wire(rows, gap);
    let digest = node_id(&bytes);
    nodes.insert(digest, bytes);
    digest
}

fn primary_key(value: u8, object: Digest) -> Vec<u8> {
    let mut key = alloc::vec![value];
    key.extend_from_slice(&object);
    key
}

fn independent(mode: usize) -> IndexData {
    let mut nodes = BTreeMap::new();
    let mut child_one_rows = alloc::vec![terminal(b"a", ONE)];
    match mode {
        3 => child_one_rows.push(terminal(b"c", ONE)), // Extra terminal.
        4 => child_one_rows[0].object = TWO,
        5 => child_one_rows.clear(),
        6 => child_one_rows[0].pointer = Some(alloc::vec![0x00]),
        _ => {}
    }
    let child_one = add(&mut nodes, &child_one_rows, None);
    let child_two = add(&mut nodes, &[terminal(b"c", TWO)], None);
    let child_missing_one = add(&mut nodes, &[terminal(b"b", ONE)], None);
    let child_missing_three = add(&mut nodes, &[terminal(b"d", THREE)], None);
    let mut owner_one_rows = alloc::vec![
        terminal(b"f", ONE),
        forward(b"g", ONE, child_one),
        forward(b"h", ONE, child_one)
    ];
    if mode == 7 {
        owner_one_rows.remove(2);
    }
    if mode == 8 {
        owner_one_rows[1] = forward(b"g", ONE, child_missing_one);
    }
    let owner_one = add(&mut nodes, &owner_one_rows, None);
    let owner_two = add(
        &mut nodes,
        &[forward(b"g", TWO, child_two), forward(b"h", TWO, child_two)],
        None,
    );
    let owner_missing_one = add(
        &mut nodes,
        &[
            forward(b"g", ONE, child_missing_one),
            forward(b"h", ONE, child_missing_one),
            terminal(b"m", ONE),
        ],
        None,
    );
    let owner_missing_three = add(
        &mut nodes,
        &[
            forward(b"g", THREE, child_missing_three),
            forward(b"h", THREE, child_missing_three),
        ],
        None,
    );
    let mut gaps = alloc::vec![
        forward(&ONE, ONE, owner_missing_one),
        forward(&THREE, THREE, owner_missing_three)
    ];
    if mode == 2 {
        gaps.pop();
    }
    if mode == 9 {
        gaps.insert(1, forward(&TWO, TWO, owner_two));
    }
    let gap = add(&mut nodes, &gaps, None);
    let mut primary = alloc::vec![
        forward(&primary_key(1, ONE), ONE, owner_one),
        forward(&primary_key(2, TWO), TWO, owner_two)
    ];
    if mode == 1 {
        primary.pop();
    }
    if mode == 10 {
        primary[0].key[0] = 0;
    }
    let root = add(
        &mut nodes,
        &primary,
        if mode == 11 { None } else { Some(gap) },
    );
    IndexData {
        root,
        nodes,
        work: Work::default(),
    }
}

#[test]
fn hierarchical_index_matches_independent_source_occurrences() {
    let (owner, graph) = sources();
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let expected = independent(0);
    let constructed = evaluation::construct(&recipe, &graph, MINIMUM, context()).unwrap();
    assert_eq!(constructed.root, expected.root);
    assert_eq!(constructed.nodes, expected.nodes);
    let checked = evaluation::verify(&recipe, &graph, MINIMUM, context(), &expected).unwrap();
    assert_eq!(checked.candidates, 2);
    assert_eq!(checked.missing_objects, 2);
    assert!(constructed.work.source_roots > graph.len());
    assert_eq!(checked.work.source_roots, 3);
    assert_eq!(checked.work.source_entries, 12);
    assert!(checked.work.rows > 0);

    // Source recurrence keeps both graft occurrences despite shared child bytes.
    let one_child = wire(&[terminal(b"a", ONE)], None);
    assert!(expected.nodes.values().any(|bytes| bytes == &one_child));
    let one_route = wire(
        &[
            terminal(b"f", ONE),
            forward(b"g", ONE, node_id(&one_child)),
            forward(b"h", ONE, node_id(&one_child)),
        ],
        None,
    );
    assert!(expected.nodes.values().any(|bytes| bytes == &one_route));
}

#[test]
fn verification_rejects_divergent_rows_routes_and_gaps() {
    verification_work::prove_physical_work();
    let (owner, graph) = sources();
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    for mode in 1..=11 {
        assert!(
            evaluation::verify(&recipe, &graph, MINIMUM, context(), &independent(mode)).is_err(),
            "divergent independently assembled model {mode}"
        );
    }
    let mut corrupted = independent(0);
    corrupted.nodes.get_mut(&corrupted.root).unwrap()[0] = 0xa2;
    assert!(evaluation::verify(&recipe, &graph, MINIMUM, context(), &corrupted).is_err());
    let mut absent = independent(0);
    absent.nodes.remove(&absent.root);
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &absent),
        Err(Error::MissingNode)
    );
    let mut extra = independent(0);
    extra
        .nodes
        .insert([0xff; 32], alloc::vec![0xa2, 1, 0, 2, 0x80]);
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &extra),
        Err(Error::Relationship)
    );
}

#[test]
fn role_contexts_preserve_shared_nodes_without_false_authority() {
    let empty = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Ordinary).unwrap();
    let index = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Index).unwrap();
    assert_eq!(empty.root_identity(), index.root_identity());
    assert_eq!(empty.root().encoded(), b"\xa2\x01\x00\x02\x80");
    let published: Vec<u8> = "c44cf1c82cbfde695a0110c9a7192bf3692f0d16c96871623f8b540acd439b81"
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect();
    assert_eq!(empty.root_identity().as_slice(), published);

    let recipe = IndexEvaluationRecipe::new(empty.root_identity(), "uid").unwrap();
    let graph = BTreeMap::from([(empty.root_identity(), empty.clone())]);
    let data = evaluation::construct(&recipe, &graph, MINIMUM, context()).unwrap();
    assert_eq!(data.root, empty.root_identity());
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &data)
            .unwrap()
            .candidates,
        0
    );
    let wrong_use = BTreeMap::from([(index.root_identity(), index)]);
    assert_eq!(
        evaluation::construct(&recipe, &wrong_use, MINIMUM, context()),
        Err(Error::Source)
    );
    assert_eq!(
        evaluation::construct(&recipe, &graph, MINIMUM + 1, context()),
        Err(Error::Source)
    );
    let wrong_key = BTreeMap::from([([0xff; 32], empty)]);
    assert_eq!(
        evaluation::construct(&recipe, &wrong_key, MINIMUM, context()),
        Err(Error::MissingSource)
    );
}

#[test]
fn generated_missing_inline_coverage_is_independent_of_candidate_count() {
    for count in 0..12 {
        let mut entries = Vec::new();
        let mut expected_route = Vec::new();
        for position in 0..count {
            let key = alloc::format!("file-{position:02}").into_bytes();
            entries.push(leaf(&key, file(ONE, None, false)));
            expected_route.push(terminal(&key, ONE));
        }
        let source = Tree::build(entries, None, MINIMUM, TreeUse::Ordinary).unwrap();
        let owner = source.root_identity();
        let graph = BTreeMap::from([(owner, source)]);
        let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
        let mut nodes = BTreeMap::new();
        let gap = if count == 0 {
            None
        } else {
            let route = add(&mut nodes, &expected_route, None);
            Some(add(&mut nodes, &[forward(&ONE, ONE, route)], None))
        };
        let root = add(&mut nodes, &[], gap);
        let model = IndexData {
            root,
            nodes,
            work: Work::default(),
        };
        let actual = evaluation::construct(&recipe, &graph, MINIMUM, context()).unwrap();
        assert_eq!(actual.root, model.root);
        assert_eq!(actual.nodes, model.nodes);
        let checked = evaluation::verify(&recipe, &graph, MINIMUM, context(), &model).unwrap();
        assert_eq!(checked.candidates, 0);
        assert_eq!(checked.missing_objects, usize::from(count != 0));
        if count != 0 {
            let bytes = wire(&[], None);
            let absent = IndexData {
                root: node_id(&bytes),
                nodes: BTreeMap::from([(node_id(&bytes), bytes)]),
                work: Work::default(),
            };
            assert!(evaluation::verify(&recipe, &graph, MINIMUM, context(), &absent).is_err());
        }
    }
}

#[test]
fn hierarchical_local_keys_do_not_flatten_long_graft_paths() {
    let key = alloc::vec![b'a'; 255];
    let bottom = Tree::build(
        alloc::vec![leaf(&key, file(ONE, Some(b"\x01"), false))],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let mut root = bottom.root_identity();
    let mut graph = BTreeMap::from([(root, bottom)]);
    for depth in 1..=65 {
        let parent = Tree::build(
            alloc::vec![leaf(&key, graft(root))],
            None,
            MINIMUM,
            TreeUse::Ordinary,
        )
        .unwrap();
        root = parent.root_identity();
        graph.insert(root, parent);
        if depth == 20 || depth == 64 {
            let recipe = IndexEvaluationRecipe::new(root, "uid").unwrap();
            let actual = evaluation::construct(&recipe, &graph, MINIMUM, context()).unwrap();
            let checked = evaluation::verify(&recipe, &graph, MINIMUM, context(), &actual).unwrap();
            assert_eq!(checked.candidates, 1);
            let mut nodes = BTreeMap::new();
            let mut route = add(&mut nodes, &[terminal(&key, ONE)], None);
            for _ in 0..depth {
                route = add(&mut nodes, &[forward(&key, ONE, route)], None);
            }
            let expected = add(
                &mut nodes,
                &[forward(&primary_key(1, ONE), ONE, route)],
                None,
            );
            assert_eq!(actual.root, expected);
            assert_eq!(actual.nodes, nodes);
        }
    }
    let recipe = IndexEvaluationRecipe::new(root, "uid").unwrap();
    assert_eq!(
        evaluation::construct(&recipe, &graph, MINIMUM, context()),
        Err(Error::Limit)
    );
}

#[test]
fn conditional_sources_remain_incomplete_and_canonical_layers_are_indexed() {
    let mut entry = file(ONE, None, false);
    entry.kind = EntryKind::Conflict {
        candidates: alloc::vec![file(ONE, None, false), file(TWO, Some(b"\x02"), false)],
        base: None,
    };
    let conditional = Tree::build(
        alloc::vec![leaf(b"conditional", entry)],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let root = conditional.root_identity();
    let graph = BTreeMap::from([(root, conditional)]);
    let recipe = IndexEvaluationRecipe::new(root, "uid").unwrap();
    assert_eq!(
        evaluation::construct(&recipe, &graph, MINIMUM, context()),
        Err(Error::Incomplete)
    );
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &independent(0)),
        Err(Error::Incomplete)
    );

    let mut entry = graft([0; 32]);
    entry.kind = EntryKind::Whiteout;
    let overlay = Tree::build(
        alloc::vec![leaf(b"removed", entry)],
        None,
        MINIMUM,
        TreeUse::OverlayLayer,
    )
    .unwrap();
    let root = overlay.root_identity();
    let graph = BTreeMap::from([(root, overlay)]);
    let recipe = IndexEvaluationRecipe::new(root, "uid").unwrap();
    let actual = evaluation::construct(&recipe, &graph, MINIMUM, context()).unwrap();
    let empty = Tree::build(Vec::new(), None, MINIMUM, TreeUse::Index).unwrap();
    assert_eq!(actual.root, empty.root_identity());
    assert_eq!(actual.nodes.len(), 1);
    assert_eq!(actual.nodes[&actual.root], empty.root().encoded());
    let checked = evaluation::verify(&recipe, &graph, MINIMUM, context(), &actual).unwrap();
    assert_eq!(checked.candidates, 0);
    assert_eq!(checked.missing_objects, 0);
}

#[test]
fn source_geometry_identities_and_registered_value_types_are_checked() {
    let source = Tree::build(
        alloc::vec![leaf(b"a", file(ONE, Some(b"\x01"), false))],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let wrong = [0xff; 32];
    let recipe = IndexEvaluationRecipe::new(wrong, "uid").unwrap();
    assert_eq!(
        evaluation::construct(
            &recipe,
            &BTreeMap::from([(wrong, source)]),
            MINIMUM,
            context()
        ),
        Err(Error::Source)
    );

    let mut invalid = file(ONE, None, false);
    invalid.attrs = alloc::vec![Attribute {
        name: "hash.sha256",
        value: b"\x01"
    }];
    invalid.attrs_present = true;
    let source = Tree::build(
        alloc::vec![leaf(b"a", invalid)],
        None,
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let root = source.root_identity();
    let recipe = IndexEvaluationRecipe::new(root, "hash.sha256").unwrap();
    assert!(matches!(
        evaluation::construct(
            &recipe,
            &BTreeMap::from([(root, source)]),
            MINIMUM,
            context()
        ),
        Err(Error::Attribute(_))
    ));
}

#[test]
fn canonical_internal_routes_check_child_summaries_and_boundaries() {
    let entries = (0..3000)
        .map(|position| {
            leaf(
                alloc::format!("file-{position:04}").as_bytes(),
                file(ONE, Some(b"\x01"), false),
            )
        })
        .collect();
    let source = Tree::build(entries, None, MINIMUM, TreeUse::Ordinary).unwrap();
    assert!(source.root().level() > 0);
    let owner = source.root_identity();
    let graph = BTreeMap::from([(owner, source)]);
    let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
    let mut data = evaluation::construct(&recipe, &graph, MINIMUM, context()).unwrap();
    let checked = evaluation::verify(&recipe, &graph, MINIMUM, context(), &data).unwrap();
    assert_eq!(checked.candidates, 1);
    assert_eq!(checked.missing_objects, 0);

    let primary_bytes = data.nodes.get(&data.root).unwrap().clone();
    let primary =
        crate::tree_format::decode_node_for(&primary_bytes, true, MINIMUM, TreeUse::Index).unwrap();
    let crate::tree_format::NodeItems::Leaf(items) = primary.items else {
        panic!("one candidate has a leaf primary");
    };
    let route = super::carrier::validate_row(
        context(),
        super::carrier::Role::Primary,
        &items[0].key,
        &items[0].entry,
    )
    .unwrap()
    .route()
    .unwrap();
    let route_bytes = data.nodes.get(&route).unwrap().clone();
    let node =
        crate::tree_format::decode_node_for(&route_bytes, true, MINIMUM, TreeUse::Index).unwrap();
    let crate::tree_format::NodeItems::Internal(references) = node.items else {
        panic!("3000 occurrences require internal routes");
    };

    // Assemble a valid canonical map with a dishonest subtree count, outside
    // the builder's immutable StoredNode constructor and its summary checks.
    let mut malformed = alloc::vec![0xa2, 1];
    cbor::write_uint(&mut malformed, u64::from(node.level));
    cbor::write_uint(&mut malformed, 2);
    cbor::write_array(&mut malformed, references.len());
    for (position, reference) in references.iter().enumerate() {
        cbor::write_array(&mut malformed, 4);
        cbor::write_bytes(&mut malformed, &reference.last_key);
        cbor::write_bytes(&mut malformed, &reference.child);
        cbor::write_uint(&mut malformed, reference.count + u64::from(position == 0));
        cbor::write_uint(&mut malformed, reference.weight);
    }
    let bad_route = node_id(&malformed);
    data.nodes.remove(&route);
    data.nodes.insert(bad_route, malformed);
    data.nodes.remove(&data.root);
    data.root = add(
        &mut data.nodes,
        &[forward(&primary_key(1, ONE), ONE, bad_route)],
        None,
    );
    assert_eq!(
        evaluation::verify(&recipe, &graph, MINIMUM, context(), &data),
        Err(Error::Relationship)
    );
}

#[test]
fn verification_enumerates_each_occurrence_once_as_predicates_grow() {
    for population in [8_u8, 16, 24] {
        for missing_only in [false, true] {
            let mut entries = Vec::new();
            let mut nodes = BTreeMap::new();
            let mut primary = Vec::new();
            let mut gaps = Vec::new();
            for number in 0..population {
                let object = [number; 32];
                let key = alloc::format!("f-{number:03}").into_bytes();
                let missing = missing_only || number % 2 == 0;
                entries.push(leaf(
                    &key,
                    file(object, if missing { None } else { Some(b"\x01") }, false),
                ));
                let child_route = add(&mut nodes, &[terminal(&key, object)], None);
                let owner_route = add(
                    &mut nodes,
                    &[
                        forward(b"g", object, child_route),
                        forward(b"h", object, child_route),
                    ],
                    None,
                );
                if missing {
                    gaps.push(forward(&object, object, owner_route));
                } else {
                    primary.push(forward(&primary_key(1, object), object, owner_route));
                }
            }
            let child = Tree::build(entries, None, MINIMUM, TreeUse::Ordinary).unwrap();
            let child_root = child.root_identity();
            let owner_tree = Tree::build(
                alloc::vec![leaf(b"g", graft(child_root)), leaf(b"h", graft(child_root))],
                None,
                MINIMUM,
                TreeUse::Ordinary,
            )
            .unwrap();
            let owner = owner_tree.root_identity();
            let graph = BTreeMap::from([(child_root, child), (owner, owner_tree)]);
            let gap = add(&mut nodes, &gaps, None);
            let root = add(&mut nodes, &primary, Some(gap));
            let data = IndexData {
                root,
                nodes,
                work: Work::default(),
            };
            let recipe = IndexEvaluationRecipe::new(owner, "uid").unwrap();
            let checked = evaluation::verify(&recipe, &graph, MINIMUM, context(), &data).unwrap();
            assert_eq!(checked.candidates, primary.len());
            assert_eq!(checked.missing_objects, gaps.len());
            assert_eq!(checked.work.source_roots, 3);
            assert_eq!(checked.work.source_entries, 2 + 2 * usize::from(population));
            assert_eq!(
                checked.physical_work.reconstructions.len(),
                2 + 3 * usize::from(population)
            );
            let built = evaluation::construct(&recipe, &graph, MINIMUM, context()).unwrap();
            assert_eq!(built.root, data.root);
            assert_eq!(built.nodes, data.nodes);

            // A validly hashed but incomplete route must refuse even when the
            // primary has zero candidates and only missing-value evidence exists.
            let mut omitted = data.clone();
            omitted.nodes.remove(&data.root);
            omitted.nodes.remove(&gap);
            let object = [0; 32];
            let child_route = add(&mut omitted.nodes, &[terminal(b"f-000", object)], None);
            let original_owner_route = node_id(&wire(
                &[
                    forward(b"g", object, child_route),
                    forward(b"h", object, child_route),
                ],
                None,
            ));
            omitted.nodes.remove(&original_owner_route);
            let owner_route = add(
                &mut omitted.nodes,
                &[forward(b"g", object, child_route)],
                None,
            );
            let mut altered_gaps = gaps.clone();
            altered_gaps[0] = forward(&object, object, owner_route);
            let gap = add(&mut omitted.nodes, &altered_gaps, None);
            omitted.root = add(&mut omitted.nodes, &primary, Some(gap));
            assert_eq!(
                evaluation::verify(&recipe, &graph, MINIMUM, context(), &omitted),
                Err(Error::Relationship)
            );

            let mut omitted_gap = data.clone();
            omitted_gap.nodes.remove(&data.root);
            omitted_gap.nodes.remove(&node_id(&wire(&gaps, None)));
            omitted_gap.nodes.remove(&original_owner_route);
            omitted_gap.nodes.remove(&child_route);
            let gap = add(&mut omitted_gap.nodes, &gaps[1..], None);
            omitted_gap.root = add(&mut omitted_gap.nodes, &primary, Some(gap));
            assert_eq!(
                evaluation::verify(&recipe, &graph, MINIMUM, context(), &omitted_gap),
                Err(Error::Relationship)
            );
        }
    }
}
