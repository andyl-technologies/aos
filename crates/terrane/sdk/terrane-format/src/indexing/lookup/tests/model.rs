//! Assembles independent literal rows, source fixtures and raw malformed Nodes.

use super::*;

/// Sets the chunk minimum for lookup fixture Trees.
pub(super) const MINIMUM: u64 = 262_144;
/// Names the fixture object with both present and missing occurrences.
pub(super) const ONE: Digest = [0x11; 32];
/// Names the distinct fixture object with a present value.
pub(super) const TWO: Digest = [0x22; 32];
/// Names the fixture Manifest object with missing values.
pub(super) const THREE: Digest = [0x33; 32];

/// Constructs the active fixture semantic revision tuple.
///
/// # Panics
/// Panics if the fixed fixture tuple becomes unsupported.
pub(super) fn context() -> SemanticContext {
    SemanticContext::new(3, 2, 1).unwrap()
}

/// Calculates the Node identity of independently assembled fixture bytes.
///
/// # Panics
/// Panics if the registered identity calculation or v1 digest conversion fails.
pub(super) fn id(bytes: &[u8]) -> Digest {
    TERRANE_V1
        .calculate(IdentityKind::Node, bytes)
        .unwrap()
        .terrane_v1_digest()
        .unwrap()
}

/// Builds a fixture file with optional inline attribute and selected content tag.
pub(super) fn file<'a>(
    object: Digest,
    value: Option<&'a [u8]>,
    attribute: &'a str,
    manifest: bool,
) -> Entry<'a> {
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
            .map(|value| {
                alloc::vec![Attribute {
                    name: attribute,
                    value
                }]
            })
            .unwrap_or_default(),
        attrs_present: value.is_some(),
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

/// Builds a bare fixture graft to the supplied root.
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

/// Copies a local key into a leaf containing the supplied fixture entry.
pub(super) fn leaf<'a>(key: &[u8], entry: Entry<'a>) -> LeafItem<'a> {
    LeafItem {
        key: key.to_vec(),
        entry,
    }
}

/// Builds an ordinary fixture Tree without root properties.
///
/// # Panics
/// Panics if the supplied rows fail Tree validation or resource limits.
pub(super) fn tree(rows: Vec<LeafItem<'_>>) -> Tree<'_> {
    Tree::build(rows, None, MINIMUM, TreeUse::Ordinary).unwrap()
}

/// Holds a literal terminal or forwarding index row for wire assembly.
#[derive(Clone)]
pub(super) struct ModelRow {
    /// Complete local row key, including any primary object suffix.
    pub(super) key: Vec<u8>,
    /// Sole object target carried by the specialized row.
    pub(super) object: Digest,
    /// Continuation Node identity, absent for a terminal occurrence.
    pub(super) route: Option<Digest>,
}

/// Builds a literal terminal row with one object target.
pub(super) fn terminal(key: &[u8], object: Digest) -> ModelRow {
    ModelRow {
        key: key.to_vec(),
        object,
        route: None,
    }
}

/// Builds a literal forwarding row with one object and continuation.
pub(super) fn forward(key: &[u8], object: Digest, route: Digest) -> ModelRow {
    ModelRow {
        key: key.to_vec(),
        object,
        route: Some(route),
    }
}

/// Concatenates canonical value bytes and the object digest without validation.
pub(super) fn value_key(value: &[u8], object: Digest) -> Vec<u8> {
    let mut key = value.to_vec();
    key.extend_from_slice(&object);
    key
}

// Integer fields and prefix compression are independent of carrier validation.
/// Assembles a prefix-compressed leaf Node and optional noninherited gap binding.
pub(super) fn wire(rows: &[ModelRow], gap: Option<Digest>) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, if gap.is_some() { 3 } else { 2 });
    cbor::write_uint(&mut bytes, 1);
    cbor::write_uint(&mut bytes, 0);
    cbor::write_uint(&mut bytes, 2);
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
        cbor::write_map(&mut bytes, if row.route.is_some() { 3 } else { 2 });
        cbor::write_uint(&mut bytes, 1);
        cbor::write_uint(&mut bytes, 7);
        if let Some(route) = row.route {
            cbor::write_uint(&mut bytes, 9);
            cbor::write_map(&mut bytes, 1);
            cbor::write_text(&mut bytes, "index.occurrences");
            cbor::write_bytes(&mut bytes, &route);
        }
        cbor::write_uint(&mut bytes, 14);
        cbor::write_array(&mut bytes, 1);
        cbor::write_bytes(&mut bytes, &row.object);
        previous = &row.key;
    }
    if let Some(gap) = gap {
        cbor::write_uint(&mut bytes, 3);
        cbor::write_map(&mut bytes, 1);
        cbor::write_text(&mut bytes, "index-gaps");
        cbor::write_map(&mut bytes, 2);
        cbor::write_text(&mut bytes, "value");
        let hex: alloc::string::String = gap
            .iter()
            .map(|byte| alloc::format!("{byte:02x}"))
            .collect();
        cbor::write_text(&mut bytes, &hex);
        cbor::write_text(&mut bytes, "inherit");
        bytes.push(0xf4);
    }
    bytes
}

/// Assembles and stores a literal leaf Node, returning its identity.
///
/// # Panics
/// Panics if the registered Node identity calculation fails.
pub(super) fn add(
    nodes: &mut BTreeMap<Digest, Vec<u8>>,
    rows: &[ModelRow],
    gap: Option<Digest>,
) -> Digest {
    let bytes = wire(rows, gap);
    let root = id(&bytes);
    nodes.insert(root, bytes);
    root
}

/// Builds the literal primary/route/gap closure and returns selected route roots.
///
/// # Panics
/// Panics if fixture Node identity calculation fails.
pub(super) fn model() -> (IndexData, Digest, Digest, Digest) {
    let mut nodes = BTreeMap::new();
    let child_present = add(&mut nodes, &[terminal(b"a", ONE)], None);
    let child_missing = add(&mut nodes, &[terminal(b"b", ONE)], None);
    let child_other = add(&mut nodes, &[terminal(b"c", TWO)], None);
    let child_manifest = add(&mut nodes, &[terminal(b"d", THREE)], None);
    let present = add(
        &mut nodes,
        &[
            terminal(b"f", ONE),
            forward(b"g", ONE, child_present),
            forward(b"h", ONE, child_present),
        ],
        None,
    );
    let missing = add(
        &mut nodes,
        &[
            forward(b"g", ONE, child_missing),
            forward(b"h", ONE, child_missing),
            terminal(b"m", ONE),
        ],
        None,
    );
    let other = add(
        &mut nodes,
        &[
            forward(b"g", TWO, child_other),
            forward(b"h", TWO, child_other),
        ],
        None,
    );
    let manifest = add(
        &mut nodes,
        &[
            forward(b"g", THREE, child_manifest),
            forward(b"h", THREE, child_manifest),
        ],
        None,
    );
    let gap = add(
        &mut nodes,
        &[
            forward(&ONE, ONE, missing),
            forward(&THREE, THREE, manifest),
        ],
        None,
    );
    let root = add(
        &mut nodes,
        &[
            forward(&value_key(b"\x01", ONE), ONE, present),
            forward(&value_key(b"\x02", TWO), TWO, other),
        ],
        Some(gap),
    );
    (
        IndexData {
            root,
            nodes,
            work: evaluation::Work::default(),
        },
        present,
        missing,
        gap,
    )
}

/// Builds the matching repeated-graft source graph and owner identity.
///
/// # Panics
/// Panics if the fixed namespace rows fail Tree construction.
pub(super) fn sources() -> (Digest, BTreeMap<Digest, Tree<'static>>) {
    let child = tree(alloc::vec![
        leaf(b"a", file(ONE, Some(b"\x01"), "uid", false)),
        leaf(b"b", file(ONE, None, "uid", false)),
        leaf(b"c", file(TWO, Some(b"\x02"), "uid", false)),
        leaf(b"d", file(THREE, None, "uid", true))
    ]);
    let child_root = child.root_identity();
    let owner = tree(alloc::vec![
        leaf(b"f", file(ONE, Some(b"\x01"), "uid", false)),
        leaf(b"g", graft(child_root)),
        leaf(b"h", graft(child_root)),
        leaf(b"m", file(ONE, None, "uid", false))
    ]);
    let root = owner.root_identity();
    (root, BTreeMap::from([(root, owner), (child_root, child)]))
}

/// Encodes a validated owner-local binding for one selected attribute.
///
/// # Panics
/// Panics if the attribute is unregistered or binding validation/encoding fails.
pub(super) fn binding(attribute: &str, root: Digest) -> Vec<u8> {
    let hex: alloc::string::String = root
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect();
    let mut bytes = Vec::new();
    cbor::write_map(&mut bytes, 1);
    cbor::write_text(&mut bytes, attribute);
    cbor::write_text(&mut bytes, &hex);
    IndexRoots::decode_value(&bytes)
        .unwrap()
        .encode_binding()
        .unwrap()
}

/// Rebuilds the fixture owner with a supplied index-roots payload in a cloned graph.
///
/// # Panics
/// Panics if the old owner is absent or the replacement Tree cannot be built.
pub(super) fn bind<'a>(
    old: Digest,
    original: &BTreeMap<Digest, Tree<'a>>,
    bytes: &'a [u8],
) -> (Digest, BTreeMap<Digest, Tree<'a>>) {
    let rows = original[&old].iter().cloned().collect();
    let owner = Tree::build(
        rows,
        Some(alloc::vec![Property {
            name: "index-roots",
            value: bytes
        }]),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap();
    let root = owner.root_identity();
    let mut trees = original.clone();
    trees.remove(&old);
    trees.insert(root, owner);
    (root, trees)
}
