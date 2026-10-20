//! Assembles raw canonical recipes, Memo records and complete output inventories.
//!
//! Expected outputs use literal rows and independently hashed addresses. No
//! common replay, algebra materialization or index construction builds an oracle.
//!
//! The helpers frame these canonical schema shapes directly:
//! ```text
//! Memo = {1: recipe-digest32, 2: result-node32}
//! recipe = {1: operation, 2: [operand-node32, ...], ? 3: arguments}
//! leaf = {1: 0, 2: [[key-suffix, shared-prefix, entry], ...], ? 3: properties}
//! ```

use super::*;
use terrane_format::cbor;
use terrane_format::tree_format::{NodeItems, TreeUse, decode_node_for};

/// Defines the native fixture geometry from the registered CDC-1M minimum.
pub(super) const MINIMUM: u64 = terrane_format::chunking::CDC_1M_MIN as u64;
const OBJECT: Digest = [7; 32];
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Hashes literal fixture bytes with an explicit domain and zero separator.
pub(super) fn hash(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut input = domain.to_vec();
    input.push(0);
    input.extend_from_slice(bytes);
    *blake3::hash(&input).as_bytes()
}

/// Frames the two digest fields of a common Memo directly from its schema.
pub(super) fn memo(key: Digest, result: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1];
    cbor::write_bytes(&mut bytes, &key);
    bytes.push(2);
    cbor::write_bytes(&mut bytes, &result);
    bytes
}

fn symlink(target: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 3, 5];
    cbor::write_bytes(&mut bytes, target);
    bytes
}

fn graft(root: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 4, 6];
    cbor::write_bytes(&mut bytes, &root);
    bytes
}

fn file(present: bool) -> Vec<u8> {
    let mut bytes = vec![if present { 0xa5 } else { 0xa4 }, 1, 1, 2];
    cbor::write_uint(&mut bytes, 0o644);
    bytes.extend_from_slice(&[3, 1, 4, 0x82, 0]);
    cbor::write_bytes(&mut bytes, &OBJECT);
    if present {
        bytes.extend_from_slice(&[9, 0xa1]);
        cbor::write_text(&mut bytes, "uid");
        bytes.push(1);
    }
    bytes
}

fn terminal() -> Vec<u8> {
    let mut bytes = vec![0xa2, 1, 7, 14, 0x81];
    cbor::write_bytes(&mut bytes, &OBJECT);
    bytes
}

fn forward(route: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa3, 1, 7, 9, 0xa1];
    cbor::write_text(&mut bytes, "index.occurrences");
    cbor::write_bytes(&mut bytes, &route);
    bytes.extend_from_slice(&[14, 0x81]);
    cbor::write_bytes(&mut bytes, &OBJECT);
    bytes
}

fn pointer(bytes: &mut Vec<u8>, digest: Digest) {
    bytes.push(0xa2);
    cbor::write_text(bytes, "value");
    cbor::write_text(
        bytes,
        &digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    cbor::write_text(bytes, "inherit");
    bytes.push(0xf4);
}

fn namespace_properties(primary: Option<Digest>) -> Vec<u8> {
    let mut bytes = vec![if primary.is_some() { 0xa2 } else { 0xa1 }];
    cbor::write_text(&mut bytes, "domain");
    cbor::write_text(&mut bytes, "private:memo-test");
    if let Some(primary) = primary {
        cbor::write_text(&mut bytes, "index-roots");
        bytes.push(0xa2);
        cbor::write_text(&mut bytes, "value");
        bytes.push(0xa1);
        cbor::write_text(&mut bytes, "uid");
        cbor::write_text(
            &mut bytes,
            &primary
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        cbor::write_text(&mut bytes, "inherit");
        bytes.push(0xf4);
    }
    bytes
}

fn gap_properties(gap: Digest) -> Vec<u8> {
    let mut bytes = vec![0xa1];
    cbor::write_text(&mut bytes, "index-gaps");
    pointer(&mut bytes, gap);
    bytes
}

/// Frames a leaf Node with compressed key prefixes and optional raw properties.
pub(super) fn leaf(rows: &Rows, props: Option<Vec<u8>>) -> Vec<u8> {
    let mut bytes = vec![if props.is_some() { 0xa3 } else { 0xa2 }, 1, 0, 2];
    cbor::write_array(&mut bytes, rows.len());
    let mut prior: &[u8] = &[];
    for (key, entry) in rows {
        let shared = key.iter().zip(prior).take_while(|(a, b)| a == b).count();
        bytes.push(0x83);
        cbor::write_bytes(&mut bytes, &key[shared..]);
        cbor::write_uint(&mut bytes, shared as u64);
        bytes.extend_from_slice(entry);
        prior = key;
    }
    if let Some(props) = props {
        bytes.push(3);
        bytes.extend(props);
    }
    bytes
}

fn namespace(rows: Rows) -> Vec<u8> {
    leaf(&rows, Some(namespace_properties(None)))
}

fn node(bytes: Vec<u8>, nodes: &mut BTreeMap<Digest, Vec<u8>>) -> Digest {
    let digest = hash(b"terrane-node-v1", &bytes);
    nodes.insert(digest, bytes);
    digest
}

/// Frames an ordered root recipe with optional raw operation arguments.
pub(super) fn recipe(operation: &str, roots: &[Digest], args: Option<Vec<u8>>) -> Vec<u8> {
    let mut bytes = vec![if args.is_some() { 0xa3 } else { 0xa2 }, 1];
    cbor::write_text(&mut bytes, operation);
    bytes.push(2);
    cbor::write_array(&mut bytes, roots.len());
    for root in roots {
        cbor::write_bytes(&mut bytes, root);
    }
    if let Some(args) = args {
        bytes.push(3);
        bytes.extend(args);
    }
    bytes
}

/// Frames the closed profile and uid-attribute arguments for an index recipe.
pub(super) fn index_args(profile: &str) -> Vec<u8> {
    let mut args = vec![0xa2];
    cbor::write_text(&mut args, "profile");
    cbor::write_text(&mut args, profile);
    cbor::write_text(&mut args, "attribute");
    cbor::write_text(&mut args, "uid");
    args
}

/// Retains raw operands and independently expected recipe output bytes.
///
/// Expected Nodes are framed directly rather than produced by common replay or
/// by the owning algebra and index evaluators.
pub(super) struct Fixture {
    /// Canonical namespace operand bytes indexed by independently hashed roots.
    pub source: BTreeMap<Digest, Vec<u8>>,
    /// Operand roots that require overlay-layer interpretation.
    pub overlay: BTreeSet<Digest>,
    /// Original canonical recipe bytes whose hash is the lookup key.
    pub recipe: Vec<u8>,
    /// First ordered operand used to predict typed mandatory-input failures.
    pub first_operand: Digest,
    /// Independently expected resulting Node identity.
    pub root: Digest,
    /// Complete independently framed output Node closure.
    pub output: BTreeMap<Digest, Vec<u8>>,
}

impl Fixture {
    /// Builds a graft fixture with two output occurrences of the same child.
    ///
    /// # Panics
    /// Panics if the fixed child operand is absent from the raw source map.
    pub fn graft() -> Self {
        let mut source = BTreeMap::new();
        let child = node(
            namespace(vec![(b"inside".to_vec(), symlink(b"target"))]),
            &mut source,
        );
        let parent = node(
            namespace(vec![
                (b"first".to_vec(), graft(child)),
                (b"second".to_vec(), symlink(b"old")),
            ]),
            &mut source,
        );
        let mut output = BTreeMap::from([(child, source[&child].clone())]);
        let root = node(
            namespace(vec![
                (b"first".to_vec(), graft(child)),
                (b"second".to_vec(), graft(child)),
            ]),
            &mut output,
        );
        let mut args = vec![0xa3];
        cbor::write_text(&mut args, "at");
        cbor::write_bytes(&mut args, b"second");
        cbor::write_text(&mut args, "entry");
        cbor::write_bytes(&mut args, &graft(child));
        cbor::write_text(&mut args, "replace");
        args.push(0xf4);
        Self {
            source,
            overlay: BTreeSet::new(),
            recipe: recipe("graft", &[parent, child], Some(args)),
            first_operand: parent,
            root,
            output,
        }
    }

    /// Builds an ordered whiteout overlay with independently framed resulting rows.
    pub fn overlay() -> Self {
        let mut source = BTreeMap::new();
        let bottom = node(
            namespace(vec![
                (b"hidden".to_vec(), symlink(b"bottom")),
                (b"same".to_vec(), symlink(b"bottom")),
                (b"stay".to_vec(), symlink(b"bottom")),
            ]),
            &mut source,
        );
        let top = node(
            namespace(vec![
                (b"hidden".to_vec(), vec![0xa1, 1, 5]),
                (b"same".to_vec(), symlink(b"top")),
            ]),
            &mut source,
        );
        let mut output = BTreeMap::new();
        let root = node(
            namespace(vec![
                (b"same".to_vec(), symlink(b"top")),
                (b"stay".to_vec(), symlink(b"bottom")),
            ]),
            &mut output,
        );
        Self {
            source,
            overlay: BTreeSet::from([top]),
            recipe: recipe("overlay", &[top, bottom], None),
            first_operand: top,
            root,
            output,
        }
    }

    /// Frames overlapping nested grafts and all independently expected roots.
    #[cfg(all(feature = "tokio", unix))]
    pub fn nested_overlay() -> Self {
        let mut source = BTreeMap::new();
        let upper_leaf = node(
            namespace(vec![
                (b"gone".to_vec(), vec![0xa1, 1, 5]),
                (b"x".to_vec(), symlink(b"upper")),
            ]),
            &mut source,
        );
        let lower_leaf = node(
            namespace(vec![
                (b"gone".to_vec(), symlink(b"hidden")),
                (b"x".to_vec(), symlink(b"lower")),
                (b"y".to_vec(), symlink(b"retained")),
            ]),
            &mut source,
        );
        let upper_child = node(
            namespace(vec![(b"nested".to_vec(), graft(upper_leaf))]),
            &mut source,
        );
        let lower_child = node(
            namespace(vec![(b"nested".to_vec(), graft(lower_leaf))]),
            &mut source,
        );
        let top = node(
            namespace(vec![(b"g".to_vec(), graft(upper_child))]),
            &mut source,
        );
        let bottom = node(
            namespace(vec![(b"g".to_vec(), graft(lower_child))]),
            &mut source,
        );

        let mut output = BTreeMap::new();
        let leaf = node(
            namespace(vec![
                (b"x".to_vec(), symlink(b"upper")),
                (b"y".to_vec(), symlink(b"retained")),
            ]),
            &mut output,
        );
        let child = node(
            namespace(vec![(b"nested".to_vec(), graft(leaf))]),
            &mut output,
        );
        let root = node(namespace(vec![(b"g".to_vec(), graft(child))]), &mut output);
        Self {
            source,
            overlay: BTreeSet::from([upper_leaf]),
            recipe: recipe("overlay", &[top, bottom], None),
            first_operand: top,
            root,
            output,
        }
    }

    /// Builds a prefer-ours merge with an independently retained expected operand.
    ///
    /// # Panics
    /// Panics if the fixed ours operand is absent from the raw source map.
    pub fn merge() -> Self {
        let mut source = BTreeMap::new();
        let base = node(
            namespace(vec![(b"file".to_vec(), symlink(b"base"))]),
            &mut source,
        );
        let ours = node(
            namespace(vec![(b"file".to_vec(), symlink(b"ours"))]),
            &mut source,
        );
        let theirs = node(
            namespace(vec![(b"file".to_vec(), symlink(b"theirs"))]),
            &mut source,
        );
        let mut args = vec![0xa1];
        cbor::write_text(&mut args, "policy");
        args.push(0x81);
        cbor::write_text(&mut args, "prefer-ours");
        Self {
            output: BTreeMap::from([(ours, source[&ours].clone())]),
            source,
            overlay: BTreeSet::new(),
            recipe: recipe("merge", &[base, ours, theirs], Some(args)),
            first_operand: base,
            root: ours,
        }
    }

    /// Builds repeated grafts with present and missing routes for the same object.
    pub fn index() -> Self {
        let mut source = BTreeMap::new();
        let child = node(
            namespace(vec![
                (b"missing".to_vec(), file(false)),
                (b"present".to_vec(), file(true)),
            ]),
            &mut source,
        );
        let mut output = BTreeMap::new();
        let child_present = node(
            leaf(&vec![(b"present".to_vec(), terminal())], None),
            &mut output,
        );
        let child_missing = node(
            leaf(&vec![(b"missing".to_vec(), terminal())], None),
            &mut output,
        );
        let present = node(
            leaf(
                &vec![
                    (b"first".to_vec(), forward(child_present)),
                    (b"second".to_vec(), forward(child_present)),
                ],
                None,
            ),
            &mut output,
        );
        let missing = node(
            leaf(
                &vec![
                    (b"first".to_vec(), forward(child_missing)),
                    (b"second".to_vec(), forward(child_missing)),
                ],
                None,
            ),
            &mut output,
        );
        let gap = node(
            leaf(&vec![(OBJECT.to_vec(), forward(missing))], None),
            &mut output,
        );
        let mut key = vec![1];
        key.extend_from_slice(&OBJECT);
        let root = node(
            leaf(&vec![(key, forward(present))], Some(gap_properties(gap))),
            &mut output,
        );
        let owner = node(
            leaf(
                &vec![
                    (b"first".to_vec(), graft(child)),
                    (b"second".to_vec(), graft(child)),
                ],
                Some(namespace_properties(Some(root))),
            ),
            &mut source,
        );
        Self {
            source,
            overlay: BTreeSet::new(),
            recipe: recipe("index", &[owner], Some(index_args("terrane-index/v1"))),
            first_operand: owner,
            root,
            output,
        }
    }

    /// Reconstructs the raw operands and checks their exact canonical encodings.
    ///
    /// # Panics
    /// Panics if an operand is malformed, is not a leaf or rebuilds to a different
    /// Node identity or byte encoding.
    pub fn trees(&self) -> BTreeMap<Digest, Tree<'_>> {
        self.source
            .iter()
            .map(|(root, bytes)| {
                let usage = if self.overlay.contains(root) {
                    TreeUse::OverlayLayer
                } else {
                    TreeUse::Ordinary
                };
                let decoded = decode_node_for(bytes, true, MINIMUM, usage)
                    .unwrap_or_else(|error| panic!("raw source: {error:?}"));
                let NodeItems::Leaf(items) = decoded.items else {
                    panic!("small raw source must be a leaf")
                };
                let tree = Tree::build(items, decoded.props, MINIMUM, usage)
                    .unwrap_or_else(|error| panic!("raw source rebuild: {error:?}"));
                assert_eq!(tree.root_identity(), *root);
                assert_eq!(tree.root().encoded(), bytes);
                (*root, tree)
            })
            .collect()
    }

    /// Returns the original recipe lookup hash in the registered Memo domain.
    pub fn key(&self) -> Digest {
        hash(b"terrane-memo-v1", &self.recipe)
    }

    /// Returns the independent common Memo claim for the expected result root.
    pub fn record(&self) -> Vec<u8> {
        memo(self.key(), self.root)
    }

    /// Returns the immutable Memo address, distinct from the recipe lookup hash.
    pub fn address(&self) -> Digest {
        hash(b"terrane-memo-v1", &self.record())
    }

    /// Returns exactly the expected complete output Node identity set.
    pub fn inventory(&self) -> BTreeSet<Digest> {
        self.output.keys().copied().collect()
    }

    /// Seeds the read-only fixture store with the expected Memo and Node bytes.
    pub fn store(&self) -> ReadOnly {
        let mut store = ReadOnly::new();
        store.memos.insert(self.address(), self.record());
        store.nodes = self.output.clone();
        store
    }
}
