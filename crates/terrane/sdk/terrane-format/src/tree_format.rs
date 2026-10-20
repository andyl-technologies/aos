//! Encodes and decodes canonical tree entries and prolly-tree nodes.
//!
//! A node decoder validates local ordering, prefix compression, shape, and
//! resource limits. [`validate_tree_entries`] checks invariants that cross
//! node boundaries after a reader has loaded the complete ordered tree.
//!
//! Nodes encode their level and prefix-compressed items as integer-keyed maps.
//! The empty leaf has this canonical representation:
//!
//! ```text
//! {1: 0, 2: []} => a2 01 00 02 80
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use crate::cbor::{self, Decoder};
use crate::identity::{Digest, IdentityKind, TERRANE_V1};

mod entry;

use entry::{decode_entry, write_entry, write_properties};
pub use entry::{decode_entry_bytes, encode_entry};

/// Maximum encoded key length in bytes.
pub const MAX_KEY: usize = 4096;
/// Maximum path component length in bytes.
pub const MAX_COMPONENT: usize = 255;
/// Maximum symlink target length in bytes.
pub const MAX_SYMLINK: usize = 4096;
/// Maximum number of attributes on one entry.
pub const MAX_ATTRIBUTES: usize = 256;
/// Maximum encoded item bytes in a node, excluding CBOR framing.
pub const MAX_NODE_ITEMS_BYTES: usize = 65536;
// Outer map, field keys, level, and item-array header; the property map is
// payload. At most eight bytes are needed with a 16,384-item upper bound.
const MAX_NODE_FRAMING_BYTES: usize = 8;
/// Maximum height of a tree, with leaves at level zero.
pub const MAX_TREE_LEVEL: u8 = 15;
/// Maximum `tree`-entry traversal depth.
pub const MAX_GRAFT_DEPTH: usize = 64;

/// An invalid tree key, entry, node, or CBOR encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The underlying CBOR is invalid or violates deterministic encoding.
    Cbor(cbor::Error),
    /// A path key or component violates the tree key grammar.
    Key,
    /// An entry contains missing, extra, or ill-typed fields.
    Entry,
    /// A reserved entry type was encountered.
    ReservedType,
    /// A node has invalid levels, item order, or prefix compression.
    Node,
    /// An entry violates a relation with another entry in the tree.
    Tree,
    /// A tree or node exceeds its resource limits.
    Limit,
}

impl From<cbor::Error> for Error {
    fn from(value: cbor::Error) -> Self {
        Self::Cbor(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => error.fmt(f),
            Self::Key => f.write_str("invalid tree key"),
            Self::Entry => f.write_str("invalid tree entry"),
            Self::ReservedType => f.write_str("reserved tree entry type"),
            Self::Node => f.write_str("invalid tree node"),
            Self::Tree => f.write_str("invalid tree relation"),
            Self::Limit => f.write_str("tree limit exceeded"),
        }
    }
}

impl core::error::Error for Error {}

/// Validates a root-relative byte path with slash-separated components.
///
/// # Errors
/// Returns [`Error::Key`] if the path is empty, too long, contains a NUL,
/// has an empty, dot, or dot-dot component, or a component is too long.
pub fn validate_key(key: &[u8]) -> Result<(), Error> {
    if key.is_empty() || key.len() > MAX_KEY || key.contains(&0) {
        return Err(Error::Key);
    }
    for component in key.split(|byte| *byte == b'/') {
        if component.is_empty()
            || component.len() > MAX_COMPONENT
            || component == b"."
            || component == b".."
        {
            return Err(Error::Key);
        }
    }
    Ok(())
}

/// Validates an opaque index-tree key without applying path grammar.
///
/// Index keys encode attribute values and object hashes, so NUL and slash
/// bytes have no filesystem meaning in this context.
///
/// # Errors
/// Returns [`Error::Key`] for an empty key or one longer than 4,096 bytes.
pub fn validate_index_key(key: &[u8]) -> Result<(), Error> {
    if key.is_empty() || key.len() > MAX_KEY {
        Err(Error::Key)
    } else {
        Ok(())
    }
}

/// A chunk or manifest reference in a file entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentRef {
    /// A file at or below the minimum chunk size names its single chunk.
    Inline(Digest),
    /// A larger file names an object manifest.
    Manifest(Digest),
}

/// A borrowed, canonical CBOR attribute value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attribute<'a> {
    /// Registered or preserved attribute name.
    pub name: &'a str,
    /// Complete canonical CBOR value bytes.
    pub value: &'a [u8],
}

/// A borrowed raw extended attribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedAttribute<'a> {
    /// Raw extended attribute name.
    pub name: &'a [u8],
    /// Raw extended attribute value.
    pub value: &'a [u8],
}

/// A property with its schema-validated canonical CBOR value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Property<'a> {
    /// Property name.
    pub name: &'a str,
    /// Canonical `property-value` bytes.
    pub value: &'a [u8],
}

/// A file, directory, graft, or algebra-only tree value.
///
/// Conflict bases are traversed iteratively during cloning, comparison,
/// formatting, and destruction. Because this type implements `Drop`, inspect
/// payloads by reference and use [`core::mem::take`] or [`core::mem::replace`]
/// to transfer owned collections. Borrowed data must outlive destruction.
pub enum EntryKind<'a> {
    /// Plaintext content of one file.
    File {
        /// POSIX permission and special bits, without file-type bits.
        mode: u16,
        /// Plaintext byte count.
        size: u64,
        /// Inline chunk or object manifest identity.
        content: ContentRef,
        /// Deterministic first key of a hard-link set.
        link_id: Option<&'a [u8]>,
    },
    /// A directory needed as an ancestor of child entries.
    Directory {
        /// POSIX permission and special bits, without file-type bits.
        mode: u16,
    },
    /// A verbatim symlink target.
    Symlink {
        /// Raw target bytes, without path normalization.
        target: &'a [u8],
    },
    /// A reference to another tree root with optional overriding properties.
    Tree {
        /// Referenced tree root identity.
        root: Digest,
        /// Property overrides applied at the graft root.
        props: Option<Vec<Property<'a>>>,
    },
    /// An overlay-layer deletion marker.
    Whiteout,
    /// An unresolved merge result in side order.
    Conflict {
        /// Candidate entries in merge-side order.
        candidates: Vec<Entry<'a>>,
        /// Absent when unspecified, null for no base, or the base entry.
        base: Option<Option<Box<Entry<'a>>>>,
    },
    /// Sorted, unique object identities in an index tree.
    Index {
        /// Referenced object identities in strict byte order.
        targets: Vec<Digest>,
    },
}

impl EntryKind<'_> {
    /// Reports whether this entry can be an ancestor of inline descendants.
    ///
    /// A conflict permits conditional descendants when one side is a
    /// directory. Resolving that conflict to a nondirectory must remove
    /// them before the result becomes a conflict-free namespace (TREE-4).
    #[must_use]
    pub fn permits_descendants(&self) -> bool {
        match self {
            Self::Directory { .. } => true,
            Self::Conflict { candidates, .. } => candidates
                .iter()
                .any(|candidate| matches!(candidate.kind, Self::Directory { .. })),
            _ => false,
        }
    }
}

/// A tree value with common attributes and introducing provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    /// Type-specific payload.
    pub kind: EntryKind<'a>,
    /// Writer-supplied or derived canonical attributes.
    pub attrs: Vec<Attribute<'a>>,
    /// Whether the optional attribute map was encoded, even when empty.
    pub attrs_present: bool,
    /// Raw filesystem extended attributes.
    pub xattrs: Vec<ExtendedAttribute<'a>>,
    /// Whether the optional extended-attribute map was encoded, even when empty.
    pub xattrs_present: bool,
    /// Commit that introduced the current entry value.
    pub provenance: Option<Digest>,
}

/// One decoded leaf item, with its full reconstructed key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafItem<'a> {
    /// Full root-relative key.
    pub key: Vec<u8>,
    /// Value at the key.
    pub entry: Entry<'a>,
}

/// One internal-node reference to a disjoint child range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildRef {
    /// Greatest key beneath this child.
    pub last_key: Vec<u8>,
    /// Child node identity.
    pub child: Digest,
    /// Exact number of entries beneath the child at write time.
    pub count: u64,
    /// Exact total encoded subtree bytes at write time.
    pub weight: u64,
}

/// Homogeneous leaf or internal items.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeItems<'a> {
    /// Entries at level zero.
    Leaf(Vec<LeafItem<'a>>),
    /// Child references above level zero.
    Internal(Vec<ChildRef>),
}

/// A canonical prolly-tree node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node<'a> {
    /// Zero for a leaf; each parent increases this level by one.
    pub level: u8,
    /// Leaf entries or child references according to `level`.
    pub items: NodeItems<'a>,
    /// Root-only property map.
    pub props: Option<Vec<Property<'a>>>,
}

fn digest(decoder: &mut Decoder<'_>) -> Result<Digest, Error> {
    decoder.bytes(32)?.try_into().map_err(|_| Error::Entry)
}

/// Validates the recursively defined property-value schema without recursion.
///
/// # Errors
/// Rejects noncanonical values, excluded property types, invalid text-map
/// names, and claimed lengths exceeding the format's input limits.
pub(crate) fn property_value(decoder: &mut Decoder<'_>) -> Result<(), Error> {
    enum Frame<'a> {
        Values(usize),
        Map {
            remaining: usize,
            previous: Option<&'a str>,
        },
    }

    let mut stack = alloc::vec![Frame::Values(1)];
    while let Some(frame) = stack.last_mut() {
        match frame {
            Frame::Values(0) | Frame::Map { remaining: 0, .. } => {
                stack.pop();
                continue;
            }
            Frame::Values(remaining) => *remaining -= 1,
            Frame::Map {
                remaining,
                previous,
            } => {
                let key = decoder.text(MAX_COMPONENT)?;
                if key.is_empty()
                    || previous
                        .is_some_and(|prior: &str| text_key_order(prior, key) != Ordering::Less)
                {
                    return Err(Error::Entry);
                }
                *previous = Some(key);
                *remaining -= 1;
            }
        }

        match decoder.peek_major()? {
            0 => {
                decoder.uint()?;
            }
            3 => {
                decoder.text(MAX_NODE_ITEMS_BYTES)?;
            }
            4 => stack.push(Frame::Values(decoder.array(MAX_NODE_ITEMS_BYTES)?)),
            5 => stack.push(Frame::Map {
                remaining: decoder.map(MAX_NODE_ITEMS_BYTES)?,
                previous: None,
            }),
            7 if decoder.simple()? != 0xf6 => {}
            _ => return Err(Error::Entry),
        }
    }
    Ok(())
}

fn text_key_order(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn byte_key_order(left: &[u8], right: &[u8]) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn properties<'a>(decoder: &mut Decoder<'a>) -> Result<Vec<Property<'a>>, Error> {
    let count = decoder.map(MAX_NODE_ITEMS_BYTES)?;
    let mut result = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let name = decoder.text(MAX_COMPONENT)?;
        if name.is_empty()
            || previous.is_some_and(|prior: &str| text_key_order(prior, name) != Ordering::Less)
        {
            return Err(Error::Entry);
        }
        previous = Some(name);
        let start = decoder.position();
        property_value(decoder)?;
        result.push(Property {
            name,
            value: decoder.slice(start, decoder.position())?,
        });
    }
    Ok(result)
}

fn common_prefix(left: &[u8], right: &[u8]) -> usize {
    left.iter().zip(right).take_while(|(a, b)| a == b).count()
}

fn leaf_items<'a>(
    decoder: &mut Decoder<'a>,
    min_chunk_size: u64,
    usage: TreeUse,
) -> Result<(Vec<LeafItem<'a>>, usize), Error> {
    let count = decoder.array(MAX_NODE_ITEMS_BYTES / 4)?;
    let mut items = Vec::with_capacity(count);
    let mut previous = Vec::<u8>::new();
    let mut encoded_bytes = 0;
    for _ in 0..count {
        let item_start = decoder.position();
        if decoder.array(3)? != 3 {
            return Err(Error::Node);
        }
        let suffix = decoder.bytes(MAX_KEY)?;
        let shared = usize::try_from(decoder.uint()?).map_err(|_| Error::Limit)?;
        if shared > previous.len() || shared + suffix.len() > MAX_KEY {
            return Err(Error::Key);
        }
        let mut key = Vec::with_capacity(shared + suffix.len());
        key.extend_from_slice(&previous[..shared]);
        key.extend_from_slice(suffix);
        validate_key_for(&key, usage)?;
        if shared != common_prefix(&previous, &key) || (!previous.is_empty() && key <= previous) {
            return Err(Error::Node);
        }

        let entry = decode_entry(decoder, min_chunk_size)?;
        validate_entry_use(&entry.kind, usage)?;
        encoded_bytes += decoder.position() - item_start;
        if encoded_bytes > MAX_NODE_ITEMS_BYTES {
            return Err(Error::Limit);
        }
        previous = key.clone();
        items.push(LeafItem { key, entry });
    }
    Ok((items, encoded_bytes))
}

fn child_refs(decoder: &mut Decoder<'_>, usage: TreeUse) -> Result<(Vec<ChildRef>, usize), Error> {
    let count = decoder.array(MAX_NODE_ITEMS_BYTES / 37)?;
    let mut items: Vec<ChildRef> = Vec::with_capacity(count);
    let mut encoded_bytes = 0;
    for _ in 0..count {
        let item_start = decoder.position();
        if decoder.array(4)? != 4 {
            return Err(Error::Node);
        }
        let last_key = decoder.bytes(MAX_KEY)?.to_vec();
        validate_key_for(&last_key, usage)?;
        if items.last().is_some_and(|prior| last_key <= prior.last_key) {
            return Err(Error::Node);
        }
        let child = digest(decoder)?;
        let count = decoder.uint()?;
        let weight = decoder.uint()?;
        if count == 0 || weight == 0 {
            return Err(Error::Node);
        }
        encoded_bytes += decoder.position() - item_start;
        if encoded_bytes > MAX_NODE_ITEMS_BYTES {
            return Err(Error::Limit);
        }
        items.push(ChildRef {
            last_key,
            child,
            count,
            weight,
        });
    }
    Ok((items, encoded_bytes))
}

/// Decodes one node with its root status and chunk profile minimum.
///
/// `is_root` distinguishes the sole empty leaf and root-only properties.
/// Child references are validated locally; their `count` and `weight` must
/// be checked against fetched children by a tree reader or builder.
///
/// # Errors
/// Rejects invalid CBOR, node shape or ordering, nonminimal prefix
/// compression, invalid entries, excessive levels, or resource limits.
pub fn decode_node(input: &[u8], is_root: bool, min_chunk_size: u64) -> Result<Node<'_>, Error> {
    decode_node_for(input, is_root, min_chunk_size, TreeUse::Ordinary)
}

/// Decodes a node using the key grammar and entry types of `usage`.
///
/// Index-tree keys are opaque bytes; other tree keys are filesystem paths.
/// Both forms remain strictly sorted and limited to 4,096 bytes.
///
/// # Errors
/// Rejects invalid CBOR, entries incompatible with `usage`, malformed keys,
/// nonminimal prefix compression, excessive levels, or resource limits.
pub fn decode_node_for(
    input: &[u8],
    is_root: bool,
    min_chunk_size: u64,
    usage: TreeUse,
) -> Result<Node<'_>, Error> {
    // Item and root-property bytes share one 64 KiB payload budget. Only
    // outer map keys, the level, and the items array header are framing.
    if input.len() > MAX_NODE_ITEMS_BYTES + MAX_NODE_FRAMING_BYTES {
        return Err(Error::Limit);
    }
    let mut decoder = Decoder::new(input);
    let fields = decoder.map(3)?;
    if !(2..=3).contains(&fields) || decoder.uint()? != 1 {
        return Err(Error::Node);
    }
    let level = u8::try_from(decoder.uint()?).map_err(|_| Error::Limit)?;
    if level > MAX_TREE_LEVEL || decoder.uint()? != 2 {
        return Err(Error::Node);
    }
    let (items, item_bytes) = if level == 0 {
        let (items, bytes) = leaf_items(&mut decoder, min_chunk_size, usage)?;
        (NodeItems::Leaf(items), bytes)
    } else {
        let (items, bytes) = child_refs(&mut decoder, usage)?;
        (NodeItems::Internal(items), bytes)
    };
    let (props, property_bytes) = if fields == 3 {
        if !is_root || decoder.uint()? != 3 {
            return Err(Error::Node);
        }
        let start = decoder.position();
        let props = properties(&mut decoder)?;
        (Some(props), decoder.position() - start)
    } else {
        (None, 0)
    };
    if item_bytes.checked_add(property_bytes).ok_or(Error::Limit)? > MAX_NODE_ITEMS_BYTES {
        return Err(Error::Limit);
    }
    decoder.finish()?;

    let empty = match &items {
        NodeItems::Leaf(values) => values.is_empty(),
        NodeItems::Internal(values) => values.is_empty(),
    };
    if empty && (!is_root || level != 0) {
        return Err(Error::Node);
    }
    Ok(Node {
        level,
        items,
        props,
    })
}

/// Encodes a node with shortest-form CBOR and canonical prefix compression.
///
/// # Errors
/// Rejects a node the decoder would not accept, including invalid entry
/// forms, item ordering, resource limits, and non-root properties.
pub fn encode_node(node: &Node<'_>, is_root: bool, min_chunk_size: u64) -> Result<Vec<u8>, Error> {
    encode_node_for(node, is_root, min_chunk_size, TreeUse::Ordinary)
}

/// Encodes a node for a specific tree context.
///
/// # Errors
/// Rejects a node whose entries or keys violate `usage`, or whose encoding
/// exceeds the node limit or fails deterministic decoding.
pub fn encode_node_for(
    node: &Node<'_>,
    is_root: bool,
    min_chunk_size: u64,
    usage: TreeUse,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    cbor::write_map(&mut output, if node.props.is_some() { 3 } else { 2 });
    cbor::write_uint(&mut output, 1);
    cbor::write_uint(&mut output, u64::from(node.level));
    cbor::write_uint(&mut output, 2);

    match &node.items {
        NodeItems::Leaf(items) => {
            if items.len() > MAX_NODE_ITEMS_BYTES / 4 {
                return Err(Error::Limit);
            }
            cbor::write_array(&mut output, items.len());
            let mut previous = &[][..];
            for item in items {
                let shared = common_prefix(previous, &item.key);
                cbor::write_array(&mut output, 3);
                cbor::write_bytes(&mut output, &item.key[shared..]);
                cbor::write_uint(&mut output, shared as u64);
                write_entry(&mut output, &item.entry)?;
                if output.len() > MAX_NODE_ITEMS_BYTES + MAX_NODE_FRAMING_BYTES {
                    return Err(Error::Limit);
                }
                previous = &item.key;
            }
        }
        NodeItems::Internal(items) => {
            if items.len() > MAX_NODE_ITEMS_BYTES / 37 {
                return Err(Error::Limit);
            }
            cbor::write_array(&mut output, items.len());
            for item in items {
                cbor::write_array(&mut output, 4);
                cbor::write_bytes(&mut output, &item.last_key);
                cbor::write_bytes(&mut output, &item.child);
                cbor::write_uint(&mut output, item.count);
                cbor::write_uint(&mut output, item.weight);
                if output.len() > MAX_NODE_ITEMS_BYTES + MAX_NODE_FRAMING_BYTES {
                    return Err(Error::Limit);
                }
            }
        }
    }
    if let Some(props) = &node.props {
        cbor::write_uint(&mut output, 3);
        write_properties(&mut output, props);
    }
    if output.len() > MAX_NODE_ITEMS_BYTES + MAX_NODE_FRAMING_BYTES {
        return Err(Error::Limit);
    }
    decode_node_for(&output, is_root, min_chunk_size, usage)?;
    Ok(output)
}

/// Verifies a child reference against a fetched, already decoded child node.
///
/// This checks the child's identity and the writer's exact count and weight
/// claim. A reader must still descend when its answer depends on entries;
/// these advisory fields cannot replace reading or validating a subtree.
///
/// # Errors
/// Returns an error if the child level, identity, last key, count, weight,
/// or subtree arithmetic is invalid.
pub fn verify_child_ref(
    parent_level: u8,
    reference: &ChildRef,
    child: &Node<'_>,
    child_bytes: &[u8],
    min_chunk_size: u64,
) -> Result<(), Error> {
    verify_child_ref_for(
        parent_level,
        reference,
        child,
        child_bytes,
        min_chunk_size,
        TreeUse::Ordinary,
    )
}

/// Verifies a child reference under the parent tree's key context.
///
/// # Errors
/// Returns an error for malformed child bytes, a mismatched level or
/// identity, or an inaccurate last key, count, or weight claim.
pub fn verify_child_ref_for(
    parent_level: u8,
    reference: &ChildRef,
    child: &Node<'_>,
    child_bytes: &[u8],
    min_chunk_size: u64,
    usage: TreeUse,
) -> Result<(), Error> {
    if decode_node_for(child_bytes, false, min_chunk_size, usage)? != *child {
        return Err(Error::Node);
    }
    if child.level.checked_add(1) != Some(parent_level) {
        return Err(Error::Node);
    }
    let identity = TERRANE_V1
        .calculate(IdentityKind::Node, child_bytes)
        .map_err(|_| Error::Node)?;
    if identity.terrane_v1_digest().map_err(|_| Error::Node)? != reference.child {
        return Err(Error::Node);
    }

    let own_weight = u64::try_from(child_bytes.len()).map_err(|_| Error::Limit)?;
    let (last_key, count, descendants_weight) = match &child.items {
        NodeItems::Leaf(items) => {
            let last = items.last().ok_or(Error::Node)?;
            (
                &last.key,
                u64::try_from(items.len()).map_err(|_| Error::Limit)?,
                0,
            )
        }
        NodeItems::Internal(items) => {
            let last = items.last().ok_or(Error::Node)?;
            let count = items.iter().try_fold(0_u64, |sum, item| {
                sum.checked_add(item.count).ok_or(Error::Limit)
            })?;
            let weight = items.iter().try_fold(0_u64, |sum, item| {
                sum.checked_add(item.weight).ok_or(Error::Limit)
            })?;
            (&last.last_key, count, weight)
        }
    };
    let weight = own_weight
        .checked_add(descendants_weight)
        .ok_or(Error::Limit)?;
    if reference.last_key.as_slice() != last_key.as_slice()
        || reference.count != count
        || reference.weight != weight
    {
        return Err(Error::Node);
    }
    Ok(())
}

/// The semantic context in which a complete tree is read or served.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreeUse {
    /// A regular tree that may hold unresolved merge entries.
    Ordinary,
    /// A layer that may contain whiteout entries.
    OverlayLayer,
    /// An index tree containing only index entries.
    Index,
    /// A consumer surface without conflict support.
    Surface,
    /// A consumer surface that declares conflict support.
    ConflictSurface,
}

fn validate_key_for(key: &[u8], usage: TreeUse) -> Result<(), Error> {
    if usage == TreeUse::Index {
        validate_index_key(key)
    } else {
        validate_key(key)
    }
}

fn validate_entry_use(kind: &EntryKind<'_>, usage: TreeUse) -> Result<(), Error> {
    match (kind, usage) {
        (EntryKind::Index { .. }, TreeUse::Index)
        | (EntryKind::Whiteout, TreeUse::OverlayLayer) => Ok(()),
        (EntryKind::Index { .. }, _)
        | (_, TreeUse::Index)
        | (EntryKind::Whiteout, _)
        | (EntryKind::Conflict { .. }, TreeUse::Surface) => Err(Error::Tree),
        _ => Ok(()),
    }
}

fn same_hardlink_value(left: &Entry<'_>, right: &Entry<'_>) -> bool {
    match (&left.kind, &right.kind) {
        (
            EntryKind::File {
                mode: lm,
                size: ls,
                content: lc,
                ..
            },
            EntryKind::File {
                mode: rm,
                size: rs,
                content: rc,
                ..
            },
        ) => {
            lm == rm
                && ls == rs
                && lc == rc
                && left.attrs_present == right.attrs_present
                && left.attrs == right.attrs
                && left.xattrs_present == right.xattrs_present
                && left.xattrs == right.xattrs
        }
        _ => false,
    }
}

/// Checks the roots traversed while resolving nested `tree` entries.
///
/// The caller appends each root before fetching it. Repeated identities
/// indicate a cycle. The initial root plus at most 64 referenced roots
/// represent the registered bound of 64 tree-entry edges.
///
/// # Errors
/// Returns [`Error::Tree`] on a cycle or [`Error::Limit`] above 64 edges.
pub fn validate_graft_chain(roots: &[Digest]) -> Result<(), Error> {
    if roots.len().saturating_sub(1) > MAX_GRAFT_DEPTH {
        return Err(Error::Limit);
    }
    for (position, root) in roots.iter().enumerate() {
        if roots[..position].contains(root) {
            return Err(Error::Tree);
        }
    }
    Ok(())
}

/// Checks whole-tree invariants across already decoded, sorted leaf items.
///
/// This verifies explicit directory ancestors, graft boundaries, hard-link
/// identities and equal inode values, and context-specific algebra entries.
/// Callers must supply every leaf item of a tree in key order.
///
/// # Errors
/// Returns an error for missing or wrong ancestors, entries beneath grafts,
/// inconsistent hard-link sets, invalid ordering, or forbidden entry types.
pub fn validate_tree_entries(entries: &[LeafItem<'_>], usage: TreeUse) -> Result<(), Error> {
    let mut previous = None;
    let mut hardlinks: alloc::collections::BTreeMap<&[u8], &Entry<'_>> =
        alloc::collections::BTreeMap::new();
    for item in entries {
        validate_key_for(&item.key, usage)?;
        if previous.is_some_and(|prior: &[u8]| item.key.as_slice() <= prior) {
            return Err(Error::Tree);
        }
        previous = Some(&item.key);
        if usage != TreeUse::Index {
            for (position, byte) in item.key.iter().enumerate() {
                if *byte != b'/' {
                    continue;
                }
                let ancestor = &item.key[..position];
                let index = entries
                    .binary_search_by(|probe| probe.key.as_slice().cmp(ancestor))
                    .map_err(|_| Error::Tree)?;
                if !entries[index].entry.kind.permits_descendants() {
                    return Err(Error::Tree);
                }
            }
        }
        validate_entry_use(&item.entry.kind, usage)?;
        if let EntryKind::File {
            link_id: Some(link_id),
            ..
        } = &item.entry.kind
        {
            match hardlinks.get(link_id) {
                Some(first_entry) if !same_hardlink_value(first_entry, &item.entry) => {
                    return Err(Error::Tree);
                }
                Some(_) => {}
                None => {
                    if *link_id != item.key.as_slice() {
                        return Err(Error::Tree);
                    }
                    hardlinks.insert(*link_id, &item.entry);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
#[path = "tree_format/entry_tests.rs"]
mod tests;
