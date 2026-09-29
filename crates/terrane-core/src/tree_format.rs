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
#[derive(Clone, Debug, Eq, PartialEq)]
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

fn content_ref(decoder: &mut Decoder<'_>) -> Result<ContentRef, Error> {
    if decoder.array(2)? != 2 {
        return Err(Error::Entry);
    }
    let tag = decoder.uint()?;
    let digest = digest(decoder)?;
    match tag {
        0 => Ok(ContentRef::Inline(digest)),
        1 => Ok(ContentRef::Manifest(digest)),
        _ => Err(Error::Entry),
    }
}

fn property_value(decoder: &mut Decoder<'_>, depth: usize) -> Result<(), Error> {
    if depth >= cbor::MAX_NESTING {
        return Err(Error::Limit);
    }
    match decoder.peek_major()? {
        0 => {
            decoder.uint()?;
        }
        3 => {
            decoder.text(MAX_NODE_ITEMS_BYTES)?;
        }
        4 => {
            let count = decoder.array(MAX_NODE_ITEMS_BYTES)?;
            for _ in 0..count {
                property_value(decoder, depth + 1)?;
            }
        }
        5 => {
            let count = decoder.map(MAX_NODE_ITEMS_BYTES)?;
            let mut previous = None;
            for _ in 0..count {
                let key = decoder.text(MAX_COMPONENT)?;
                if key.is_empty()
                    || previous
                        .is_some_and(|prior: &str| text_key_order(prior, key) != Ordering::Less)
                {
                    return Err(Error::Entry);
                }
                previous = Some(key);
                property_value(decoder, depth + 1)?;
            }
        }
        7 => {
            if decoder.simple()? == 0xf6 {
                return Err(Error::Entry);
            }
        }
        _ => return Err(Error::Entry),
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
        property_value(decoder, 0)?;
        result.push(Property {
            name,
            value: decoder.slice(start, decoder.position())?,
        });
    }
    Ok(result)
}

fn attributes<'a>(decoder: &mut Decoder<'a>) -> Result<Vec<Attribute<'a>>, Error> {
    let count = decoder.map(MAX_ATTRIBUTES)?;
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
        let value = decoder.raw_value(MAX_NODE_ITEMS_BYTES)?;
        result.push(Attribute { name, value });
    }
    Ok(result)
}

fn extended_attributes<'a>(decoder: &mut Decoder<'a>) -> Result<Vec<ExtendedAttribute<'a>>, Error> {
    let count = decoder.map(MAX_NODE_ITEMS_BYTES)?;
    let mut result = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let name = decoder.bytes(MAX_COMPONENT)?;
        if name.is_empty()
            || previous.is_some_and(|prior: &[u8]| byte_key_order(prior, name) != Ordering::Less)
        {
            return Err(Error::Entry);
        }
        previous = Some(name);
        let value = decoder.bytes(MAX_NODE_ITEMS_BYTES)?;
        result.push(ExtendedAttribute { name, value });
    }
    Ok(result)
}

fn decode_entry<'a>(
    decoder: &mut Decoder<'a>,
    depth: usize,
    min_chunk_size: u64,
) -> Result<Entry<'a>, Error> {
    if depth >= MAX_GRAFT_DEPTH {
        return Err(Error::Limit);
    }
    let count = decoder.map(14)?;
    let mut previous = 0;
    let mut kind = None;
    let mut mode = None;
    let mut size = None;
    let mut content = None;
    let mut target = None;
    let mut root = None;
    let mut props = None;
    let mut link_id = None;
    let mut attrs = Vec::new();
    let mut xattrs = Vec::new();
    let mut provenance = None;
    let mut candidates = None;
    let mut base = None;
    let mut targets = None;
    let mut present = 0_u16;

    for _ in 0..count {
        let field = decoder.uint()?;
        if field <= previous || field > 14 {
            return Err(Error::Entry);
        }
        previous = field;
        present |= 1 << field;
        match field {
            1 => kind = Some(decoder.uint()?),
            2 => {
                let value = decoder.uint()?;
                mode = Some(u16::try_from(value).map_err(|_| Error::Entry)?);
                if value > 0x0fff {
                    return Err(Error::Entry);
                }
            }
            3 => size = Some(decoder.uint()?),
            4 => content = Some(content_ref(decoder)?),
            5 => target = Some(decoder.bytes(MAX_SYMLINK)?),
            6 => root = Some(digest(decoder)?),
            7 => props = Some(properties(decoder)?),
            8 => {
                let key = decoder.bytes(MAX_KEY)?;
                validate_key(key)?;
                link_id = Some(key);
            }
            9 => attrs = attributes(decoder)?,
            10 => xattrs = extended_attributes(decoder)?,
            11 => provenance = Some(digest(decoder)?),
            12 => {
                let length = decoder.array(MAX_NODE_ITEMS_BYTES)?;
                if length < 2 {
                    return Err(Error::Entry);
                }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    let entry = decode_entry(decoder, depth + 1, min_chunk_size)?;
                    if matches!(&entry.kind, EntryKind::Conflict { .. }) {
                        return Err(Error::Entry);
                    }
                    values.push(entry);
                }
                candidates = Some(values);
            }
            13 => {
                if decoder.peek_major()? == 7 {
                    if decoder.simple()? != 0xf6 {
                        return Err(Error::Entry);
                    }
                    base = Some(None);
                } else {
                    let entry = decode_entry(decoder, depth + 1, min_chunk_size)?;
                    base = Some(Some(Box::new(entry)));
                }
            }
            14 => {
                let length = decoder.array(MAX_NODE_ITEMS_BYTES)?;
                if length == 0 {
                    return Err(Error::Entry);
                }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    let value = digest(decoder)?;
                    if values.last().is_some_and(|prior: &Digest| value <= *prior) {
                        return Err(Error::Entry);
                    }
                    values.push(value);
                }
                targets = Some(values);
            }
            _ => return Err(Error::Entry),
        }
    }

    let kind = match kind.ok_or(Error::Entry)? {
        1 => {
            let size = size.ok_or(Error::Entry)?;
            let content = content.ok_or(Error::Entry)?;
            let correct = matches!(content, ContentRef::Inline(_)) == (size <= min_chunk_size);
            if !correct {
                return Err(Error::Entry);
            }
            EntryKind::File {
                mode: mode.ok_or(Error::Entry)?,
                size,
                content,
                link_id,
            }
        }
        2 => EntryKind::Directory {
            mode: mode.ok_or(Error::Entry)?,
        },
        3 => EntryKind::Symlink {
            target: target.ok_or(Error::Entry)?,
        },
        4 => EntryKind::Tree {
            root: root.ok_or(Error::Entry)?,
            props,
        },
        5 => EntryKind::Whiteout,
        6 => EntryKind::Conflict {
            candidates: candidates.ok_or(Error::Entry)?,
            base,
        },
        7 => EntryKind::Index {
            targets: targets.ok_or(Error::Entry)?,
        },
        8..=15 => return Err(Error::ReservedType),
        _ => return Err(Error::Entry),
    };

    let allowed = match &kind {
        EntryKind::File { .. } => {
            bit(1) | bit(2) | bit(3) | bit(4) | bit(8) | bit(9) | bit(10) | bit(11)
        }
        EntryKind::Directory { .. } => bit(1) | bit(2) | bit(9) | bit(10) | bit(11),
        EntryKind::Symlink { .. } => bit(1) | bit(5) | bit(9) | bit(10) | bit(11),
        EntryKind::Tree { .. } => bit(1) | bit(6) | bit(7) | bit(9) | bit(10) | bit(11),
        EntryKind::Whiteout => bit(1) | bit(11),
        EntryKind::Conflict { .. } => bit(1) | bit(9) | bit(10) | bit(11) | bit(12) | bit(13),
        EntryKind::Index { .. } => bit(1) | bit(9) | bit(10) | bit(11) | bit(14),
    };
    if present & !allowed != 0 {
        return Err(Error::Entry);
    }
    if matches!(&kind, EntryKind::Whiteout) && (!attrs.is_empty() || !xattrs.is_empty()) {
        return Err(Error::Entry);
    }
    Ok(Entry {
        kind,
        attrs,
        attrs_present: present & bit(9) != 0,
        xattrs,
        xattrs_present: present & bit(10) != 0,
        provenance,
    })
}

const fn bit(field: u32) -> u16 {
    1 << field
}

/// Decodes one standalone entry using the configured chunk profile minimum.
///
/// # Errors
/// Rejects invalid CBOR, unknown or reserved fields/types, incompatible
/// content references, and any entry resource limit.
pub fn decode_entry_bytes(input: &[u8], min_chunk_size: u64) -> Result<Entry<'_>, Error> {
    if input.len() > MAX_NODE_ITEMS_BYTES {
        return Err(Error::Limit);
    }
    let mut decoder = Decoder::new(input);
    let entry = decode_entry(&mut decoder, 0, min_chunk_size)?;
    decoder.finish()?;
    Ok(entry)
}

fn write_properties(output: &mut Vec<u8>, values: &[Property<'_>]) {
    let mut sorted: Vec<_> = values.iter().collect();
    sorted.sort_by(|left, right| text_key_order(left.name, right.name));
    cbor::write_map(output, sorted.len());
    for property in sorted {
        cbor::write_text(output, property.name);
        output.extend_from_slice(property.value);
    }
}

fn write_attributes(output: &mut Vec<u8>, values: &[Attribute<'_>]) {
    let mut sorted: Vec<_> = values.iter().collect();
    sorted.sort_by(|left, right| text_key_order(left.name, right.name));
    cbor::write_map(output, sorted.len());
    for attribute in sorted {
        cbor::write_text(output, attribute.name);
        output.extend_from_slice(attribute.value);
    }
}

fn write_extended_attributes(output: &mut Vec<u8>, values: &[ExtendedAttribute<'_>]) {
    let mut sorted: Vec<_> = values.iter().collect();
    sorted.sort_by(|left, right| byte_key_order(left.name, right.name));
    cbor::write_map(output, sorted.len());
    for attribute in sorted {
        cbor::write_bytes(output, attribute.name);
        cbor::write_bytes(output, attribute.value);
    }
}

fn write_entry(output: &mut Vec<u8>, entry: &Entry<'_>, depth: usize) -> Result<(), Error> {
    if depth >= MAX_GRAFT_DEPTH {
        return Err(Error::Limit);
    }
    let common = usize::from(entry.attrs_present)
        + usize::from(entry.xattrs_present)
        + usize::from(entry.provenance.is_some());
    let fields = match &entry.kind {
        EntryKind::File { link_id, .. } => 4 + usize::from(link_id.is_some()),
        EntryKind::Directory { .. }
        | EntryKind::Symlink { .. }
        | EntryKind::Tree { props: None, .. } => 2,
        EntryKind::Tree { props: Some(_), .. } => 3,
        EntryKind::Whiteout => 1,
        EntryKind::Conflict { base, .. } => 2 + usize::from(base.is_some()),
        EntryKind::Index { .. } => 2,
    };
    cbor::write_map(output, fields + common);
    cbor::write_uint(output, 1);
    cbor::write_uint(
        output,
        match &entry.kind {
            EntryKind::File { .. } => 1,
            EntryKind::Directory { .. } => 2,
            EntryKind::Symlink { .. } => 3,
            EntryKind::Tree { .. } => 4,
            EntryKind::Whiteout => 5,
            EntryKind::Conflict { .. } => 6,
            EntryKind::Index { .. } => 7,
        },
    );

    match &entry.kind {
        EntryKind::File {
            mode,
            size,
            content,
            ..
        } => {
            cbor::write_uint(output, 2);
            cbor::write_uint(output, u64::from(*mode));
            cbor::write_uint(output, 3);
            cbor::write_uint(output, *size);
            cbor::write_uint(output, 4);
            cbor::write_array(output, 2);
            match content {
                ContentRef::Inline(hash) => {
                    cbor::write_uint(output, 0);
                    cbor::write_bytes(output, hash);
                }
                ContentRef::Manifest(hash) => {
                    cbor::write_uint(output, 1);
                    cbor::write_bytes(output, hash);
                }
            }
        }
        EntryKind::Directory { mode } => {
            cbor::write_uint(output, 2);
            cbor::write_uint(output, u64::from(*mode));
        }
        EntryKind::Symlink { target } => {
            cbor::write_uint(output, 5);
            cbor::write_bytes(output, target);
        }
        EntryKind::Tree { root, props } => {
            cbor::write_uint(output, 6);
            cbor::write_bytes(output, root);
            if let Some(props) = props {
                cbor::write_uint(output, 7);
                write_properties(output, props);
            }
        }
        EntryKind::Whiteout | EntryKind::Conflict { .. } | EntryKind::Index { .. } => {}
    }

    if let EntryKind::File {
        link_id: Some(key), ..
    } = &entry.kind
    {
        cbor::write_uint(output, 8);
        cbor::write_bytes(output, key);
    }
    if entry.attrs_present {
        cbor::write_uint(output, 9);
        write_attributes(output, &entry.attrs);
    }
    if entry.xattrs_present {
        cbor::write_uint(output, 10);
        write_extended_attributes(output, &entry.xattrs);
    }
    if let Some(provenance) = entry.provenance {
        cbor::write_uint(output, 11);
        cbor::write_bytes(output, &provenance);
    }

    match &entry.kind {
        EntryKind::Conflict { candidates, base } => {
            cbor::write_uint(output, 12);
            cbor::write_array(output, candidates.len());
            for candidate in candidates {
                write_entry(output, candidate, depth + 1)?;
            }
            if let Some(base) = base {
                cbor::write_uint(output, 13);
                if let Some(base) = base {
                    write_entry(output, base, depth + 1)?;
                } else {
                    output.push(0xf6);
                }
            }
        }
        EntryKind::Index { targets } => {
            cbor::write_uint(output, 14);
            cbor::write_array(output, targets.len());
            for target in targets {
                cbor::write_bytes(output, target);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Encodes one entry and rejects any shape the decoder would reject.
///
/// # Errors
/// Returns an error for invalid fields, canonical values, resource limits,
/// or a file content form incompatible with `min_chunk_size`.
pub fn encode_entry(entry: &Entry<'_>, min_chunk_size: u64) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    write_entry(&mut output, entry, 0)?;
    decode_entry_bytes(&output, min_chunk_size)?;
    Ok(output)
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

        let entry = decode_entry(decoder, 0, min_chunk_size)?;
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
                write_entry(&mut output, &item.entry, 0)?;
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
/// indicate a cycle; more than 64 roots exceed the graft depth bound.
///
/// # Errors
/// Returns [`Error::Tree`] on a cycle or [`Error::Limit`] above 64 roots.
pub fn validate_graft_chain(roots: &[Digest]) -> Result<(), Error> {
    if roots.len() > MAX_GRAFT_DEPTH {
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
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{
        ChildRef, ContentRef, Entry, EntryKind, Error, LeafItem, Node, NodeItems, TreeUse,
        decode_entry_bytes, decode_node, decode_node_for, encode_node, encode_node_for,
        validate_graft_chain, validate_index_key, validate_key, validate_tree_entries,
        verify_child_ref,
    };

    const MIN_CHUNK: u64 = 262_144;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("ASCII test vector");
                u8::from_str_radix(text, 16).expect("hex test vector")
            })
            .collect()
    }

    fn file<'a>(link_id: Option<&'a [u8]>) -> Entry<'a> {
        Entry {
            kind: EntryKind::File {
                mode: 0o644,
                size: 15,
                content: ContentRef::Inline([7; 32]),
                link_id,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        }
    }

    fn directory() -> Entry<'static> {
        Entry {
            kind: EntryKind::Directory { mode: 0o755 },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        }
    }

    fn item<'a>(key: &[u8], entry: Entry<'a>) -> LeafItem<'a> {
        LeafItem {
            key: key.to_vec(),
            entry,
        }
    }

    #[test]
    fn golden_leaf_round_trips_byte_exactly() {
        let encoded = hex_bytes(concat!(
            "a201000281834968656c6c6f2e74787400a40101021901a4030f048200582094",
            "79e1e57491078eb09f9decc2c56c63110c372de01557d73560dbc2ba9f3ba0",
        ));
        let node = decode_node(&encoded, true, MIN_CHUNK).expect("golden node decodes");
        assert_eq!(
            encode_node(&node, true, MIN_CHUNK).expect("re-encodes"),
            encoded
        );
    }

    #[test]
    fn empty_leaf_is_the_only_empty_tree_node() {
        let empty = [0xa2, 1, 0, 2, 0x80];
        let node = decode_node(&empty, true, MIN_CHUNK).expect("empty root");
        assert_eq!(encode_node(&node, true, MIN_CHUNK).expect("encode"), empty);
        assert_eq!(decode_node(&empty, false, MIN_CHUNK), Err(Error::Node));
    }

    #[test]
    fn rejects_malformed_paths_and_missing_ancestors() {
        for key in [
            &b""[..],
            b"/a",
            b"a/",
            b"a//b",
            b"a/./b",
            b"a/../b",
            b"a\0b",
        ] {
            assert_eq!(validate_key(key), Err(Error::Key), "{key:?}");
        }
        assert_eq!(validate_key(&vec![b'a'; 256]), Err(Error::Key));
        let entries = [item(b"a/b", file(None))];
        assert_eq!(
            validate_tree_entries(&entries, TreeUse::Ordinary),
            Err(Error::Tree)
        );

        let entries = [item(b"a", directory()), item(b"a/b", file(None))];
        validate_tree_entries(&entries, TreeUse::Ordinary).expect("explicit ancestor");
    }

    #[test]
    fn only_directory_conflicts_permit_conditional_descendants() {
        let mut ancestor = directory();
        ancestor.kind = EntryKind::Conflict {
            candidates: vec![file(None), directory()],
            base: None,
        };
        let mut entries = [item(b"a", ancestor), item(b"a/b", file(None))];

        validate_tree_entries(&entries, TreeUse::Ordinary).expect("conditional directory");
        validate_tree_entries(&entries, TreeUse::ConflictSurface).expect("conflict-aware view");
        assert_eq!(
            validate_tree_entries(&entries, TreeUse::Surface),
            Err(Error::Tree)
        );

        entries[0].entry.kind = EntryKind::Conflict {
            candidates: vec![file(None), file(None)],
            base: None,
        };
        assert_eq!(
            validate_tree_entries(&entries, TreeUse::Ordinary),
            Err(Error::Tree)
        );

        entries[0].entry = file(None);
        assert_eq!(
            validate_tree_entries(&entries, TreeUse::Ordinary),
            Err(Error::Tree)
        );
    }

    #[test]
    fn rejects_reserved_and_unknown_entry_fields() {
        assert_eq!(
            decode_entry_bytes(&[0xa1, 1, 8], MIN_CHUNK),
            Err(Error::ReservedType)
        );
        assert_eq!(
            decode_entry_bytes(&[0xa2, 1, 5, 15, 0], MIN_CHUNK),
            Err(Error::Entry)
        );
        assert_eq!(
            decode_entry_bytes(&[0xa2, 1, 5, 1, 0], MIN_CHUNK),
            Err(Error::Entry)
        );
    }

    #[test]
    fn file_content_form_tracks_profile_minimum() {
        let inline = file(None);
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"f", inline)]),
            props: None,
        };
        let encoded = encode_node(&node, true, MIN_CHUNK).expect("small file inline");
        assert!(decode_node(&encoded, true, 14).is_err());
    }

    #[test]
    fn entry_limits_and_type_fields_fail_at_decode() {
        let mut invalid_mode = file(None);
        if let EntryKind::File { mode, .. } = &mut invalid_mode.kind {
            *mode = 0x1000;
        }
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"f", invalid_mode)]),
            props: None,
        };
        assert!(encode_node(&node, true, MIN_CHUNK).is_err());

        let symlink = Entry {
            kind: EntryKind::Symlink {
                target: b"\xff/../raw",
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"link", symlink)]),
            props: None,
        };
        assert!(encode_node(&node, true, MIN_CHUNK).is_ok());

        let long_target = vec![b'x'; 4097];
        let symlink = Entry {
            kind: EntryKind::Symlink {
                target: &long_target,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"link", symlink)]),
            props: None,
        };
        assert!(encode_node(&node, true, MIN_CHUNK).is_err());
    }

    #[test]
    fn prefix_compression_must_use_full_common_prefix() {
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"a1", file(None)), item(b"a2", file(None))]),
            props: None,
        };
        let mut encoded = encode_node(&node, true, MIN_CHUNK).expect("canonical node");
        let second = encoded
            .windows(4)
            .position(|window| window == [0x83, 0x41, b'2', 0x01])
            .expect("stored suffix and shared length");
        encoded.splice(second..second + 4, [0x83, 0x42, b'a', b'2', 0x00]);
        assert!(decode_node(&encoded, true, MIN_CHUNK).is_err());
    }

    #[test]
    fn whiteout_and_index_forms_are_strict() {
        let whiteout_with_attrs = [0xa2, 1, 5, 9, 0xa0];
        assert_eq!(
            decode_entry_bytes(&whiteout_with_attrs, MIN_CHUNK),
            Err(Error::Entry)
        );

        let index_with_duplicate_targets = {
            let mut bytes = vec![0xa2, 1, 7, 14, 0x82];
            for _ in 0..2 {
                bytes.extend_from_slice(&[0x58, 32]);
                bytes.extend_from_slice(&[3; 32]);
            }
            bytes
        };
        assert_eq!(
            decode_entry_bytes(&index_with_duplicate_targets, MIN_CHUNK),
            Err(Error::Entry)
        );
    }

    #[test]
    fn conflicts_reject_conflict_candidates() {
        let nested = Entry {
            kind: EntryKind::Conflict {
                candidates: vec![file(None), file(None)],
                base: Some(None),
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        let outer = Entry {
            kind: EntryKind::Conflict {
                candidates: vec![file(None), nested],
                base: Some(None),
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        assert!(super::encode_entry(&outer, MIN_CHUNK).is_err());
    }

    #[test]
    fn properties_are_root_only_and_preserve_presence() {
        let node = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"f", file(None))]),
            props: Some(Vec::new()),
        };
        let encoded = encode_node(&node, true, MIN_CHUNK).expect("root property map");
        assert_eq!(
            encode_node(
                &decode_node(&encoded, true, MIN_CHUNK).expect("decode"),
                true,
                MIN_CHUNK
            )
            .expect("encode"),
            encoded
        );
        assert_eq!(decode_node(&encoded, false, MIN_CHUNK), Err(Error::Node));
    }

    #[test]
    fn root_properties_and_items_share_the_node_payload_cap() {
        let mut value = Vec::new();
        crate::cbor::write_argument(&mut value, 3, 65_500);
        value.extend_from_slice(&vec![b'x'; 65_500]);
        let props = vec![super::Property {
            name: "p",
            value: &value,
        }];

        let root = Node {
            level: 0,
            items: NodeItems::Leaf(Vec::new()),
            props: Some(props.clone()),
        };
        encode_node(&root, true, MIN_CHUNK).expect("properties fit alone");

        let oversized = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"file", file(None))]),
            props: Some(props),
        };
        assert_eq!(encode_node(&oversized, true, MIN_CHUNK), Err(Error::Limit));
    }

    #[test]
    fn child_summary_binds_identity_count_and_weight() {
        let child = Node {
            level: 0,
            items: NodeItems::Leaf(vec![item(b"f", file(None))]),
            props: None,
        };
        let encoded = encode_node(&child, false, MIN_CHUNK).expect("child encoding");
        let identity = crate::identity::TERRANE_V1
            .calculate(crate::identity::IdentityKind::Node, &encoded)
            .expect("node identity")
            .terrane_v1_digest()
            .expect("profile digest");
        let mut reference = ChildRef {
            last_key: b"f".to_vec(),
            child: identity,
            count: 1,
            weight: encoded.len() as u64,
        };
        verify_child_ref(1, &reference, &child, &encoded, MIN_CHUNK).expect("exact child");

        reference.count = 2;
        assert_eq!(
            verify_child_ref(1, &reference, &child, &encoded, MIN_CHUNK),
            Err(Error::Node)
        );
        reference.count = 1;
        reference.weight += 1;
        assert_eq!(
            verify_child_ref(1, &reference, &child, &encoded, MIN_CHUNK),
            Err(Error::Node)
        );
    }

    #[test]
    fn hardlink_set_uses_first_key_and_identical_values() {
        let entries = [item(b"a", file(Some(b"a"))), item(b"b", file(Some(b"a")))];
        validate_tree_entries(&entries, TreeUse::Ordinary).expect("equal hardlinks");

        let wrong = [item(b"a", file(Some(b"b"))), item(b"b", file(Some(b"b")))];
        assert_eq!(
            validate_tree_entries(&wrong, TreeUse::Ordinary),
            Err(Error::Tree)
        );

        let mut changed = file(Some(b"a"));
        if let EntryKind::File { mode, .. } = &mut changed.kind {
            *mode = 0o600;
        }
        let divergent = [item(b"a", file(Some(b"a"))), item(b"b", changed)];
        assert_eq!(
            validate_tree_entries(&divergent, TreeUse::Ordinary),
            Err(Error::Tree)
        );
    }

    #[test]
    fn grafts_and_algebra_entries_are_contextual() {
        let graft = Entry {
            kind: EntryKind::Tree {
                root: [3; 32],
                props: None,
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        let entries = [item(b"a", graft), item(b"a/b", file(None))];
        assert_eq!(
            validate_tree_entries(&entries, TreeUse::Ordinary),
            Err(Error::Tree)
        );

        let whiteout = Entry {
            kind: EntryKind::Whiteout,
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        let entries = [item(b"a", whiteout)];
        validate_tree_entries(&entries, TreeUse::OverlayLayer).expect("layer marker");
        assert_eq!(
            validate_tree_entries(&entries, TreeUse::Surface),
            Err(Error::Tree)
        );
    }

    #[test]
    fn index_keys_are_opaque_bytes_at_construction_and_decode() {
        let index = || Entry {
            kind: EntryKind::Index {
                targets: vec![[1; 32]],
            },
            attrs: Vec::new(),
            attrs_present: false,
            xattrs: Vec::new(),
            xattrs_present: false,
            provenance: None,
        };
        let entries = [
            item(b"\0", index()),
            item(b"a\0b", index()),
            item(b"a/b", index()),
        ];
        validate_tree_entries(&entries, TreeUse::Index).expect("opaque keys in byte order");
        assert_eq!(validate_index_key(b""), Err(Error::Key));
        assert_eq!(validate_index_key(&vec![b'x'; 4097]), Err(Error::Key));

        let node = Node {
            level: 0,
            items: NodeItems::Leaf(entries.to_vec()),
            props: None,
        };
        let encoded =
            encode_node_for(&node, true, MIN_CHUNK, TreeUse::Index).expect("opaque index node");
        let decoded = decode_node_for(&encoded, true, MIN_CHUNK, TreeUse::Index)
            .expect("opaque index decode");
        assert_eq!(decoded, node);
        assert_eq!(decode_node(&encoded, true, MIN_CHUNK), Err(Error::Key));
        assert_eq!(encode_node(&node, true, MIN_CHUNK), Err(Error::Key));

        let ordinary_entries = [item(b"a/b", file(None))];
        assert_eq!(
            validate_tree_entries(&ordinary_entries, TreeUse::Ordinary),
            Err(Error::Tree)
        );
        let ordinary = Node {
            level: 0,
            items: NodeItems::Leaf(ordinary_entries.to_vec()),
            props: None,
        };
        let ordinary_bytes =
            encode_node(&ordinary, true, MIN_CHUNK).expect("single node checks local path grammar");
        assert!(decode_node(&ordinary_bytes, true, MIN_CHUNK).is_ok());
    }

    #[test]
    fn internal_index_keys_preserve_binary_last_key_order() {
        let node = Node {
            level: 1,
            items: NodeItems::Internal(vec![ChildRef {
                last_key: b"part/\0hash".to_vec(),
                child: [9; 32],
                count: 1,
                weight: 40,
            }]),
            props: None,
        };
        let encoded =
            encode_node_for(&node, true, MIN_CHUNK, TreeUse::Index).expect("binary last key");
        assert_eq!(
            decode_node_for(&encoded, true, MIN_CHUNK, TreeUse::Index),
            Ok(node)
        );
        assert_eq!(decode_node(&encoded, true, MIN_CHUNK), Err(Error::Key));
    }

    #[test]
    fn graft_chain_rejects_cycles_and_excessive_depth() {
        assert_eq!(validate_graft_chain(&[[1; 32], [1; 32]]), Err(Error::Tree));
        assert_eq!(validate_graft_chain(&[[1; 32]; 65]), Err(Error::Limit));
    }
}
