//! Encodes and decodes canonical tree entries and prolly-tree nodes.
//!
//! A node decoder validates local ordering, prefix compression, shape, and
//! resource limits. [`validate_tree_entries`] checks invariants that cross
//! node boundaries after a reader has loaded the complete ordered tree.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use crate::cbor::{self, Decoder};
use crate::identity::Digest;

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
    Directory { mode: u16 },
    /// A verbatim symlink target.
    Symlink { target: &'a [u8] },
    /// A reference to another tree root with optional overriding properties.
    Tree { root: Digest, props: Option<Vec<Property<'a>>> },
    /// An overlay-layer deletion marker.
    Whiteout,
    /// An unresolved merge result in side order.
    Conflict { candidates: Vec<Entry<'a>>, base: Option<Option<Box<Entry<'a>>>> },
    /// Sorted, unique object identities in an index tree.
    Index { targets: Vec<Digest> },
}

/// A tree value with common attributes and introducing provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    /// Type-specific payload.
    pub kind: EntryKind<'a>,
    /// Writer-supplied or derived canonical attributes.
    pub attrs: Vec<Attribute<'a>>,
    /// Raw filesystem extended attributes.
    pub xattrs: Vec<ExtendedAttribute<'a>>,
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
        0 => { decoder.uint()?; }
        3 => { decoder.text(MAX_NODE_ITEMS_BYTES)?; }
        4 => {
            let count = decoder.array(MAX_NODE_ITEMS_BYTES)?;
            for _ in 0..count { property_value(decoder, depth + 1)?; }
        }
        5 => {
            let count = decoder.map(MAX_NODE_ITEMS_BYTES)?;
            let mut previous = None;
            for _ in 0..count {
                let key = decoder.text(MAX_COMPONENT)?;
                if key.is_empty() || previous.is_some_and(|prior: &str| text_key_order(prior, key) != Ordering::Less) {
                    return Err(Error::Entry);
                }
                previous = Some(key);
                property_value(decoder, depth + 1)?;
            }
        }
        7 => {
            if decoder.simple()? == 0xf6 { return Err(Error::Entry); }
        }
        _ => return Err(Error::Entry),
    }
    Ok(())
}

fn text_key_order(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.as_bytes().cmp(right.as_bytes()))
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
        if name.is_empty() || previous.is_some_and(|prior: &str| text_key_order(prior, name) != Ordering::Less) {
            return Err(Error::Entry);
        }
        previous = Some(name);
        let start = decoder.position();
        property_value(decoder, 0)?;
        result.push(Property { name, value: decoder.slice(start, decoder.position())? });
    }
    Ok(result)
}

fn attributes<'a>(decoder: &mut Decoder<'a>) -> Result<Vec<Attribute<'a>>, Error> {
    let count = decoder.map(MAX_ATTRIBUTES)?;
    let mut result = Vec::with_capacity(count);
    let mut previous = None;
    for _ in 0..count {
        let name = decoder.text(MAX_COMPONENT)?;
        if name.is_empty() || previous.is_some_and(|prior: &str| text_key_order(prior, name) != Ordering::Less) {
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
        if name.is_empty() || previous.is_some_and(|prior: &[u8]| byte_key_order(prior, name) != Ordering::Less) {
            return Err(Error::Entry);
        }
        previous = Some(name);
        let value = decoder.bytes(MAX_NODE_ITEMS_BYTES)?;
        result.push(ExtendedAttribute { name, value });
    }
    Ok(result)
}

fn decode_entry<'a>(decoder: &mut Decoder<'a>, depth: usize, min_chunk_size: u64) -> Result<Entry<'a>, Error> {
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
                if value > 0x0fff { return Err(Error::Entry); }
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
                if length < 2 { return Err(Error::Entry); }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    let entry = decode_entry(decoder, depth + 1, min_chunk_size)?;
                    if matches!(entry.kind, EntryKind::Conflict { .. }) { return Err(Error::Entry); }
                    values.push(entry);
                }
                candidates = Some(values);
            }
            13 => {
                if decoder.peek_major()? == 7 {
                    if decoder.simple()? != 0xf6 { return Err(Error::Entry); }
                    base = Some(None);
                } else {
                    let entry = decode_entry(decoder, depth + 1, min_chunk_size)?;
                    base = Some(Some(Box::new(entry)));
                }
            }
            14 => {
                let length = decoder.array(MAX_NODE_ITEMS_BYTES)?;
                if length == 0 { return Err(Error::Entry); }
                let mut values = Vec::with_capacity(length);
                for _ in 0..length {
                    let value = digest(decoder)?;
                    if values.last().is_some_and(|prior: &Digest| value <= *prior) { return Err(Error::Entry); }
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
            if !correct { return Err(Error::Entry); }
            EntryKind::File { mode: mode.ok_or(Error::Entry)?, size, content, link_id }
        }
        2 => EntryKind::Directory { mode: mode.ok_or(Error::Entry)? },
        3 => EntryKind::Symlink { target: target.ok_or(Error::Entry)? },
        4 => EntryKind::Tree { root: root.ok_or(Error::Entry)?, props },
        5 => EntryKind::Whiteout,
        6 => EntryKind::Conflict { candidates: candidates.ok_or(Error::Entry)?, base },
        7 => EntryKind::Index { targets: targets.ok_or(Error::Entry)? },
        8..=15 => return Err(Error::ReservedType),
        _ => return Err(Error::Entry),
    };

    let allowed = match &kind {
        EntryKind::File { .. } => bit(1) | bit(2) | bit(3) | bit(4) | bit(8) | bit(9) | bit(10) | bit(11),
        EntryKind::Directory { .. } => bit(1) | bit(2) | bit(9) | bit(10) | bit(11),
        EntryKind::Symlink { .. } => bit(1) | bit(5) | bit(9) | bit(10) | bit(11),
        EntryKind::Tree { .. } => bit(1) | bit(6) | bit(7) | bit(9) | bit(10) | bit(11),
        EntryKind::Whiteout => bit(1) | bit(11),
        EntryKind::Conflict { .. } => bit(1) | bit(9) | bit(10) | bit(11) | bit(12) | bit(13),
        EntryKind::Index { .. } => bit(1) | bit(9) | bit(10) | bit(11) | bit(14),
    };
    if present & !allowed != 0 { return Err(Error::Entry); }
    if matches!(kind, EntryKind::Whiteout) && (!attrs.is_empty() || !xattrs.is_empty()) {
        return Err(Error::Entry);
    }
    Ok(Entry { kind, attrs, xattrs, provenance })
}

const fn bit(field: u32) -> u16 { 1 << field }

/// Decodes one standalone entry using the configured chunk profile minimum.
///
/// # Errors
/// Rejects invalid CBOR, unknown or reserved fields/types, incompatible
/// content references, and any entry resource limit.
pub fn decode_entry_bytes(input: &[u8], min_chunk_size: u64) -> Result<Entry<'_>, Error> {
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
    if depth >= MAX_GRAFT_DEPTH { return Err(Error::Limit); }
    let common = usize::from(!entry.attrs.is_empty())
        + usize::from(!entry.xattrs.is_empty())
        + usize::from(entry.provenance.is_some());
    let fields = match &entry.kind {
        EntryKind::File { link_id, .. } => 4 + usize::from(link_id.is_some()),
        EntryKind::Directory { .. } | EntryKind::Symlink { .. } | EntryKind::Tree { props: None, .. } => 2,
        EntryKind::Tree { props: Some(_), .. } => 3,
        EntryKind::Whiteout => 1,
        EntryKind::Conflict { base, .. } => 2 + usize::from(base.is_some()),
        EntryKind::Index { .. } => 2,
    };
    cbor::write_map(output, fields + common);
    cbor::write_uint(output, 1);
    cbor::write_uint(output, match &entry.kind {
        EntryKind::File { .. } => 1,
        EntryKind::Directory { .. } => 2,
        EntryKind::Symlink { .. } => 3,
        EntryKind::Tree { .. } => 4,
        EntryKind::Whiteout => 5,
        EntryKind::Conflict { .. } => 6,
        EntryKind::Index { .. } => 7,
    });

    match &entry.kind {
        EntryKind::File { mode, size, content, .. } => {
            cbor::write_uint(output, 2); cbor::write_uint(output, u64::from(*mode));
            cbor::write_uint(output, 3); cbor::write_uint(output, *size);
            cbor::write_uint(output, 4); cbor::write_array(output, 2);
            match content {
                ContentRef::Inline(hash) => { cbor::write_uint(output, 0); cbor::write_bytes(output, hash); }
                ContentRef::Manifest(hash) => { cbor::write_uint(output, 1); cbor::write_bytes(output, hash); }
            }
        }
        EntryKind::Directory { mode } => {
            cbor::write_uint(output, 2); cbor::write_uint(output, u64::from(*mode));
        }
        EntryKind::Symlink { target } => {
            cbor::write_uint(output, 5); cbor::write_bytes(output, target);
        }
        EntryKind::Tree { root, props } => {
            cbor::write_uint(output, 6); cbor::write_bytes(output, root);
            if let Some(props) = props {
                cbor::write_uint(output, 7); write_properties(output, props);
            }
        }
        EntryKind::Whiteout | EntryKind::Conflict { .. } | EntryKind::Index { .. } => {}
    }

    if let EntryKind::File { link_id: Some(key), .. } = &entry.kind {
        cbor::write_uint(output, 8); cbor::write_bytes(output, key);
    }
    if !entry.attrs.is_empty() {
        cbor::write_uint(output, 9); write_attributes(output, &entry.attrs);
    }
    if !entry.xattrs.is_empty() {
        cbor::write_uint(output, 10); write_extended_attributes(output, &entry.xattrs);
    }
    if let Some(provenance) = entry.provenance {
        cbor::write_uint(output, 11); cbor::write_bytes(output, &provenance);
    }

    match &entry.kind {
        EntryKind::Conflict { candidates, base } => {
            cbor::write_uint(output, 12); cbor::write_array(output, candidates.len());
            for candidate in candidates { write_entry(output, candidate, depth + 1)?; }
            if let Some(base) = base {
                cbor::write_uint(output, 13);
                if let Some(base) = base { write_entry(output, base, depth + 1)?; }
                else { output.push(0xf6); }
            }
        }
        EntryKind::Index { targets } => {
            cbor::write_uint(output, 14); cbor::write_array(output, targets.len());
            for target in targets { cbor::write_bytes(output, target); }
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
