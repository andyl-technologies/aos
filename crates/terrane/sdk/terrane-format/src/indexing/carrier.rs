//! Validates contextual primary, gap and occurrence-route carrier data.
//!
//! ```text
//! terminal = {1: 7, 14: [O32]}
//! forward = {1: 7, 9: {"index.occurrences": P32}, 14: [O32]}
//! index-gaps = {"value": "lowercase-node-hex64", "inherit": false}
//! ```
//!
//! Roles and semantic revisions come from the caller. Syntax establishes no
//! namespace relationship, nonempty continuation, complete coverage or authority.

use super::{Error, IndexKey};
use crate::cbor::{self, Decoder};
use crate::identity::Digest;
use crate::tree_format::{self, Entry, EntryKind, Node, NodeItems};
use alloc::vec::Vec;

/// The contextual structural pointer name, excluded from value registrations.
pub const OCCURRENCES_ATTRIBUTE: &str = "index.occurrences";

/// Explicit revisions supported by the completed executable carrier profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticContext(());

impl SemanticContext {
    /// Checks the property, attribute and physical tree semantic revisions.
    ///
    /// This checks ordinary revision data; callers independently authenticate
    /// the represented vocabularies and the context's source.
    ///
    /// # Errors
    /// Rejects every combination except property 3, attribute 2 and tree 1.
    pub fn new(property: u64, attribute: u64, tree: u64) -> Result<Self, Error> {
        if (property, attribute, tree) != (3, 2, 1) {
            return Err(Error::Schema);
        }
        Ok(Self(()))
    }
}

/// A role supplied by the independently selected owner or traversed edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Canonical value plus object identity, with mandatory continuation.
    Primary,
    /// Missing object's identity, with mandatory continuation.
    Gap,
    /// Root-local paths to matching files or graft continuations.
    PresentRoute,
    /// Root-local paths to files lacking the attribute or graft continuations.
    MissingRoute,
}

/// A closed type-7 row retaining its object separately from its continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Row {
    object: Digest,
    route: Option<Digest>,
}

impl Row {
    /// Returns the retained namespace file's Chunk or Manifest identity.
    pub const fn object(self) -> Digest {
        self.object
    }

    /// Returns the continuation Node identity when the row forwards.
    pub const fn route(self) -> Option<Digest> {
        self.route
    }
}

/// Classifies the exact closed terminal or forwarding shape in active context.
///
/// # Errors
/// Rejects non-Index entries, multiple targets, extra metadata, explicit empty
/// maps, other attributes, malformed pointers or pointers of the wrong width.
pub fn classify_entry(_context: SemanticContext, entry: &Entry<'_>) -> Result<Row, Error> {
    let EntryKind::Index { targets } = &entry.kind else {
        return Err(Error::Schema);
    };
    let [object] = targets.as_slice() else {
        return Err(Error::Schema);
    };
    if entry.xattrs_present || !entry.xattrs.is_empty() || entry.provenance.is_some() {
        return Err(Error::Schema);
    }

    let route = match entry.attrs.as_slice() {
        [] if !entry.attrs_present => None,
        [attribute] if entry.attrs_present && attribute.name == OCCURRENCES_ATTRIBUTE => {
            let mut decoder = Decoder::new(attribute.value);
            let route = decoder.bytes(32)?.try_into().map_err(|_| Error::Schema)?;
            decoder.finish()?;
            Some(route)
        }
        _ => return Err(Error::Schema),
    };
    Ok(Row {
        object: *object,
        route,
    })
}

/// Validates a full key and closed entry against an explicitly supplied role.
///
/// # Errors
/// Rejects invalid key grammar or limits, mismatched object suffixes, terminal
/// primary/gap rows, and entries outside the closed carrier shapes.
pub fn validate_row(
    context: SemanticContext,
    role: Role,
    key: &[u8],
    entry: &Entry<'_>,
) -> Result<Row, Error> {
    let row = classify_entry(context, entry)?;
    validate_key(role, key)?;
    match role {
        Role::Primary => {
            if IndexKey::decode(key)?.object() != row.object || row.route.is_none() {
                return Err(Error::Schema);
            }
        }
        Role::Gap => {
            if key != row.object || row.route.is_none() {
                return Err(Error::Schema);
            }
        }
        Role::PresentRoute | Role::MissingRoute => {}
    }
    Ok(row)
}

fn validate_key(role: Role, key: &[u8]) -> Result<(), Error> {
    match role {
        Role::Primary => {
            IndexKey::decode(key)?;
        }
        Role::Gap if key.len() == 32 => {}
        Role::Gap => return Err(Error::Schema),
        Role::PresentRoute | Role::MissingRoute => {
            tree_format::validate_key(key).map_err(|error| match error {
                tree_format::Error::Limit => Error::Limit,
                _ => Error::Schema,
            })?;
        }
    }
    Ok(())
}

/// Validates contextual rows, internal separator grammars and property placement.
///
/// The node must separately pass physical Node validation. This function does
/// not fetch children, verify separator summaries or prove nonempty referenced
/// routes/gaps. An empty physical root remains valid ordinary data.
///
/// # Errors
/// Rejects role-invalid rows or separators, properties on nonroots or auxiliary
/// roles, other primary properties, and explicit empty primary property maps.
pub fn validate_node(
    context: SemanticContext,
    role: Role,
    node: &Node<'_>,
    is_root: bool,
) -> Result<Option<GapBinding>, Error> {
    let gap = match node.props.as_deref() {
        None => None,
        Some([property]) if is_root && role == Role::Primary && property.name == "index-gaps" => {
            Some(GapBinding::decode_binding(property.value)?)
        }
        Some(_) => return Err(Error::Schema),
    };
    match &node.items {
        NodeItems::Leaf(items) => {
            for item in items {
                validate_row(context, role, &item.key, &item.entry)?;
            }
        }
        NodeItems::Internal(children) => {
            for child in children {
                validate_key(role, &child.last_key)?;
            }
        }
    }
    Ok(gap)
}

/// An unverified missing-object Node identity in an exact noninherited binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GapBinding(Digest);

impl GapBinding {
    /// Constructs ordinary pointer data without asserting a nonempty gap tree.
    pub const fn new(node: Digest) -> Self {
        Self(node)
    }

    /// Returns the referenced gap Node identity.
    pub const fn node(self) -> Digest {
        self.0
    }

    /// Decodes the exact `index-gaps` property wrapper.
    ///
    /// # Errors
    /// Rejects bare or inherited values, extra fields, noncanonical CBOR,
    /// uppercase or malformed hex, incorrect widths and trailing bytes.
    pub fn decode_binding(encoded: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(encoded);
        if decoder.map(2)? != 2 || decoder.text(5)? != "value" {
            return Err(Error::Schema);
        }
        let text = decoder.text(64)?;
        if text.len() != 64 {
            return Err(Error::Schema);
        }
        let mut node = [0; 32];
        for (pair, byte) in text.as_bytes().as_chunks::<2>().0.iter().zip(&mut node) {
            *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        if decoder.text(7)? != "inherit" || decoder.simple()? != 0xf4 {
            return Err(Error::Schema);
        }
        decoder.finish()?;
        Ok(Self(node))
    }

    /// Encodes the exact canonical noninherited property binding.
    pub fn encode_binding(self) -> Vec<u8> {
        let mut output = Vec::new();
        cbor::write_map(&mut output, 2);
        cbor::write_text(&mut output, "value");
        cbor::write_argument(&mut output, 3, 64);
        for byte in self.0 {
            output.push(b"0123456789abcdef"[usize::from(byte >> 4)]);
            output.push(b"0123456789abcdef"[usize::from(byte & 15)]);
        }
        cbor::write_text(&mut output, "inherit");
        output.push(0xf4);
        output
    }
}

fn hex_digit(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(Error::Schema),
    }
}

/// Checks structural attribute placement under an explicit recorded revision.
///
/// Revision 1 preserves pointer bytes inertly. Revision 2 rejects the pointer
/// on namespace entries; active carriers require [`SemanticContext`] instead.
/// This helper does not apply strict value-name policy or physical validation.
///
/// # Errors
/// Rejects unsupported revisions and revision-2 namespace structural pointers.
pub fn validate_namespace_attributes(
    attribute_revision: u64,
    entry: &Entry<'_>,
) -> Result<(), Error> {
    match attribute_revision {
        1 => Ok(()),
        2 if !entry
            .attrs
            .iter()
            .any(|attribute| attribute.name == OCCURRENCES_ATTRIBUTE) =>
        {
            Ok(())
        }
        _ => Err(Error::Schema),
    }
}
