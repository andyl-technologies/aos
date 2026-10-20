//! Owns the canonical Entry codec and iterative conflict-base traversal.
//!
//! Conflict bases contain full entries; their depth is bounded by encoded
//! bytes rather than the separate tree-graft traversal limit.
//!
//! ```text
//! {1: 6, 12: [{1: 5}, {1: 5}], 13: {1: 5}}
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use crate::cbor::{self, Decoder};
use crate::identity::Digest;

use super::{
    Attribute, ContentRef, Entry, EntryKind, Error, ExtendedAttribute, MAX_ATTRIBUTES,
    MAX_COMPONENT, MAX_KEY, MAX_NODE_FRAMING_BYTES, MAX_NODE_ITEMS_BYTES, MAX_SYMLINK, Property,
    byte_key_order, digest, properties, text_key_order, validate_key,
};

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

fn attributes<'a>(decoder: &mut Decoder<'a>) -> Result<Vec<Attribute<'a>>, Error> {
    let count = decoder.map(MAX_ATTRIBUTES)?;
    let mut result = Vec::new();
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
    let mut result = Vec::new();
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

/// Decodes base chains with one shallow, input-backed frame per conflict.
pub(super) fn decode_entry<'a>(
    decoder: &mut Decoder<'a>,
    min_chunk_size: u64,
) -> Result<Entry<'a>, Error> {
    let mut parents = Vec::new();
    let mut value = loop {
        let (entry, pending_base) = decode_shallow(decoder, false, min_chunk_size)?;
        if !pending_base {
            break entry;
        }
        parents.push(entry);
    };

    while let Some(mut parent) = parents.pop() {
        if let EntryKind::Conflict { base, .. } = &mut parent.kind {
            *base = Some(Some(Box::new(value)));
        }
        value = parent;
    }
    Ok(value)
}

fn decode_shallow<'a>(
    decoder: &mut Decoder<'a>,
    candidate: bool,
    min_chunk_size: u64,
) -> Result<(Entry<'a>, bool), Error> {
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
    let mut pending_base = false;

    for index in 0..count {
        let field = decoder.uint()?;
        if field <= previous || field > 14 {
            return Err(Error::Entry);
        }
        previous = field;
        present |= 1 << field;
        match field {
            1 => {
                let value = decoder.uint()?;
                if candidate && value == 6 {
                    return Err(Error::Entry);
                }
                kind = Some(value);
            }
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
                if kind != Some(6) || candidate {
                    return Err(Error::Entry);
                }
                let length = decoder.array(MAX_NODE_ITEMS_BYTES)?;
                if length < 2 {
                    return Err(Error::Entry);
                }
                let mut values = Vec::new();
                for _ in 0..length {
                    let (entry, _) = decode_shallow(decoder, true, min_chunk_size)?;
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
                    // Only conflicts permit field 13, and it is their final
                    // field in canonical order. Finish this frame before
                    // descending into its full Entry base (TREE-31).
                    if kind != Some(6) || index + 1 != count {
                        return Err(Error::Entry);
                    }
                    pending_base = true;
                    break;
                }
            }
            14 => {
                let length = decoder.array(MAX_NODE_ITEMS_BYTES)?;
                if length == 0 {
                    return Err(Error::Entry);
                }
                let mut values = Vec::new();
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
    Ok((
        Entry {
            kind,
            attrs,
            attrs_present: present & bit(9) != 0,
            xattrs,
            xattrs_present: present & bit(10) != 0,
            provenance,
        },
        pending_base,
    ))
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
    let entry = decode_entry(&mut decoder, min_chunk_size)?;
    decoder.finish()?;
    Ok(entry)
}

pub(super) fn write_properties(output: &mut Vec<u8>, values: &[Property<'_>]) {
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

fn write_shallow<'e, 'a>(
    output: &mut Vec<u8>,
    entry: &'e Entry<'a>,
) -> Result<Option<&'e Entry<'a>>, Error> {
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
            if candidates.len() < 2 {
                return Err(Error::Entry);
            }
            for candidate in candidates {
                if matches!(candidate.kind, EntryKind::Conflict { .. }) {
                    return Err(Error::Entry);
                }
                write_shallow(output, candidate)?;
                if output.len() > MAX_NODE_ITEMS_BYTES + MAX_NODE_FRAMING_BYTES {
                    return Err(Error::Limit);
                }
            }
            if let Some(base) = base {
                cbor::write_uint(output, 13);
                if let Some(base) = base {
                    return Ok(Some(base));
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
    Ok(None)
}

/// Encodes one entry and rejects any shape the decoder would reject.
///
/// # Errors
/// Returns an error for invalid fields, canonical values, resource limits,
/// or a file content form incompatible with `min_chunk_size`.
pub fn encode_entry(entry: &Entry<'_>, min_chunk_size: u64) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    write_entry(&mut output, entry)?;
    decode_entry_bytes(&output, min_chunk_size)?;
    Ok(output)
}

/// Writes successive bases without consuming the call stack.
pub(super) fn write_entry(output: &mut Vec<u8>, mut entry: &Entry<'_>) -> Result<(), Error> {
    loop {
        let next = write_shallow(output, entry)?;
        if output.len() > MAX_NODE_ITEMS_BYTES + MAX_NODE_FRAMING_BYTES {
            return Err(Error::Limit);
        }
        match next {
            Some(base) => entry = base,
            None => return Ok(()),
        }
    }
}

// The public Box-based model preserves borrowed values and existing callers.
// Trait operations must also respect TREE-31's unrestricted full Entry base.
impl Drop for EntryKind<'_> {
    fn drop(&mut self) {
        fn detach<'a>(kind: &mut EntryKind<'a>, pending: &mut Vec<Entry<'a>>) {
            if let EntryKind::Conflict { candidates, base } = kind {
                pending.append(candidates);
                if let Some(Some(value)) = base.take() {
                    pending.push(*value);
                }
            }
        }

        let mut pending = Vec::new();
        detach(self, &mut pending);
        while let Some(mut entry) = pending.pop() {
            detach(&mut entry.kind, &mut pending);
        }
    }
}

impl<'a> EntryKind<'a> {
    /// Copies one frame, leaving the recursive base for its caller.
    fn clone_shallow(&self) -> Self {
        match self {
            Self::File {
                mode,
                size,
                content,
                link_id,
            } => Self::File {
                mode: *mode,
                size: *size,
                content: *content,
                link_id: *link_id,
            },
            Self::Directory { mode } => Self::Directory { mode: *mode },
            Self::Symlink { target } => Self::Symlink { target },
            Self::Tree { root, props } => Self::Tree {
                root: *root,
                props: props.clone(),
            },
            Self::Whiteout => Self::Whiteout,
            Self::Conflict { candidates, base } => Self::Conflict {
                candidates: candidates.clone(),
                base: base.as_ref().map(|_| None),
            },
            Self::Index { targets } => Self::Index {
                targets: targets.clone(),
            },
        }
    }
}

impl Clone for EntryKind<'_> {
    fn clone(&self) -> Self {
        let mut result = self.clone_shallow();
        let mut source = self;
        let mut frames = Vec::new();
        while let Self::Conflict {
            base: Some(Some(entry)),
            ..
        } = source
        {
            frames.push(Entry {
                kind: entry.kind.clone_shallow(),
                attrs: entry.attrs.clone(),
                attrs_present: entry.attrs_present,
                xattrs: entry.xattrs.clone(),
                xattrs_present: entry.xattrs_present,
                provenance: entry.provenance,
            });
            source = &entry.kind;
        }

        let mut child = None;
        while let Some(mut frame) = frames.pop() {
            if let (Self::Conflict { base, .. }, Some(value)) = (&mut frame.kind, child.take()) {
                *base = Some(Some(value));
            }
            child = Some(Box::new(frame));
        }
        if let (Self::Conflict { base, .. }, Some(value)) = (&mut result, child) {
            *base = Some(Some(value));
        }
        result
    }
}

impl PartialEq for EntryKind<'_> {
    fn eq(&self, other: &Self) -> bool {
        let (mut left, mut right) = (self, other);
        loop {
            match (left, right) {
                (
                    Self::File {
                        mode: a,
                        size: b,
                        content: c,
                        link_id: d,
                    },
                    Self::File {
                        mode: e,
                        size: f,
                        content: g,
                        link_id: h,
                    },
                ) => return (a, b, c, d) == (e, f, g, h),
                (Self::Directory { mode: a }, Self::Directory { mode: b }) => return a == b,
                (Self::Symlink { target: a }, Self::Symlink { target: b }) => return a == b,
                (Self::Tree { root: a, props: b }, Self::Tree { root: c, props: d }) => {
                    return (a, b) == (c, d);
                }
                (Self::Whiteout, Self::Whiteout) => return true,
                (Self::Index { targets: a }, Self::Index { targets: b }) => return a == b,
                (
                    Self::Conflict {
                        candidates: a,
                        base: b,
                    },
                    Self::Conflict {
                        candidates: c,
                        base: d,
                    },
                ) => {
                    if a != c {
                        return false;
                    }
                    match (b, d) {
                        (None, None) | (Some(None), Some(None)) => return true,
                        (Some(Some(a)), Some(Some(b))) => {
                            if a.attrs != b.attrs
                                || a.attrs_present != b.attrs_present
                                || a.xattrs != b.xattrs
                                || a.xattrs_present != b.xattrs_present
                                || a.provenance != b.provenance
                            {
                                return false;
                            }
                            (left, right) = (&a.kind, &b.kind);
                        }
                        _ => return false,
                    }
                }
                _ => return false,
            }
        }
    }
}

impl Eq for EntryKind<'_> {}

/// Formats one kind while optionally displaying its complete base chain.
struct KindDebug<'e, 'a>(&'e EntryKind<'a>, bool);

impl fmt::Debug for KindDebug<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            EntryKind::File {
                mode,
                size,
                content,
                link_id,
            } => f
                .debug_struct("File")
                .field("mode", mode)
                .field("size", size)
                .field("content", content)
                .field("link_id", link_id)
                .finish(),
            EntryKind::Directory { mode } => {
                f.debug_struct("Directory").field("mode", mode).finish()
            }
            EntryKind::Symlink { target } => {
                f.debug_struct("Symlink").field("target", target).finish()
            }
            EntryKind::Tree { root, props } => f
                .debug_struct("Tree")
                .field("root", root)
                .field("props", props)
                .finish(),
            EntryKind::Whiteout => f.write_str("Whiteout"),
            EntryKind::Index { targets } => {
                f.debug_struct("Index").field("targets", targets).finish()
            }
            EntryKind::Conflict { candidates, base } => {
                let mut fields = f.debug_struct("Conflict");
                fields.field("candidates", candidates);
                if self.1 {
                    fields.field("base", &BaseDebug(base));
                } else {
                    // Base frames appear in the enclosing flat list, making
                    // diagnostics safe for every successfully decoded chain.
                    fields.field("base_present", &base.is_some());
                }
                fields.finish()
            }
        }
    }
}

struct BaseDebug<'e, 'a>(&'e Option<Option<Box<Entry<'a>>>>);

impl fmt::Debug for BaseDebug<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut value = match self.0 {
            None => return f.write_str("None"),
            Some(None) => return f.write_str("Some(None)"),
            Some(Some(entry)) => entry.as_ref(),
        };
        let mut list = f.debug_list();
        loop {
            list.entry(&BaseFrameDebug(value));
            match &value.kind {
                EntryKind::Conflict {
                    base: Some(Some(entry)),
                    ..
                } => value = entry,
                EntryKind::Conflict {
                    base: Some(None), ..
                } => {
                    list.entry(&Option::<()>::None);
                    break;
                }
                _ => break,
            }
        }
        list.finish()
    }
}

struct BaseFrameDebug<'e, 'a>(&'e Entry<'a>);

impl fmt::Debug for BaseFrameDebug<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("kind", &KindDebug(&self.0.kind, false))
            .field("attrs", &self.0.attrs)
            .field("attrs_present", &self.0.attrs_present)
            .field("xattrs", &self.0.xattrs)
            .field("xattrs_present", &self.0.xattrs_present)
            .field("provenance", &self.0.provenance)
            .finish()
    }
}

impl fmt::Debug for EntryKind<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        KindDebug(self, true).fmt(f)
    }
}
