//! Copy-on-write placement updates with bounded page and path custody.
//!
//! Recursive frames contain only encoded child coordinates. The parent page is
//! released before descent and read again after the changed child is durable in
//! the append-only arena. Split and merge outputs therefore do not accumulate
//! one allocated page per tree level.

mod insert_batch;

use super::index_arena::Arena;
use super::index_format::{self as wire, Header, Key, Node, PageReference, Value};
use super::index_io::{Bytes, Operation};
use super::placement_index::{EncodedIndex, IndexSnapshot, read_into};
use super::*;

enum Root {
    Inline(Bytes),
    Page(PageReference),
}

#[derive(Clone, Copy)]
struct Child {
    upper: Key,
    reference: PageReference,
}

#[derive(Clone, Copy)]
struct Replacement {
    first: Option<Child>,
    second: Option<Child>,
}

impl Replacement {
    fn empty() -> Self {
        Self {
            first: None,
            second: None,
        }
    }

    fn one(child: Child) -> Self {
        Self {
            first: Some(child),
            second: None,
        }
    }

    fn count(self) -> usize {
        usize::from(self.first.is_some()) + usize::from(self.second.is_some())
    }
}

pub(super) struct Update {
    header: Header,
    root: Root,
    arena: Arena,
}

impl Update {
    pub(super) fn new(
        snapshot: &IndexSnapshot,
        backend: &PackedBlobBackend,
        operation: &mut Operation<'_>,
    ) -> Result<Self, StoreError> {
        let (root, arena) = match snapshot.header.arena {
            Some(identity) => {
                let arena = Arena::open(
                    backend,
                    identity,
                    snapshot.header.committed_bytes,
                    operation,
                )?;
                (Root::Page(PageReference::decode(snapshot.body())?), arena)
            }
            None => {
                let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
                bytes.value.extend_from_slice(snapshot.body());
                (Root::Inline(bytes), Arena::empty())
            }
        };

        Ok(Self {
            header: snapshot.header,
            root,
            arena,
        })
    }

    pub(super) fn clear_repack_plan(&mut self) {
        self.header.last_repack_plan = None;
    }

    pub(super) fn arena_identity(&self) -> Option<[u8; 32]> {
        self.arena.identity()
    }

    pub(super) fn uncommitted_backing(&self) -> bool {
        self.arena.modified()
    }

    pub(super) fn find(
        &self,
        key: Key,
        operation: &mut Operation<'_>,
    ) -> Result<Option<Value>, StoreError> {
        let mut reference = match &self.root {
            Root::Inline(bytes) => return lookup(&Node::parse(&bytes.value, true)?, key),
            Root::Page(reference) => *reference,
        };
        let mut root = true;
        let mut lower = None;
        let mut upper = None;
        let mut bytes = operation.buffer(wire::PAGE_BYTES)?;

        loop {
            self.load(reference, root, false, lower, upper, &mut bytes, operation)?;
            let node = Node::parse(&bytes.value, root)?;
            if node.height == 0 {
                return lookup(&node, key);
            }
            let slot = node.position(key)?;
            if slot == node.count {
                return Ok(None);
            }
            lower = if slot == 0 {
                lower
            } else {
                Some(node.key(slot - 1)?)
            };
            upper = Some(node.key(slot)?);
            reference = node.child(slot)?;
            root = false;
        }
    }

    /// Changes one tagged record; logical counters are checked before arena IO.
    pub(super) fn set(
        &mut self,
        backend: &PackedBlobBackend,
        key: Key,
        value: Option<Value>,
        operation: &mut Operation<'_>,
    ) -> Result<Option<Value>, StoreError> {
        if let Some(value) = value {
            value.validate_for(key)?;
        }
        let prior = self.find(key, operation)?;
        self.apply_known(backend, key, value, prior, operation)
    }

    /// Retains the point-insertion reference for differential component controls.
    #[cfg(test)]
    pub(super) fn insert_absent(
        &mut self,
        backend: &PackedBlobBackend,
        key: Key,
        value: Value,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        if self.find(key, operation)?.is_some() {
            return Err(StoreError::InvalidComposition {
                reason: "Packed insertion requires confirmed absence",
            });
        }
        value.validate_for(key)?;

        if matches!(self.root, Root::Page(_)) {
            // Preserve the preliminary page admission and allocation cut,
            // then retire it before header checks or copy-on-write pages.
            let page = operation.buffer(wire::PAGE_BYTES)?;
            drop(page);
            operation.check()?;
        }
        self.apply_known(backend, key, Some(value), None, operation)?;
        Ok(())
    }

    // Only the immediately preceding search supplies this scalar prior value.
    // No page bytes or absence certificate escape the mutably borrowed update.
    fn apply_known(
        &mut self,
        backend: &PackedBlobBackend,
        key: Key,
        value: Option<Value>,
        prior: Option<Value>,
        operation: &mut Operation<'_>,
    ) -> Result<Option<Value>, StoreError> {
        if prior == value {
            return Ok(prior);
        }
        let header = changed_header(self.header, key, prior, value)?;

        match &mut self.root {
            Root::Inline(bytes) => {
                edit_leaf(&mut bytes.value, key, value)?;
                let count = row_count(&bytes.value, 0)?;
                if count <= wire::MAX_ROWS {
                    wire::finish_node(&mut bytes.value, count, count as u64)?;
                } else {
                    // Move the only inline working page out before allocating
                    // its two outputs. No copied root remains in this owner.
                    let replacement = operation.buffer(wire::PAGE_BYTES)?;
                    let bytes = std::mem::replace(bytes, replacement);
                    let children = self.emit_rows(backend, &bytes.value, 0, operation)?;
                    drop(bytes);
                    self.root = Root::Page(self.make_root(backend, children, operation)?);
                }
            }
            Root::Page(reference) => {
                let reference = *reference;
                let replacement =
                    self.change_page(backend, reference, true, None, None, key, value, operation)?;
                self.root = match (replacement.first, replacement.second) {
                    (None, None) => Root::Inline(empty_leaf(operation)?),
                    (Some(child), None) => Root::Page(child.reference),
                    (Some(_), Some(_)) => {
                        Root::Page(self.make_root(backend, replacement, operation)?)
                    }
                    _ => return Err(StoreError::Incompatible),
                };
                self.collapse_root(operation)?;
            }
        }
        self.header = header;
        Ok(prior)
    }

    pub(super) fn finish(
        &mut self,
        backend: &PackedBlobBackend,
        operation: &mut Operation<'_>,
    ) -> Result<EncodedIndex, StoreError> {
        let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
        match &self.root {
            Root::Inline(node) => {
                self.header.arena = None;
                self.header.committed_bytes = 0;
                self.header.height = 0;
                self.header
                    .append(backend.configuration, &node.value, &mut bytes.value)?;
            }
            Root::Page(reference) => {
                self.arena.sync(operation)?;
                self.header.arena = self.arena.identity();
                self.header.committed_bytes = self.arena.length();
                self.header.height = reference.height;
                let mut encoded = [0; wire::REFERENCE_BYTES];
                encode_reference(*reference, &mut encoded);
                self.header
                    .append(backend.configuration, &encoded, &mut bytes.value)?;
            }
        }
        // The emitted root is checked independently before any caller can
        // publish it. The arena becomes reachable only at root replacement.
        Header::decode(&bytes.value, backend.configuration)?;
        Ok(EncodedIndex {
            bytes,
            header: self.header,
        })
    }

    // crucible-lint: allow rust-allow -- One frame records the exact bounded child and key interval.
    #[allow(
        clippy::too_many_arguments,
        reason = "One frame records the exact bounded child and key interval."
    )]
    fn change_page(
        &mut self,
        backend: &PackedBlobBackend,
        reference: PageReference,
        root: bool,
        lower: Option<Key>,
        upper: Option<Key>,
        key: Key,
        value: Option<Value>,
        operation: &mut Operation<'_>,
    ) -> Result<Replacement, StoreError> {
        let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
        self.load(reference, root, false, lower, upper, &mut bytes, operation)?;
        let node = Node::parse(&bytes.value, root)?;
        if node.height == 0 {
            edit_leaf(&mut bytes.value, key, value)?;
            return self.emit_rows(backend, &bytes.value, 0, operation);
        }

        let slot = node.position(key)?.min(node.count - 1);
        let child = node.child(slot)?;
        let child_lower = if slot == 0 {
            lower
        } else {
            Some(node.key(slot - 1)?)
        };
        let child_upper = Some(node.key(slot)?);
        let height = node.height;
        drop(bytes);

        let replacement = self.change_page(
            backend,
            child,
            false,
            child_lower,
            child_upper,
            key,
            value,
            operation,
        )?;

        let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
        self.load(reference, root, false, lower, upper, &mut bytes, operation)?;
        replace_children(&mut bytes.value, slot, 1, replacement)?;
        if replacement.count() == 1 {
            self.rebalance(backend, &mut bytes.value, slot, height, operation)?;
        }
        self.emit_rows(backend, &bytes.value, height, operation)
    }

    fn rebalance(
        &mut self,
        backend: &PackedBlobBackend,
        parent: &mut Vec<u8>,
        changed_slot: usize,
        height: u8,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        let count = row_count(parent, height)?;
        if count < 2 {
            return Ok(());
        }
        let changed = child_at(parent, changed_slot)?;
        let mut changed_bytes = operation.buffer(wire::PAGE_BYTES)?;
        self.load(
            changed.reference,
            false,
            true,
            None,
            Some(changed.upper),
            &mut changed_bytes,
            operation,
        )?;
        if Node::parse_pending(&changed_bytes.value)?.count >= wire::MIN_ROWS {
            return Ok(());
        }

        let first_slot = if changed_slot == 0 {
            0
        } else {
            changed_slot - 1
        };
        let sibling_slot = if changed_slot == 0 {
            1
        } else {
            changed_slot - 1
        };
        let sibling = child_at(parent, sibling_slot)?;
        let mut sibling_bytes = operation.buffer(wire::PAGE_BYTES)?;
        self.load(
            sibling.reference,
            false,
            false,
            None,
            Some(sibling.upper),
            &mut sibling_bytes,
            operation,
        )?;
        let (left, right) = if changed_slot == 0 {
            (&changed_bytes.value[..], &sibling_bytes.value[..])
        } else {
            (&sibling_bytes.value[..], &changed_bytes.value[..])
        };
        let children = self.emit_joined(backend, left, right, height - 1, operation)?;
        replace_children(parent, first_slot, 2, children)
    }

    fn emit_rows(
        &mut self,
        backend: &PackedBlobBackend,
        pending: &[u8],
        height: u8,
        operation: &mut Operation<'_>,
    ) -> Result<Replacement, StoreError> {
        let width = row_width(height);
        let rows = &pending[wire::PAGE_HEADER_BYTES..];
        let count = row_count(pending, height)?;
        self.emit_slices(backend, rows, &[], count, width, height, operation)
    }

    fn emit_joined(
        &mut self,
        backend: &PackedBlobBackend,
        left: &[u8],
        right: &[u8],
        height: u8,
        operation: &mut Operation<'_>,
    ) -> Result<Replacement, StoreError> {
        let left = Node::parse_pending(left)?;
        let right = Node::parse_pending(right)?;
        if left.count == 0
            || right.count == 0
            || left.height != height
            || right.height != height
            || left.key(left.count - 1)? >= right.key(0)?
        {
            return Err(StoreError::Incompatible);
        }
        // Borrow whole payload slices; no combined decoded array is allocated.
        let left_bytes = left.payload();
        let right_bytes = right.payload();
        self.emit_slices(
            backend,
            left_bytes,
            right_bytes,
            left.count + right.count,
            row_width(height),
            height,
            operation,
        )
    }

    // crucible-lint: allow rust-allow -- The two borrowed payloads share one fixed-width page geometry.
    #[allow(
        clippy::too_many_arguments,
        reason = "The two borrowed payloads share one fixed-width page geometry."
    )]
    fn emit_slices(
        &mut self,
        backend: &PackedBlobBackend,
        left: &[u8],
        right: &[u8],
        count: usize,
        width: usize,
        height: u8,
        operation: &mut Operation<'_>,
    ) -> Result<Replacement, StoreError> {
        if count == 0 {
            return Ok(Replacement::empty());
        }
        if count > wire::MAX_ROWS * 2 || left.len() + right.len() != count * width {
            return Err(StoreError::Incompatible);
        }
        let first_count = if count > wire::MAX_ROWS {
            count / 2
        } else {
            count
        };
        let mut first = operation.buffer(wire::PAGE_BYTES)?;
        wire::begin_node(&mut first.value, height);
        append_range(&mut first.value, left, right, 0, first_count * width)?;
        seal_pending(&mut first.value, height)?;
        let first = self.append_page(backend, &first.value, operation)?;

        if first_count == count {
            return Ok(Replacement::one(first));
        }
        let mut second = operation.buffer(wire::PAGE_BYTES)?;
        wire::begin_node(&mut second.value, height);
        append_range(
            &mut second.value,
            left,
            right,
            first_count * width,
            count * width,
        )?;
        seal_pending(&mut second.value, height)?;
        let second = self.append_page(backend, &second.value, operation)?;
        Ok(Replacement {
            first: Some(first),
            second: Some(second),
        })
    }

    fn make_root(
        &mut self,
        backend: &PackedBlobBackend,
        children: Replacement,
        operation: &mut Operation<'_>,
    ) -> Result<PageReference, StoreError> {
        let first = children.first.ok_or(StoreError::Incompatible)?;
        let second = children.second.ok_or(StoreError::Incompatible)?;
        let height = first
            .reference
            .height
            .checked_add(1)
            .ok_or(StoreError::Quota)?;
        if height as usize >= wire::MAX_HEIGHT || second.reference.height != first.reference.height
        {
            return Err(StoreError::Quota);
        }
        let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
        wire::begin_node(&mut bytes.value, height);
        append_child(&mut bytes.value, first);
        append_child(&mut bytes.value, second);
        seal_pending(&mut bytes.value, height)?;
        Ok(self
            .append_page(backend, &bytes.value, operation)?
            .reference)
    }

    fn collapse_root(&mut self, operation: &mut Operation<'_>) -> Result<(), StoreError> {
        loop {
            let reference = match self.root {
                Root::Page(reference) => reference,
                Root::Inline(_) => return Ok(()),
            };
            let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
            self.load(reference, true, true, None, None, &mut bytes, operation)?;
            let node = Node::parse_pending(&bytes.value)?;
            if node.height == 0 {
                self.root = Root::Inline(bytes);
                return Ok(());
            }
            if node.count == 1 {
                self.root = Root::Page(node.child(0)?);
                continue;
            }
            if node.records > wire::MAX_ROWS as u64 {
                return Ok(());
            }
            // At most sixty-four rows can have only one branch level and four
            // non-root leaves. Retain those scalar coordinates, then reuse the
            // root buffer as the inline output while one input page is live.
            if node.height != 1 || node.count > 4 {
                return Err(StoreError::Incompatible);
            }
            let count = node.count;
            let records = node.records;
            let mut children = [None; 4];
            for (slot, child) in children[..count].iter_mut().enumerate() {
                *child = Some(Child {
                    upper: node.key(slot)?,
                    reference: node.child(slot)?,
                });
            }
            wire::begin_node(&mut bytes.value, 0);
            let mut input = operation.buffer(wire::PAGE_BYTES)?;
            let mut lower = None;
            let mut rows = 0;
            for child in children.into_iter().flatten() {
                self.load(
                    child.reference,
                    false,
                    false,
                    lower,
                    Some(child.upper),
                    &mut input,
                    operation,
                )?;
                let leaf = Node::parse(&input.value, false)?;
                if leaf.height != 0 {
                    return Err(StoreError::Incompatible);
                }
                rows += leaf.count;
                if rows > wire::MAX_ROWS {
                    return Err(StoreError::Incompatible);
                }
                bytes.value.extend_from_slice(
                    &input.value[wire::PAGE_HEADER_BYTES..input.value.len() - 32],
                );
                lower = Some(child.upper);
            }
            if rows as u64 != records {
                return Err(StoreError::Incompatible);
            }
            wire::finish_node(&mut bytes.value, rows, records)?;
            self.root = Root::Inline(bytes);
            return Ok(());
        }
    }

    fn append_page(
        &mut self,
        backend: &PackedBlobBackend,
        bytes: &[u8],
        operation: &mut Operation<'_>,
    ) -> Result<Child, StoreError> {
        let node = Node::parse_pending(bytes)?;
        if node.count == 0 {
            return Err(StoreError::Incompatible);
        }
        let reference = self.arena.append(
            backend,
            self.header.instance,
            self.header.generation,
            bytes,
            operation,
        )?;
        Ok(Child {
            upper: node.key(node.count - 1)?,
            reference,
        })
    }

    // crucible-lint: allow rust-allow -- The load validates one exact reference and its parent interval.
    #[allow(
        clippy::too_many_arguments,
        reason = "The load validates one exact reference and its parent interval."
    )]
    fn load(
        &self,
        reference: PageReference,
        root: bool,
        pending: bool,
        lower: Option<Key>,
        upper: Option<Key>,
        bytes: &mut Bytes,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        reference.validate(self.arena.length())?;
        read_into(
            operation,
            self.arena.file()?,
            reference.offset,
            reference.length as usize,
            bytes,
        )?;
        let node = if pending {
            Node::parse_pending(&bytes.value)?
        } else {
            Node::parse(&bytes.value, root)?
        };
        node.validate_children_before(reference.offset)?;
        if node.height != reference.height
            || node.records != reference.records
            || wire::page_digest(&bytes.value)? != reference.digest
            || node.count == 0
        {
            return Err(StoreError::Incompatible);
        }
        if lower.is_some_and(|key| node.key(0).is_ok_and(|first| first <= key))
            || upper.is_some_and(|key| node.key(node.count - 1).is_ok_and(|last| last != key))
        {
            return Err(StoreError::Incompatible);
        }
        Ok(())
    }
}

fn empty_leaf(operation: &Operation<'_>) -> Result<Bytes, StoreError> {
    let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
    wire::begin_node(&mut bytes.value, 0);
    wire::finish_node(&mut bytes.value, 0, 0)?;
    Ok(bytes)
}

fn lookup(node: &Node<'_>, key: Key) -> Result<Option<Value>, StoreError> {
    let slot = node.position(key)?;
    if slot < node.count && node.key(slot)? == key {
        Ok(Some(node.value(slot)?))
    } else {
        Ok(None)
    }
}

fn row_width(height: u8) -> usize {
    if height == 0 {
        wire::LEAF_ROW_BYTES
    } else {
        wire::BRANCH_ROW_BYTES
    }
}

fn row_count(bytes: &[u8], height: u8) -> Result<usize, StoreError> {
    let length = bytes
        .len()
        .checked_sub(wire::PAGE_HEADER_BYTES)
        .ok_or(StoreError::Incompatible)?;
    if !length.is_multiple_of(row_width(height)) {
        return Err(StoreError::Incompatible);
    }
    Ok(length / row_width(height))
}

fn edit_leaf(bytes: &mut Vec<u8>, key: Key, value: Option<Value>) -> Result<(), StoreError> {
    let node = Node::parse(bytes, true)?;
    let slot = node.position(key)?;
    let present = slot < node.count && node.key(slot)? == key;
    bytes.truncate(bytes.len() - 32);
    let start = wire::PAGE_HEADER_BYTES + slot * wire::LEAF_ROW_BYTES;
    let removed = if present { wire::LEAF_ROW_BYTES } else { 0 };
    let mut encoded = [0; wire::LEAF_ROW_BYTES];
    encoded[..wire::KEY_BYTES].copy_from_slice(&key.0);
    if let Some(value) = value {
        encoded[wire::KEY_BYTES..].copy_from_slice(&value.0);
    }
    splice(
        bytes,
        start,
        removed,
        if value.is_some() { &encoded } else { &[] },
    )
}

fn splice(
    bytes: &mut Vec<u8>,
    start: usize,
    removed: usize,
    replacement: &[u8],
) -> Result<(), StoreError> {
    let tail = start.checked_add(removed).ok_or(StoreError::Quota)?;
    let length = bytes
        .len()
        .checked_sub(removed)
        .and_then(|n| n.checked_add(replacement.len()))
        .ok_or(StoreError::Quota)?;
    if tail > bytes.len() || length + 32 > bytes.capacity() {
        return Err(StoreError::Quota);
    }
    let old_length = bytes.len();
    if length > old_length {
        bytes.resize(length, 0);
    }
    bytes.copy_within(tail..old_length, start + replacement.len());
    bytes[start..start + replacement.len()].copy_from_slice(replacement);
    bytes.truncate(length);
    Ok(())
}

fn child_at(bytes: &[u8], slot: usize) -> Result<Child, StoreError> {
    let start = wire::PAGE_HEADER_BYTES + slot * wire::BRANCH_ROW_BYTES;
    let row = bytes
        .get(start..start + wire::BRANCH_ROW_BYTES)
        .ok_or(StoreError::Incompatible)?;
    Ok(Child {
        upper: Key(row[..wire::KEY_BYTES]
            .try_into()
            .map_err(|_| StoreError::Incompatible)?),
        reference: PageReference::decode(&row[wire::KEY_BYTES..])?,
    })
}

fn encode_reference(reference: PageReference, bytes: &mut [u8; wire::REFERENCE_BYTES]) {
    bytes[..8].copy_from_slice(&reference.offset.to_be_bytes());
    bytes[8..12].copy_from_slice(&reference.length.to_be_bytes());
    bytes[12..44].copy_from_slice(&reference.digest);
    bytes[44..52].copy_from_slice(&reference.records.to_be_bytes());
    bytes[52] = reference.height;
}

fn append_child(bytes: &mut Vec<u8>, child: Child) {
    bytes.extend_from_slice(&child.upper.0);
    child.reference.append(bytes);
}

fn replace_children(
    bytes: &mut Vec<u8>,
    slot: usize,
    removed: usize,
    children: Replacement,
) -> Result<(), StoreError> {
    // A sealed input loses its checksum exactly once; further edits operate on
    // the same unsealed payload until emit_rows computes the new one.
    let height = *bytes.get(17).ok_or(StoreError::Incompatible)?;
    if (bytes.len() - wire::PAGE_HEADER_BYTES) % row_width(height) == 32 {
        bytes.truncate(bytes.len() - 32);
    }
    let mut encoded = [0; wire::BRANCH_ROW_BYTES * 2];
    let mut count = 0;
    for child in [children.first, children.second].into_iter().flatten() {
        let start = count * wire::BRANCH_ROW_BYTES;
        encoded[start..start + wire::KEY_BYTES].copy_from_slice(&child.upper.0);
        let mut reference = [0; wire::REFERENCE_BYTES];
        encode_reference(child.reference, &mut reference);
        encoded[start + wire::KEY_BYTES..start + wire::BRANCH_ROW_BYTES]
            .copy_from_slice(&reference);
        count += 1;
    }
    splice(
        bytes,
        wire::PAGE_HEADER_BYTES + slot * wire::BRANCH_ROW_BYTES,
        removed * wire::BRANCH_ROW_BYTES,
        &encoded[..count * wire::BRANCH_ROW_BYTES],
    )
}

fn seal_pending(bytes: &mut Vec<u8>, height: u8) -> Result<(), StoreError> {
    let count = row_count(bytes, height)?;
    let mut records = 0_u64;
    for slot in 0..count {
        let added = if height == 0 {
            1
        } else {
            child_at(bytes, slot)?.reference.records
        };
        records = records.checked_add(added).ok_or(StoreError::Quota)?;
    }
    wire::finish_node(bytes, count, records)
}

fn append_range(
    out: &mut Vec<u8>,
    left: &[u8],
    right: &[u8],
    start: usize,
    end: usize,
) -> Result<(), StoreError> {
    if start > end
        || end > left.len() + right.len()
        || out.len() + end - start + 32 > out.capacity()
    {
        return Err(StoreError::Quota);
    }
    if start < left.len() {
        out.extend_from_slice(&left[start..end.min(left.len())]);
    }
    if end > left.len() {
        out.extend_from_slice(&right[start.saturating_sub(left.len())..end - left.len()]);
    }
    Ok(())
}

fn changed_header(
    mut header: Header,
    key: Key,
    old: Option<Value>,
    new: Option<Value>,
) -> Result<Header, StoreError> {
    let count = |number: u64| {
        number
            .checked_sub(u64::from(old.is_some()))
            .and_then(|n| n.checked_add(u64::from(new.is_some())))
            .ok_or(StoreError::Quota)
    };
    if key.0[0] == 0 {
        key.id()?;
        header.count = count(header.count)?;
        let old_bytes = old
            .map(Value::entry)
            .transpose()?
            .map_or(0, |entry| entry.length);
        let new_bytes = new
            .map(Value::entry)
            .transpose()?
            .map_or(0, |entry| entry.length);
        header.logical_bytes = header
            .logical_bytes
            .checked_sub(old_bytes)
            .and_then(|n| n.checked_add(new_bytes))
            .ok_or(StoreError::Quota)?;
        header.generation = header.generation.checked_add(1).ok_or(StoreError::Quota)?;
        header.last_repack_plan = None;
    } else {
        key.pack_id()?;
        header.packs = count(header.packs)?;
        let old_bytes = old
            .map(Value::pack_record)
            .transpose()?
            .map_or(0, |record| record.physical_bytes);
        let new_bytes = new
            .map(Value::pack_record)
            .transpose()?
            .map_or(0, |record| record.physical_bytes);
        header.physical_bytes = header
            .physical_bytes
            .checked_sub(old_bytes)
            .and_then(|n| n.checked_add(new_bytes))
            .ok_or(StoreError::Quota)?;
    }
    header.records = header
        .count
        .checked_add(header.packs)
        .ok_or(StoreError::Quota)?;
    Ok(header)
}
