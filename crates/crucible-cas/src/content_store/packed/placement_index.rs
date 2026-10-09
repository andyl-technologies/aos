//! Bounded placement lookup and ordered cursors over one committed arena.
//!
//! Small stores keep the leaf inside their root file. Larger stores authenticate
//! one immutable page at a time while retaining the state fence; deferred pack
//! readers never depend on a live placement cursor.

use super::*;
use crate::owned_decode::DecodeBudget;
use std::os::unix::fs::FileExt;

use super::index_format::{self as wire, Header, Key, Node, PageReference, Value};
use super::index_io::{self, Bytes, IndexFile, Operation};

pub(super) struct IndexSnapshot {
    bytes: Bytes,
    pub(super) header: Header,
}

pub(super) struct EncodedIndex {
    pub(super) bytes: Bytes,
    pub(super) header: Header,
}

impl EncodedIndex {
    pub(super) fn empty(
        backend: &PackedBlobBackend,
        instance: [u8; 32],
        original: &DecodeBudget,
    ) -> Result<Self, StoreError> {
        Self::empty_under(
            backend,
            instance,
            &mut Operation {
                original: Some(original),
                boundary: &mut || Ok(()),
            },
        )
    }

    pub(super) fn empty_under(
        backend: &PackedBlobBackend,
        instance: [u8; 32],
        operation: &mut Operation<'_>,
    ) -> Result<Self, StoreError> {
        let header = Header::empty(instance);
        let mut node = operation.buffer(wire::PAGE_HEADER_BYTES + 32)?;
        wire::begin_node(&mut node.value, 0);
        wire::finish_node(&mut node.value, 0, 0)?;
        let mut bytes = operation.buffer(wire::ROOT_HEADER_BYTES + node.value.len() + 32)?;
        header.append(backend.configuration, &node.value, &mut bytes.value)?;
        Ok(Self { bytes, header })
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes.value
    }

    pub(super) fn snapshot(self) -> IndexSnapshot {
        IndexSnapshot {
            bytes: self.bytes,
            header: self.header,
        }
    }
}

impl IndexSnapshot {
    pub(super) fn encoded_bytes(&self) -> &[u8] {
        &self.bytes.value
    }

    #[cfg(test)]
    pub(super) fn inserted(
        &self,
        backend: &PackedBlobBackend,
        id: ContentId,
        entry: IndexEntry,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<EncodedIndex, StoreError> {
        let physical_bytes = entry
            .offset
            .checked_add(entry.length)
            .ok_or(StoreError::Quota)?;
        super::maintenance::replacement(
            backend,
            self,
            &[(id, entry)],
            physical_bytes,
            &mut Operation {
                original: Some(original),
                boundary,
            },
            &mut checked_publication::Progress::default(),
        )
    }

    pub(super) fn load(
        backend: &PackedBlobBackend,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        Self::load_under(
            backend,
            &mut Operation {
                original: Some(original),
                boundary,
            },
        )
    }

    pub(super) fn load_under(
        backend: &PackedBlobBackend,
        operation: &mut Operation<'_>,
    ) -> Result<Self, StoreError> {
        operation.with_path(&backend.admin, INDEX_FILE, |operation, path| {
            let file = operation.open(path, false)?;
            let length =
                usize::try_from(operation.length(&file)?).map_err(|_| StoreError::Quota)?;
            let mut version = [0; 16];
            operation.read_exact(file.file(), &mut version, 0)?;
            Header::require_version(&version)?;
            if length > wire::PAGE_BYTES {
                return Err(StoreError::Quota);
            }
            let bytes = operation.read(file.file(), 0, length)?;
            let header = Header::decode(&bytes.value, backend.configuration)?;
            operation.require_eof(file.file(), length as u64)?;
            operation.sync_admin(backend)?;
            Ok(Self { bytes, header })
        })
    }

    pub(super) fn body(&self) -> &[u8] {
        &self.bytes.value[wire::ROOT_HEADER_BYTES..self.bytes.value.len() - 32]
    }

    pub(super) fn digest(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"crucible.content-store.packed-index-digest.v2");
        hash.update(&self.bytes.value);
        *hash.finalize().as_bytes()
    }

    pub(super) fn reader<'a>(
        &'a self,
        backend: &PackedBlobBackend,
        operation: &mut Operation<'_>,
    ) -> Result<Reader<'a>, StoreError> {
        let arena = if let Some(arena) = self.header.arena {
            let name = index_io::arena_name(arena);
            let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
            let file = operation.with_path(&backend.admin, name, |operation, path| {
                operation.open(path, false)
            })?;
            if operation.length(&file)? < self.header.committed_bytes {
                return Err(StoreError::Incompatible);
            }
            Some(file)
        } else {
            None
        };
        Ok(Reader {
            snapshot: self,
            arena,
        })
    }

    pub(super) fn find(
        &self,
        backend: &PackedBlobBackend,
        id: ContentId,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Option<IndexEntry>, StoreError> {
        let mut operation = Operation {
            original: Some(original),
            boundary,
        };
        self.reader(backend, &mut operation)?
            .find(Key::object(id), &mut operation)?
            .map(Value::entry)
            .transpose()
    }
}

pub(super) struct Reader<'a> {
    snapshot: &'a IndexSnapshot,
    arena: Option<IndexFile>,
}

impl<'s> Reader<'s> {
    pub(super) fn find(
        &self,
        key: Key,
        operation: &mut Operation<'_>,
    ) -> Result<Option<Value>, StoreError> {
        if self.arena.is_none() {
            let node = Node::parse(self.snapshot.body(), true)?;
            return leaf_find(&node, key);
        }
        let mut buffer = operation.buffer(wire::PAGE_BYTES)?;
        self.find_into(key, &mut buffer, operation)
    }

    pub(super) fn find_into(
        &self,
        key: Key,
        buffer: &mut Bytes,
        operation: &mut Operation<'_>,
    ) -> Result<Option<Value>, StoreError> {
        operation.check()?;
        if self.arena.is_none() {
            let node = Node::parse(self.snapshot.body(), true)?;
            return leaf_find(&node, key);
        }
        let mut reference = PageReference::decode(self.snapshot.body())?;
        let mut lower = None;
        let mut upper = None;
        let mut root = true;
        loop {
            self.load(reference, root, lower, upper, buffer, operation)?;
            let node = Node::parse(&buffer.value, root)?;
            if node.height == 0 {
                return leaf_find(&node, key);
            }
            let position = node.position(key)?;
            if position == node.count {
                return Ok(None);
            }
            lower = if position == 0 {
                lower
            } else {
                Some(node.key(position - 1)?)
            };
            upper = Some(node.key(position)?);
            reference = node.child(position)?;
            root = false;
        }
    }

    pub(super) fn cursor<'a>(
        &'a self,
        operation: &mut Operation<'_>,
    ) -> Result<Cursor<'a, 's>, StoreError> {
        let buffer = if self.arena.is_some() {
            Some(operation.buffer(wire::PAGE_BYTES)?)
        } else {
            None
        };
        Ok(Cursor {
            reader: self,
            buffer,
            frames: [None; wire::MAX_HEIGHT],
            depth: 0,
            slot: 0,
            started: false,
            ended: false,
        })
    }

    fn load(
        &self,
        reference: PageReference,
        root: bool,
        lower: Option<Key>,
        upper: Option<Key>,
        buffer: &mut Bytes,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        reference.validate(self.snapshot.header.committed_bytes)?;
        let file = self.arena.as_ref().ok_or(StoreError::Incompatible)?.file();
        read_into(
            operation,
            file,
            reference.offset,
            reference.length as usize,
            buffer,
        )?;
        let node = Node::parse(&buffer.value, root)?;
        node.validate_children_before(reference.offset)?;
        if node.height != reference.height
            || node.records != reference.records
            || wire::page_digest(&buffer.value)? != reference.digest
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

fn leaf_find(node: &Node<'_>, key: Key) -> Result<Option<Value>, StoreError> {
    let position = node.position(key)?;
    if position < node.count && node.key(position)? == key {
        Ok(Some(node.value(position)?))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Copy)]
struct Frame {
    reference: PageReference,
    slot: usize,
    lower: Option<Key>,
    upper: Option<Key>,
}

pub(super) struct Cursor<'a, 's> {
    reader: &'a Reader<'s>,
    buffer: Option<Bytes>,
    frames: [Option<Frame>; wire::MAX_HEIGHT],
    depth: usize,
    slot: usize,
    started: bool,
    ended: bool,
}

impl Cursor<'_, '_> {
    pub(super) fn next(
        &mut self,
        operation: &mut Operation<'_>,
    ) -> Result<Option<(Key, Value)>, StoreError> {
        if self.ended {
            return Ok(None);
        }
        operation.check()?;
        if self.reader.arena.is_none() {
            let node = Node::parse(self.reader.snapshot.body(), true)?;
            if self.slot == node.count {
                self.ended = true;
                return Ok(None);
            }
            let result = (node.key(self.slot)?, node.value(self.slot)?);
            self.slot += 1;
            return Ok(Some(result));
        }
        if !self.started {
            self.descend(
                PageReference::decode(self.reader.snapshot.body())?,
                None,
                None,
                operation,
            )?;
            self.started = true;
        }
        loop {
            let buffer = self.buffer.as_mut().ok_or(StoreError::Incompatible)?;
            let node = Node::parse(&buffer.value, self.depth == 0)?;
            if self.slot < node.count {
                let result = (node.key(self.slot)?, node.value(self.slot)?);
                self.slot += 1;
                return Ok(Some(result));
            }
            let mut next = None;
            while self.depth > 0 {
                self.depth -= 1;
                let frame = self.frames[self.depth]
                    .take()
                    .ok_or(StoreError::Incompatible)?;
                self.reader.load(
                    frame.reference,
                    self.depth == 0,
                    frame.lower,
                    frame.upper,
                    buffer,
                    operation,
                )?;
                let parent = Node::parse(&buffer.value, self.depth == 0)?;
                if frame.slot + 1 < parent.count {
                    let slot = frame.slot + 1;
                    let child = parent.child(slot)?;
                    let lower = Some(parent.key(slot - 1)?);
                    let upper = Some(parent.key(slot)?);
                    self.frames[self.depth] = Some(Frame { slot, ..frame });
                    self.depth += 1;
                    next = Some((child, lower, upper));
                    break;
                }
            }
            match next {
                Some((reference, lower, upper)) => {
                    self.descend(reference, lower, upper, operation)?
                }
                None => {
                    self.ended = true;
                    return Ok(None);
                }
            }
        }
    }

    fn descend(
        &mut self,
        mut reference: PageReference,
        lower: Option<Key>,
        mut upper: Option<Key>,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        loop {
            let buffer = self.buffer.as_mut().ok_or(StoreError::Incompatible)?;
            self.reader
                .load(reference, self.depth == 0, lower, upper, buffer, operation)?;
            let node = Node::parse(&buffer.value, self.depth == 0)?;
            if node.height == 0 {
                self.slot = 0;
                return Ok(());
            }
            if self.depth >= self.frames.len() {
                return Err(StoreError::Incompatible);
            }
            let child = node.child(0)?;
            let child_upper = Some(node.key(0)?);
            self.frames[self.depth] = Some(Frame {
                reference,
                slot: 0,
                lower,
                upper,
            });
            self.depth += 1;
            reference = child;
            upper = child_upper;
        }
    }
}

pub(super) fn read_into(
    operation: &mut Operation<'_>,
    file: &File,
    offset: u64,
    length: usize,
    buffer: &mut Bytes,
) -> Result<(), StoreError> {
    if length > buffer.value.capacity() {
        return Err(StoreError::Quota);
    }
    buffer.value.resize(length, 0);
    if let Some(original) = operation.original {
        return checked_io::read_exact_at(
            file,
            &mut buffer.value,
            offset,
            original,
            operation.boundary,
        );
    }
    let mut observed = 0;
    while observed < length {
        operation.check()?;
        let count = match file.read_at(&mut buffer.value[observed..], offset + observed as u64) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(StoreError::StreamIo {
                    operation: "read-packed-index-page",
                    source,
                });
            }
        };
        operation.check()?;
        if count == 0 {
            return Err(StoreError::Incompatible);
        }
        observed += count;
    }
    Ok(())
}
