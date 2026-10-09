//! Sorted placement rebuilds without a retained page array at each height.
//!
//! One exclusive temporary file holds at most sixteen partial branch pages.
//! Eighty rows provide enough lookahead to emit sixty-four and retain sixteen;
//! this preserves non-root occupancy even when the stream ends immediately.
//! Scratch names never become committed references, and every completed arena
//! page follows its children physically.

use super::index_arena::Arena;
use super::index_format::{self as wire, Header, Key, Node, PageReference, Value};
use super::index_io::{Bytes, Operation};
use super::placement_index::{EncodedIndex, read_into};
use super::*;

const LOOKAHEAD_ROWS: usize = wire::MAX_ROWS + wire::MIN_ROWS;

use super::index_io::Temporary as Scratch;

#[derive(Clone, Copy)]
struct Child {
    upper: Key,
    reference: PageReference,
}

/// Returns cleanup independently so the enclosing paid scope retains both causes.
pub(super) struct Terminal {
    pub(super) result: Result<EncodedIndex, StoreError>,
    pub(super) cleanup: Result<(), StoreError>,
    pub(super) uncommitted_arena_created: bool,
}

pub(super) struct Builder {
    header: Header,
    arena: Arena,
    leaf: Bytes,
    leaf_rows: usize,
    scratch: Option<Scratch>,
    branch_rows: [u8; wire::MAX_HEIGHT],
    branch_digests: [[u8; 32]; wire::MAX_HEIGHT],
    prior: Option<Key>,
}

impl Builder {
    pub(super) fn new(mut header: Header, operation: &Operation<'_>) -> Result<Self, StoreError> {
        header.arena = None;
        header.committed_bytes = 0;
        header.count = 0;
        header.logical_bytes = 0;
        header.packs = 0;
        header.physical_bytes = 0;
        header.records = 0;
        header.height = 0;
        let mut leaf = operation.buffer(wire::PAGE_BYTES)?;
        wire::begin_node(&mut leaf.value, 0);
        Ok(Self {
            header,
            arena: Arena::empty(),
            leaf,
            leaf_rows: 0,
            scratch: None,
            branch_rows: [0; wire::MAX_HEIGHT],
            branch_digests: [[0; 32]; wire::MAX_HEIGHT],
            prior: None,
        })
    }

    pub(super) fn push(
        &mut self,
        backend: &PackedBlobBackend,
        key: Key,
        value: Value,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        if self.prior.is_some_and(|prior| prior >= key) {
            return Err(StoreError::Incompatible);
        }
        value.validate_for(key)?;
        let header = added_record(self.header, key, value)?;
        if self.leaf_rows >= LOOKAHEAD_ROWS {
            return Err(StoreError::Incompatible);
        }
        self.leaf.value.extend_from_slice(&key.0);
        self.leaf.value.extend_from_slice(&value.0);
        self.leaf_rows += 1;
        self.prior = Some(key);
        self.header = header;

        if self.leaf_rows == LOOKAHEAD_ROWS {
            let child = self.emit_leaf(backend, 0, wire::MAX_ROWS, operation)?;
            self.leaf.value.copy_within(
                wire::PAGE_HEADER_BYTES + wire::MAX_ROWS * wire::LEAF_ROW_BYTES..,
                wire::PAGE_HEADER_BYTES,
            );
            self.leaf_rows = wire::MIN_ROWS;
            self.leaf
                .value
                .truncate(wire::PAGE_HEADER_BYTES + self.leaf_rows * wire::LEAF_ROW_BYTES);
            self.carry(backend, 1, child, operation)?;
        }
        Ok(())
    }

    pub(super) fn terminate(
        mut self,
        backend: &PackedBlobBackend,
        operation: &mut Operation<'_>,
        work: Result<(), StoreError>,
    ) -> Terminal {
        let result = work.and_then(|()| self.finish(backend, operation));
        let cleanup = self.scratch.as_mut().map_or(Ok(()), Scratch::cleanup);
        Terminal {
            result,
            cleanup,
            uncommitted_arena_created: self.arena.newly_created(),
        }
    }

    fn finish(
        &mut self,
        backend: &PackedBlobBackend,
        operation: &mut Operation<'_>,
    ) -> Result<EncodedIndex, StoreError> {
        if self.scratch.is_none() && self.leaf_rows <= wire::MAX_ROWS {
            wire::finish_node(&mut self.leaf.value, self.leaf_rows, self.leaf_rows as u64)?;
            let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
            self.header
                .append(backend.configuration, &self.leaf.value, &mut bytes.value)?;
            Header::decode(&bytes.value, backend.configuration)?;
            return Ok(EncodedIndex {
                bytes,
                header: self.header,
            });
        }

        if self.leaf_rows > wire::MAX_ROWS {
            let middle = self.leaf_rows / 2;
            let first = self.emit_leaf(backend, 0, middle, operation)?;
            let second = self.emit_leaf(backend, middle, self.leaf_rows, operation)?;
            self.carry(backend, 1, first, operation)?;
            self.carry(backend, 1, second, operation)?;
        } else if self.leaf_rows != 0 {
            let child = self.emit_leaf(backend, 0, self.leaf_rows, operation)?;
            self.carry(backend, 1, child, operation)?;
        }

        for height in 1..wire::MAX_HEIGHT {
            let count = usize::from(self.branch_rows[height]);
            if count == 0 {
                continue;
            }
            let highest = self.branch_rows[height + 1..]
                .iter()
                .all(|count| *count == 0);
            if highest && count <= wire::MAX_ROWS {
                let child = if count == 1 {
                    let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
                    self.read_branch(height, count, &mut bytes, operation)?;
                    decode_child(&bytes.value)?
                } else {
                    self.emit_branch(backend, height, 0, count, operation)?
                };
                let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
                self.arena.sync(operation)?;
                self.header.arena = self.arena.identity();
                self.header.committed_bytes = self.arena.length();
                self.header.height = child.reference.height;
                let mut reference = [0; wire::REFERENCE_BYTES];
                encode_reference(child.reference, &mut reference);
                self.header
                    .append(backend.configuration, &reference, &mut bytes.value)?;
                Header::decode(&bytes.value, backend.configuration)?;
                return Ok(EncodedIndex {
                    bytes,
                    header: self.header,
                });
            }

            if count < wire::MIN_ROWS {
                return Err(StoreError::Incompatible);
            }
            let middle = if count > wire::MAX_ROWS {
                count / 2
            } else {
                count
            };
            let first = self.emit_branch(backend, height, 0, middle, operation)?;
            let second = if middle != count {
                Some(self.emit_branch(backend, height, middle, count, operation)?)
            } else {
                None
            };
            self.branch_rows[height] = 0;
            self.branch_digests[height] = [0; 32];
            self.carry(backend, height + 1, first, operation)?;
            if let Some(second) = second {
                self.carry(backend, height + 1, second, operation)?;
            }
        }
        Err(StoreError::Quota)
    }

    fn emit_leaf(
        &mut self,
        backend: &PackedBlobBackend,
        start: usize,
        end: usize,
        operation: &mut Operation<'_>,
    ) -> Result<Child, StoreError> {
        if start >= end || end > self.leaf_rows || end - start > wire::MAX_ROWS {
            return Err(StoreError::Incompatible);
        }
        let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
        wire::begin_node(&mut bytes.value, 0);
        bytes.value.extend_from_slice(
            &self.leaf.value[wire::PAGE_HEADER_BYTES + start * wire::LEAF_ROW_BYTES
                ..wire::PAGE_HEADER_BYTES + end * wire::LEAF_ROW_BYTES],
        );
        wire::finish_node(&mut bytes.value, end - start, (end - start) as u64)?;
        let node = Node::parse_pending(&bytes.value)?;
        let upper = node.key(node.count - 1)?;
        let reference = self.arena.append(
            backend,
            self.header.instance,
            self.header.generation,
            &bytes.value,
            operation,
        )?;
        Ok(Child { upper, reference })
    }

    fn carry(
        &mut self,
        backend: &PackedBlobBackend,
        height: usize,
        child: Child,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        if height >= wire::MAX_HEIGHT || usize::from(child.reference.height) + 1 != height {
            return Err(StoreError::Quota);
        }
        if self.scratch.is_none() {
            self.scratch = Some(Scratch::new(
                backend,
                &backend.admin,
                "index-build",
                operation,
            )?);
        }
        let count = usize::from(self.branch_rows[height]);
        if count >= LOOKAHEAD_ROWS {
            return Err(StoreError::Incompatible);
        }
        let mut row = [0; wire::BRANCH_ROW_BYTES];
        row[..wire::KEY_BYTES].copy_from_slice(&child.upper.0);
        let mut reference = [0; wire::REFERENCE_BYTES];
        encode_reference(child.reference, &mut reference);
        row[wire::KEY_BYTES..].copy_from_slice(&reference);
        operation.write(
            self.scratch_file()?,
            branch_offset(height)? + (count * wire::BRANCH_ROW_BYTES) as u64,
            &row,
        )?;
        self.branch_digests[height] = extend_digest(self.branch_digests[height], &row);
        self.branch_rows[height] += 1;
        if count + 1 != LOOKAHEAD_ROWS {
            return Ok(());
        }

        let parent = self.emit_branch(backend, height, 0, wire::MAX_ROWS, operation)?;
        {
            let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
            self.read_branch(height, LOOKAHEAD_ROWS, &mut bytes, operation)?;
            operation.write(
                self.scratch_file()?,
                branch_offset(height)?,
                &bytes.value[wire::MAX_ROWS * wire::BRANCH_ROW_BYTES..],
            )?;
            self.branch_digests[height] =
                rows_digest(&bytes.value[wire::MAX_ROWS * wire::BRANCH_ROW_BYTES..]);
        }
        self.branch_rows[height] = wire::MIN_ROWS as u8;
        // Every allocated branch buffer has ended before upward propagation.
        self.carry(backend, height + 1, parent, operation)
    }

    fn emit_branch(
        &mut self,
        backend: &PackedBlobBackend,
        height: usize,
        start: usize,
        end: usize,
        operation: &mut Operation<'_>,
    ) -> Result<Child, StoreError> {
        let count = usize::from(self.branch_rows[height]);
        if start >= end || end > count || end - start > wire::MAX_ROWS {
            return Err(StoreError::Incompatible);
        }
        let mut input = operation.buffer(wire::PAGE_BYTES)?;
        self.read_branch(height, count, &mut input, operation)?;
        let mut bytes = operation.buffer(wire::PAGE_BYTES)?;
        wire::begin_node(&mut bytes.value, height as u8);
        let mut records = 0_u64;
        for row in input.value[start * wire::BRANCH_ROW_BYTES..end * wire::BRANCH_ROW_BYTES]
            .as_chunks::<{ wire::BRANCH_ROW_BYTES }>()
            .0
        {
            records = records
                .checked_add(decode_child(row)?.reference.records)
                .ok_or(StoreError::Quota)?;
            bytes.value.extend_from_slice(row);
        }
        wire::finish_node(&mut bytes.value, end - start, records)?;
        let node = Node::parse_pending(&bytes.value)?;
        let upper = node.key(node.count - 1)?;
        let reference = self.arena.append(
            backend,
            self.header.instance,
            self.header.generation,
            &bytes.value,
            operation,
        )?;
        Ok(Child { upper, reference })
    }

    fn scratch_file(&self) -> Result<&File, StoreError> {
        self.scratch
            .as_ref()
            .ok_or(StoreError::Incompatible)?
            .file()
    }

    fn read_branch(
        &self,
        height: usize,
        count: usize,
        bytes: &mut Bytes,
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        read_into(
            operation,
            self.scratch_file()?,
            branch_offset(height)?,
            count * wire::BRANCH_ROW_BYTES,
            bytes,
        )?;
        // Partial pages live outside the committed tree. Their expected hash
        // remains in process-private state, so a damaged scratch file cannot
        // be blessed into a newly authenticated root.
        if rows_digest(&bytes.value) != self.branch_digests[height] {
            return Err(StoreError::Incompatible);
        }
        Ok(())
    }
}

fn branch_offset(height: usize) -> Result<u64, StoreError> {
    if height == 0 || height >= wire::MAX_HEIGHT {
        return Err(StoreError::Quota);
    }
    Ok(((height - 1) * wire::PAGE_BYTES) as u64)
}

fn extend_digest(prior: [u8; 32], row: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"crucible.content-store.packed-build-partial.v2");
    hash.update(&prior);
    hash.update(row);
    *hash.finalize().as_bytes()
}

fn rows_digest(rows: &[u8]) -> [u8; 32] {
    rows.as_chunks::<{ wire::BRANCH_ROW_BYTES }>()
        .0
        .iter()
        .fold([0; 32], |digest, row| extend_digest(digest, row))
}

fn encode_reference(reference: PageReference, bytes: &mut [u8; wire::REFERENCE_BYTES]) {
    bytes[..8].copy_from_slice(&reference.offset.to_be_bytes());
    bytes[8..12].copy_from_slice(&reference.length.to_be_bytes());
    bytes[12..44].copy_from_slice(&reference.digest);
    bytes[44..52].copy_from_slice(&reference.records.to_be_bytes());
    bytes[52] = reference.height;
}

fn decode_child(bytes: &[u8]) -> Result<Child, StoreError> {
    if bytes.len() != wire::BRANCH_ROW_BYTES {
        return Err(StoreError::Incompatible);
    }
    Ok(Child {
        upper: Key(bytes[..wire::KEY_BYTES]
            .try_into()
            .map_err(|_| StoreError::Incompatible)?),
        reference: PageReference::decode(&bytes[wire::KEY_BYTES..])?,
    })
}

fn added_record(mut header: Header, key: Key, value: Value) -> Result<Header, StoreError> {
    if key.0[0] == 0 {
        header.count = header.count.checked_add(1).ok_or(StoreError::Quota)?;
        header.logical_bytes = header
            .logical_bytes
            .checked_add(value.entry()?.length)
            .ok_or(StoreError::Quota)?;
    } else {
        header.packs = header.packs.checked_add(1).ok_or(StoreError::Quota)?;
        header.physical_bytes = header
            .physical_bytes
            .checked_add(value.pack_record()?.physical_bytes)
            .ok_or(StoreError::Quota)?;
    }
    header.records = header.records.checked_add(1).ok_or(StoreError::Quota)?;
    Ok(header)
}
