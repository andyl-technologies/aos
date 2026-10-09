//! Original-owned immutable page appends shared by updates and bulk rebuilds.

use super::index_format::{self as wire, Node, PageReference};
use super::index_io::{self, IndexFile, Operation};
use super::*;

pub(super) struct Arena {
    file: Option<IndexFile>,
    identity: Option<[u8; 32]>,
    length: u64,
    newly_created: bool,
    modified: bool,
}

impl Arena {
    pub(super) fn empty() -> Self {
        Self {
            file: None,
            identity: None,
            length: 0,
            newly_created: false,
            modified: false,
        }
    }

    pub(super) fn open(
        backend: &PackedBlobBackend,
        identity: [u8; 32],
        committed_bytes: u64,
        operation: &mut Operation<'_>,
    ) -> Result<Self, StoreError> {
        let name = index_io::arena_name(identity);
        let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
        let file = operation.with_path(&backend.admin, name, |operation, path| {
            operation.open(path, true)
        })?;
        let length = operation.length(&file)?;
        if length < committed_bytes {
            return Err(StoreError::Incompatible);
        }
        Ok(Self {
            file: Some(file),
            identity: Some(identity),
            length,
            newly_created: false,
            modified: false,
        })
    }

    pub(super) fn identity(&self) -> Option<[u8; 32]> {
        self.identity
    }

    pub(super) fn length(&self) -> u64 {
        self.length
    }

    pub(super) fn file(&self) -> Result<&File, StoreError> {
        self.file
            .as_ref()
            .map(IndexFile::file)
            .ok_or(StoreError::Incompatible)
    }

    pub(super) fn append(
        &mut self,
        backend: &PackedBlobBackend,
        instance: [u8; 32],
        generation: u64,
        bytes: &[u8],
        operation: &mut Operation<'_>,
    ) -> Result<PageReference, StoreError> {
        let node = Node::parse_pending(bytes)?;
        if node.count == 0 {
            return Err(StoreError::Incompatible);
        }
        node.validate_children_before(self.length)?;
        let length = u32::try_from(bytes.len()).map_err(|_| StoreError::Quota)?;
        let end = self
            .length
            .checked_add(u64::from(length))
            .ok_or(StoreError::Quota)?;
        if self.file.is_none() {
            let mut hash = blake3::Hasher::new();
            hash.update(b"crucible.content-store.packed-arena.v2");
            hash.update(&instance);
            hash.update(&generation.to_be_bytes());
            hash.update(&std::process::id().to_be_bytes());
            hash.update(&TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed).to_be_bytes());
            let identity = *hash.finalize().as_bytes();
            let name = index_io::arena_name(identity);
            let name = std::str::from_utf8(&name).map_err(|_| StoreError::Incompatible)?;
            let file = operation.with_path(&backend.admin, name, |operation, path| {
                operation.create(path)
            })?;
            // Name and descriptor custody precede the successful-create
            // callback. A failure leaves actual unreachable backing for GC;
            // it never claims that the namespace refunded these bytes.
            self.identity = Some(identity);
            self.file = Some(file);
            self.newly_created = true;
            operation.check()?;
        }

        let reference = PageReference {
            offset: self.length,
            length,
            digest: wire::page_digest(bytes)?,
            records: node.records,
            height: node.height,
        };
        self.modified = true;
        operation.write(self.file()?, self.length, bytes)?;
        self.length = end;
        Ok(reference)
    }

    pub(super) fn sync(&self, operation: &mut Operation<'_>) -> Result<(), StoreError> {
        operation.sync(self.file()?)
    }

    pub(super) fn modified(&self) -> bool {
        self.newly_created || self.modified
    }

    pub(super) fn newly_created(&self) -> bool {
        self.newly_created
    }
}
