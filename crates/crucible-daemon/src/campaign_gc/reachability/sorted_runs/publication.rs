//! Closed run-purpose publication in the existing admitted mark namespace.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crucible_cas::content_store::{BlobHandle, ObjectKind, OwnedBlobBytes};
use crucible_cas::owned_decode::ResourceLoan;

const OBJECTS: usize = MerkleMap::MAX_CHECKED_BATCH_UPSERTS;
const BYTES: u64 = 4 * 1024 * 1024;

pub(super) struct Publication<'a, 'boundary> {
    backend: &'a dyn ImmutableBlobBackend,
    operation: &'a CampaignGcOperationContext<'boundary>,
    pending: Vec<(ContentId, BlobHandle)>,
    bytes: u64,
    _credit: ResourceLoan,
}

impl<'a, 'boundary> Publication<'a, 'boundary> {
    pub(super) fn new(
        backend: &'a dyn ImmutableBlobBackend,
        operation: &'a CampaignGcOperationContext<'boundary>,
    ) -> Result<Self, StoreError> {
        let extent = OBJECTS
            .checked_mul(std::mem::size_of::<(ContentId, BlobHandle)>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(StoreError::Quota)?;
        let credit = operation.reserve_bytes(extent as u64)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(OBJECTS)
            .map_err(|source| allocation_error(operation.original(), source))?;
        Ok(Self {
            backend,
            operation,
            pending,
            bytes: 0,
            _credit: credit,
        })
    }

    pub(super) fn stage(&mut self, node: NodeRef, bytes: OwnedBlobBytes) -> Result<(), StoreError> {
        self.operation.check()?;
        // No caller may broaden normal graph kinds. This private publisher
        // accepts only the closed run grammar, then asks the actual namespace
        // for its ordinary per-kind headroom before checked publication.
        let actual = match format::decode(node.id, &bytes)? {
            format::Record::Leaf { node, .. } | format::Record::Branch { node, .. } => node,
        };
        if actual != node {
            return Err(StoreError::Corrupt { id: node.id });
        }
        self.backend
            .admit_object_graph(&[(ObjectKind::Projection, 1)])?;
        let length = bytes.len() as u64;
        if length > format::MAX_PAGE_BYTES {
            return Err(StoreError::Quota);
        }
        if self.pending.len() == OBJECTS
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|bytes| bytes > BYTES)
        {
            self.finish()?;
        }
        let source = BlobHandle::from_owned_bytes(bytes)?;
        self.bytes = self.bytes.checked_add(length).ok_or(StoreError::Quota)?;
        self.pending.push((node.id, source));
        Ok(())
    }

    pub(super) fn finish(&mut self) -> Result<(), StoreError> {
        if self.pending.is_empty() {
            return self.operation.check();
        }
        let original = self.operation.original();
        let receipts =
            self.backend
                .put_many_if_absent_with_boundary(original, &self.pending, &mut || {
                    self.operation.check()
                })?;
        if receipts.len() != self.pending.len()
            || receipts
                .iter()
                .zip(&self.pending)
                .any(|(receipt, (id, _))| receipt.id != *id)
        {
            return Err(StoreError::InvalidComposition {
                reason: "GC run publication receipt mismatch",
            });
        }
        let _receipts = receipts.accept_with_boundary(&mut || self.operation.check())?;
        self.operation.check()?;
        self.pending.clear();
        self.bytes = 0;
        Ok(())
    }
}

pub(super) struct RunWriter<'a, 'boundary> {
    publication: Publication<'a, 'boundary>,
    operation: &'a CampaignGcOperationContext<'boundary>,
    page: Vec<MarkEntry>,
    levels: [Option<NodeRef>; format::LEVELS],
    previous: Option<CampaignHash>,
    _credit: ResourceLoan,
}

impl<'a, 'boundary> RunWriter<'a, 'boundary> {
    pub(super) fn new(
        backend: &'a dyn ImmutableBlobBackend,
        operation: &'a CampaignGcOperationContext<'boundary>,
    ) -> Result<Self, StoreError> {
        let extent = PAGE
            .checked_mul(std::mem::size_of::<MarkEntry>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(StoreError::Quota)?;
        let credit = operation.reserve_bytes(extent as u64)?;
        let publication = Publication::new(backend, operation)?;
        let mut page = Vec::new();
        page.try_reserve_exact(PAGE)
            .map_err(|source| allocation_error(operation.original(), source))?;
        Ok(Self {
            publication,
            operation,
            page,
            levels: [None; format::LEVELS],
            previous: None,
            _credit: credit,
        })
    }

    pub(super) fn push(&mut self, entry: MarkEntry) -> Result<(), StoreError> {
        self.operation.check()?;
        if self.previous.is_some_and(|previous| previous >= entry.0) {
            return Err(StoreError::InvalidComposition {
                reason: "GC merged run is not strictly sorted",
            });
        }
        if self.page.len() == PAGE {
            self.flush_page()?;
        }
        self.page.push(entry);
        self.previous = Some(entry.0);
        Ok(())
    }

    fn join(&mut self, left: NodeRef, right: NodeRef) -> Result<NodeRef, StoreError> {
        let (node, bytes) = format::branch(left, right, self.operation.original(), &mut || {
            self.operation.check()
        })?;
        self.publication.stage(node, bytes)?;
        Ok(node)
    }

    fn flush_page(&mut self) -> Result<(), StoreError> {
        if self.page.is_empty() {
            return Ok(());
        }
        let (mut node, bytes) = format::leaf(&self.page, self.operation.original(), &mut || {
            self.operation.check()
        })?;
        self.publication.stage(node, bytes)?;
        let mut level = 0;
        while let Some(left) = self.levels.get(level).copied().flatten() {
            node = self.join(left, node)?;
            self.levels[level] = None;
            level += 1;
        }
        *self.levels.get_mut(level).ok_or(StoreError::Quota)? = Some(node);
        self.page.clear();
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<Option<NodeRef>, StoreError> {
        self.flush_page()?;
        let mut root = None;
        // Smaller trailing ranks belong after the earlier higher-rank pages.
        // Fold them toward the front to preserve order without a page list.
        for level in 0..self.levels.len() {
            if let Some(left) = self.levels[level] {
                root = Some(match root {
                    None => left,
                    Some(right) => self.join(left, right)?,
                });
            }
        }
        self.publication.finish()?;
        self.operation.check()?;
        Ok(root)
    }
}
