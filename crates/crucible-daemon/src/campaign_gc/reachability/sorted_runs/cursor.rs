//! Bounded current-page traversal with complete authenticated run tails.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crucible_cas::content_store::OwnedBlobBytes;
use crucible_cas::owned_decode::ResourceLoan;

pub(super) struct Cursor<'a, 'boundary> {
    backend: &'a dyn ImmutableBlobBackend,
    operation: &'a CampaignGcOperationContext<'boundary>,
    root: NodeRef,
    pending: [Option<NodeRef>; format::LEVELS],
    depth: usize,
    leaf: Option<OwnedBlobBytes>,
    leaf_id: ContentId,
    position: usize,
    remaining: u64,
    pub(super) observed: u64,
    previous: Option<CampaignHash>,
    pub(super) complete: bool,
    failed: bool,
    _credit: ResourceLoan,
}

impl<'a, 'boundary> Cursor<'a, 'boundary> {
    pub(super) fn new(
        root: NodeRef,
        backend: &'a dyn ImmutableBlobBackend,
        operation: &'a CampaignGcOperationContext<'boundary>,
    ) -> Result<Self, StoreError> {
        let credit = operation.reserve_bytes(std::mem::size_of::<Self>() as u64)?;
        let mut pending = [None; format::LEVELS];
        pending[0] = Some(root);
        Ok(Self {
            backend,
            operation,
            root,
            pending,
            depth: 1,
            leaf: None,
            leaf_id: root.id,
            position: 0,
            remaining: 0,
            observed: 0,
            previous: None,
            complete: false,
            failed: false,
            _credit: credit,
        })
    }

    pub(super) fn next_entry(&mut self) -> Result<Option<MarkEntry>, StoreError> {
        if self.failed {
            return Err(StoreError::Unsupported {
                capability: "failed-GC-run-cursor",
            });
        }
        let result = self.read_next();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn read_next(&mut self) -> Result<Option<MarkEntry>, StoreError> {
        if self.complete {
            return Ok(None);
        }
        self.operation.check()?;
        loop {
            if self.remaining > 0 {
                let bytes = self
                    .leaf
                    .as_ref()
                    .ok_or(StoreError::Corrupt { id: self.leaf_id })?;
                let mut reader = format::Reader::at(bytes, self.leaf_id, self.position);
                let entry = reader.entry()?;
                self.position = reader.position;
                self.remaining -= 1;
                if self.remaining == 0 {
                    reader.finish()?;
                }
                if self.previous.is_some_and(|previous| previous >= entry.0) {
                    return Err(StoreError::Corrupt { id: self.root.id });
                }
                self.observed = self.observed.checked_add(1).ok_or(StoreError::Quota)?;
                if self.observed > self.root.count {
                    return Err(StoreError::Corrupt { id: self.root.id });
                }
                self.previous = Some(entry.0);
                self.operation.check()?;
                return Ok(Some(entry));
            }

            // Close the old leaf before opening any new physical source.
            self.leaf = None;
            if self.depth == 0 {
                if self.observed != self.root.count || self.previous != Some(self.root.last) {
                    return Err(StoreError::Corrupt { id: self.root.id });
                }
                self.operation.check()?;
                self.complete = true;
                return Ok(None);
            }
            self.depth -= 1;
            let expected = self.pending[self.depth]
                .take()
                .ok_or(StoreError::Corrupt { id: self.root.id })?;
            let bytes = {
                let source = self.backend.read_with_boundary(
                    self.operation.original(),
                    expected.id,
                    None,
                    &mut || self.operation.check(),
                )?;
                source.read_all_with_boundary(
                    self.operation.original(),
                    format::MAX_PAGE_BYTES,
                    &mut || self.operation.check(),
                )?
            };
            match format::decode(expected.id, &bytes)? {
                format::Record::Leaf { node, entries } => {
                    if node != expected {
                        return Err(StoreError::Corrupt { id: expected.id });
                    }
                    self.position = entries.position;
                    self.remaining = node.count;
                    self.leaf_id = node.id;
                    self.leaf = Some(bytes);
                }
                format::Record::Branch {
                    node,
                    children: [left, right],
                } => {
                    if node != expected || self.depth + 2 > self.pending.len() {
                        return Err(StoreError::Corrupt { id: expected.id });
                    }
                    self.pending[self.depth] = Some(right);
                    self.pending[self.depth + 1] = Some(left);
                    self.depth += 2;
                }
            }
        }
    }
}

impl Iterator for Cursor<'_, '_> {
    type Item = Result<MarkEntry, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_entry() {
            Ok(entry) => entry.map(Ok),
            Err(error) => Some(Err(error)),
        }
    }
}
