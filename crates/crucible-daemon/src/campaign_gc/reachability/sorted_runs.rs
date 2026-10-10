//! Balanced bounded runs feeding one canonical authenticated GC mark tree.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crucible_cas::owned_decode::ResourceLoan;

mod cursor;
mod format;
mod publication;

use cursor::Cursor;
use format::NodeRef;
use publication::RunWriter;

const PAGE: usize = MerkleMap::MAX_CHECKED_PREFIX_UPSERTS;
const RUN_LEVELS: usize = usize::BITS as usize;

#[derive(Clone, Copy)]
struct RunRef {
    node: NodeRef,
    weight: usize,
}

pub(super) struct SortOwner<'a, 'boundary> {
    backend: Arc<dyn ImmutableBlobBackend>,
    operation: &'a CampaignGcOperationContext<'boundary>,
    page: Vec<MarkEntry>,
    levels: [Option<RunRef>; RUN_LEVELS],
    observed: usize,
    failed: bool,
    _credit: ResourceLoan,
}

impl<'a, 'boundary> SortOwner<'a, 'boundary> {
    pub(super) fn new(
        operation: &'a CampaignGcOperationContext<'boundary>,
    ) -> Result<Self, StoreError> {
        let extent = PAGE
            .checked_mul(std::mem::size_of::<MarkEntry>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(StoreError::Quota)?;
        let credit = operation.reserve_bytes(extent as u64)?;
        let mut page = Vec::new();
        page.try_reserve_exact(PAGE)
            .map_err(|source| allocation_error(operation.original(), source))?;
        Ok(Self {
            backend: operation.marks(),
            operation,
            page,
            levels: [None; RUN_LEVELS],
            observed: 0,
            failed: false,
            _credit: credit,
        })
    }

    pub(super) fn insert(&mut self, id: ContentId) -> Result<(), StoreError> {
        if self.failed {
            return Err(terminal_failure());
        }
        let result = (|| {
            self.operation.check()?;
            self.observed = self.observed.checked_add(1).ok_or(StoreError::Quota)?;
            self.page.push((mark_key(id), id));
            if self.page.len() == PAGE {
                self.flush()?;
            }
            Ok(())
        })();
        self.failed = result.is_err();
        result
    }

    fn flush(&mut self) -> Result<(), StoreError> {
        if self.page.is_empty() {
            return self.operation.check();
        }
        self.page.sort_unstable_by_key(|entry| entry.0);
        if self
            .page
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
        {
            return Err(StoreError::InvalidComposition {
                reason: "GC typed mark key collision",
            });
        }
        self.page.dedup_by_key(|entry| entry.0);
        let mut writer = RunWriter::new(self.backend.as_ref(), self.operation)?;
        for entry in &self.page {
            writer.push(*entry)?;
        }
        let node = writer.finish()?.ok_or(StoreError::Quota)?;
        let mut run = RunRef { node, weight: 1 };
        let mut level = 0;
        while let Some(left) = self.levels.get(level).copied().flatten() {
            if left.weight != run.weight {
                return Err(StoreError::Quota);
            }
            run = self.merge(left, run)?;
            level += 1;
        }
        self.operation.check()?;
        if level >= self.levels.len() {
            return Err(StoreError::Quota);
        }
        // Keep all accepted input heads until the complete carry has passed
        // publication and final-tail checks. A later merge refusal retains them.
        self.levels[..level].fill(None);
        self.levels[level] = Some(run);
        self.page.clear();
        Ok(())
    }

    fn merge(&self, left: RunRef, right: RunRef) -> Result<RunRef, StoreError> {
        let weight = left
            .weight
            .checked_add(right.weight)
            .ok_or(StoreError::Quota)?;
        let mut left_cursor = Cursor::new(left.node, self.backend.as_ref(), self.operation)?;
        let mut right_cursor = Cursor::new(right.node, self.backend.as_ref(), self.operation)?;
        let mut writer = RunWriter::new(self.backend.as_ref(), self.operation)?;
        let mut left_entry = left_cursor.next_entry()?;
        let mut right_entry = right_cursor.next_entry()?;
        while left_entry.is_some() || right_entry.is_some() {
            self.operation.check()?;
            match (left_entry, right_entry) {
                (Some(left), Some(right)) if left.0 == right.0 => {
                    if left.1 != right.1 {
                        return Err(StoreError::InvalidComposition {
                            reason: "GC typed mark key collision",
                        });
                    }
                    writer.push(left)?;
                    left_entry = left_cursor.next_entry()?;
                    right_entry = right_cursor.next_entry()?;
                }
                (Some(left), right) if right.is_none_or(|right| left.0 < right.0) => {
                    writer.push(left)?;
                    left_entry = left_cursor.next_entry()?;
                }
                (_, Some(right)) => {
                    writer.push(right)?;
                    right_entry = right_cursor.next_entry()?;
                }
                _ => {
                    return Err(StoreError::InvalidComposition {
                        reason: "GC merge input state disagrees",
                    });
                }
            }
        }
        // Both cursors have accepted their exact complete tails, not merely
        // yielded their final key. Only now can the output head replace inputs.
        let node = writer.finish()?.ok_or(StoreError::Quota)?;
        self.operation.check()?;
        Ok(RunRef { node, weight })
    }

    pub(super) fn finish(mut self, marks: &mut Reachability) -> Result<(), StoreError> {
        if self.failed {
            return Err(terminal_failure());
        }
        self.flush()?;
        // Release the collection allocation before the final merge phase.
        self.page = Vec::new();
        let mut run = None;
        for level in 0..self.levels.len() {
            if let Some(next) = self.levels[level] {
                run = Some(match run {
                    None => next,
                    Some(prior) => self.merge(prior, next)?,
                });
            }
        }
        let account = mark_account(&marks.original)?;
        let root = match run {
            Some(run) => {
                let cursor = Cursor::new(run.node, self.backend.as_ref(), self.operation)?;
                let root = marks
                    .map
                    .build_from_sorted_with_boundary(cursor, &account, &mut || {
                        self.operation.check()
                    })
                    .map_err(|source| mark_builder_error(&account, source))?;
                if root.entry_count() != run.node.count {
                    return Err(StoreError::Corrupt {
                        id: root.content_id(),
                    });
                }
                root
            }
            None => marks
                .map
                .build_from_sorted_with_boundary(std::iter::empty(), &account, &mut || {
                    self.operation.check()
                })
                .map_err(|source| mark_builder_error(&account, source))?,
        };
        account
            .check()
            .map_err(|error| mark_admission(&account, error))?;
        self.operation.check()?;
        if root.entry_count() > MAX_CAMPAIGN_CLOSURE_OBJECTS as u64 {
            return Err(StoreError::Quota);
        }
        marks.root = root;
        Ok(())
    }
}

fn terminal_failure() -> StoreError {
    StoreError::Unsupported {
        capability: "failed-GC-run-owner",
    }
}

fn allocation_error(
    original: &DecodeBudget,
    source: std::collections::TryReserveError,
) -> StoreError {
    StoreError::Allocation {
        source,
        custody: Some(original.custody()),
    }
}

#[cfg(test)]
mod tests;
