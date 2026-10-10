//! One bounded placement insertion over the existing pack publication group.
//!
//! Each affected subtree authenticates once on entry and each old parent is
//! freshly revalidated after child work. Only final affected pages are appended;
//! no intermediate point-update ancestors or process cache are retained. An
//! iterative, paid work stack keeps per-level ledgers off the native call stack.

use super::{Bytes, ContentId, IndexEntry, Key, Node, Operation, PackedBlobBackend};
use super::{Child, Replacement, Root, Update, changed_header, lookup, seal_pending};
use super::{PageReference, StoreError, Value, wire};
use crate::content_store::batch;
use crate::owned_decode::DecodeScratch;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
struct Row {
    key: Key,
    value: Value,
}

// Values precede credit so actual allocation/control destruction closes first.
struct Ledger<T> {
    values: Vec<T>,
    _credit: Option<DecodeScratch>,
}

impl<T> Ledger<T> {
    fn new(capacity: usize, operation: &mut Operation<'_>) -> Result<Self, StoreError> {
        operation.check()?;
        let credit = operation.reserve_array::<T>(capacity)?;
        let mut values = Vec::new();
        values.try_reserve_exact(capacity).map_err(|error| {
            operation.original.map_or(StoreError::Quota, |original| {
                batch::allocation_under(original, error)
            })
        })?;
        if values.capacity() > capacity {
            return Err(StoreError::Quota);
        }
        let owner = Self {
            values,
            _credit: credit,
        };
        operation.check()?;
        Ok(owner)
    }
}

// Concrete simultaneous loop/constructor controls, not a whole native-stack
// certificate. No caller derives authority from this target-sized floor.
type BatchControls = (
    Ledger<Row>,
    Ledger<Frame>,
    PageTask,
    Option<Replacement>,
    Prepared,
    Frame,
    Bytes,
    Root,
    Root,
    ChildWork,
    StoreError,
    PageScratch,
);

// One input and one output retain their original loans across this traversal.
// Contents never stand in for a fresh read. Output admission stays lazy so an
// authenticated duplicate or malformed leaf still precedes its first debit.
#[derive(Default)]
struct PageScratch {
    input: Option<Bytes>,
    output: Option<Bytes>,
}

fn page_buffer<'a>(
    slot: &'a mut Option<Bytes>,
    operation: &Operation<'_>,
) -> Result<&'a mut Bytes, StoreError> {
    if slot.is_none() {
        *slot = Some(operation.buffer(wire::PAGE_BYTES)?);
    } else if let Some(original) = operation.original {
        // Reuse removes a reservation, not its live-owner supervision cut.
        original
            .verify_live()
            .map_err(|error| batch::admission_under(original, error))?;
    }
    slot.as_mut().ok_or(StoreError::Incompatible)
}

#[derive(Clone, Copy)]
struct PageTask {
    reference: PageReference,
    root: bool,
    lower: Option<Key>,
    upper: Option<Key>,
    start: usize,
    end: usize,
}

struct ChildWork {
    old: Child,
    replacement: Replacement,
}

struct Frame {
    task: PageTask,
    height: u8,
    children: Ledger<ChildWork>,
    next_child: usize,
    next_input: usize,
}

impl Frame {
    fn next(&mut self, rows: &[Row]) -> Result<Option<PageTask>, StoreError> {
        while self.next_child < self.children.values.len() {
            let slot = self.next_child;
            self.next_child += 1;
            let old = self.children.values[slot].old;
            let start = self.next_input;
            let end = if self.next_child == self.children.values.len() {
                self.task.end
            } else {
                start + rows[start..self.task.end].partition_point(|row| row.key <= old.upper)
            };
            self.next_input = end;
            if start == end {
                continue;
            }
            return Ok(Some(PageTask {
                reference: old.reference,
                root: false,
                lower: if slot == 0 {
                    self.task.lower
                } else {
                    Some(self.children.values[slot - 1].old.upper)
                },
                upper: Some(old.upper),
                start,
                end,
            }));
        }
        if self.next_input != self.task.end {
            return Err(StoreError::Incompatible);
        }
        Ok(None)
    }

    fn accept(&mut self, replacement: Replacement) -> Result<(), StoreError> {
        let slot = self
            .next_child
            .checked_sub(1)
            .ok_or(StoreError::Incompatible)?;
        let child = self
            .children
            .values
            .get_mut(slot)
            .ok_or(StoreError::Incompatible)?;
        // An insertion cannot remove an existing nonempty child.
        if replacement.count() == 0 {
            return Err(StoreError::Incompatible);
        }
        child.replacement = replacement;
        Ok(())
    }
}

enum Prepared {
    Branch(Frame),
    Leaf(Replacement),
}

impl Update {
    /// Inserts the existing bounded group without publishing point ancestors.
    ///
    /// Partial errors retain the actual arena in this owner. The caller must
    /// preserve its uncommitted-backing outcome before propagating the refusal.
    ///
    /// # Errors
    ///
    /// Refuses unordered, malformed or duplicate rows, invalid authenticated
    /// pages, exhausted resources, IO failures or the original operation's
    /// refusal. Partial append errors retain arena custody in this update.
    pub(in crate::content_store::packed) fn insert_absent_batch(
        &mut self,
        backend: &PackedBlobBackend,
        entries: &[(ContentId, IndexEntry)],
        operation: &mut Operation<'_>,
    ) -> Result<(), StoreError> {
        if entries.is_empty() || entries.len() > wire::MAX_ROWS {
            return Err(StoreError::Incompatible);
        }
        // Covers fixed live wrappers/copies before their construction. Each
        // dynamic ledger and page separately retains its actual body debit.
        let _controls = operation.reserve_array::<BatchControls>(1)?;
        let mut rows = Ledger::new(entries.len(), operation)?;
        for (id, entry) in entries {
            let key = Key::object(*id);
            let value = Value::object(*entry);
            value.validate_for(key)?;
            rows.values.push(Row { key, value });
        }
        // Production manifests already order ContentId exactly as Key.
        // Refuse a broken private caller invariant before any page effect.
        for pair in rows.values.windows(2) {
            match pair[0].key.cmp(&pair[1].key) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(duplicate()),
                std::cmp::Ordering::Greater => return Err(StoreError::Incompatible),
            }
        }
        let mut header = self.header;
        for row in &rows.values {
            header = changed_header(header, row.key, None, Some(row.value))?;
        }

        let replacement = match &self.root {
            Root::Inline(old) => {
                // Preserve the accepted old inline owner on every refusal.
                let mut input = operation.buffer(wire::PAGE_BYTES)?;
                input.value.extend_from_slice(&old.value);
                operation.check()?;
                let node = Node::parse(&input.value, true)?;
                let count = node
                    .count
                    .checked_add(rows.values.len())
                    .ok_or(StoreError::Quota)?;
                if count <= wire::MAX_ROWS {
                    let mut output = None;
                    merged_leaf(&node, &rows.values, 0, count, &mut output, operation)?;
                    Root::Inline(output.ok_or(StoreError::Incompatible)?)
                } else {
                    let mut output = None;
                    let children =
                        self.insert_leaf(backend, &node, &rows.values, &mut output, operation)?;
                    drop(output);
                    Root::Page(self.make_root(backend, children, operation)?)
                }
            }
            Root::Page(reference) => {
                let task = PageTask {
                    reference: *reference,
                    root: true,
                    lower: None,
                    upper: None,
                    start: 0,
                    end: rows.values.len(),
                };
                let children = self.insert_pages(backend, task, &rows.values, operation)?;
                Root::Page(match (children.first, children.second) {
                    (Some(first), None) => first.reference,
                    (Some(_), Some(_)) => self.make_root(backend, children, operation)?,
                    _ => return Err(StoreError::Incompatible),
                })
            }
        };
        let old_root = std::mem::replace(&mut self.root, replacement);
        if let Err(error) = self.collapse_root(operation) {
            self.root = old_root;
            return Err(error);
        }
        self.header = header;
        drop(old_root);
        operation.check()
    }

    fn insert_pages(
        &mut self,
        backend: &PackedBlobBackend,
        initial: PageTask,
        rows: &[Row],
        operation: &mut Operation<'_>,
    ) -> Result<Replacement, StoreError> {
        let mut frames = Ledger::<Frame>::new(wire::MAX_HEIGHT, operation)?;
        let mut scratch = PageScratch::default();
        let mut task = Some(initial);
        let mut ready = None;
        loop {
            if let Some(next) = task.take() {
                match self.prepare_page(backend, next, rows, &mut scratch, operation)? {
                    Prepared::Leaf(result) => ready = Some(result),
                    Prepared::Branch(frame) => {
                        if frames.values.len() == wire::MAX_HEIGHT {
                            return Err(StoreError::Quota);
                        }
                        frames.values.push(frame);
                    }
                }
            }
            if let Some(result) = ready.take() {
                match frames.values.last_mut() {
                    Some(frame) => frame.accept(result)?,
                    None => return Ok(result),
                }
            }
            let frame = frames.values.last_mut().ok_or(StoreError::Incompatible)?;
            if let Some(next) = frame.next(rows)? {
                task = Some(next);
                continue;
            }
            let frame = frames.values.pop().ok_or(StoreError::Incompatible)?;
            ready = Some(self.finish_branch(backend, &frame, &mut scratch, operation)?);
        }
    }

    fn prepare_page(
        &mut self,
        backend: &PackedBlobBackend,
        task: PageTask,
        rows: &[Row],
        scratch: &mut PageScratch,
        operation: &mut Operation<'_>,
    ) -> Result<Prepared, StoreError> {
        let bytes = page_buffer(&mut scratch.input, operation)?;
        self.load(
            task.reference,
            task.root,
            false,
            task.lower,
            task.upper,
            bytes,
            operation,
        )?;
        let node = Node::parse(&bytes.value, task.root)?;
        if node.height == 0 {
            return self
                .insert_leaf(
                    backend,
                    &node,
                    &rows[task.start..task.end],
                    &mut scratch.output,
                    operation,
                )
                .map(Prepared::Leaf);
        }
        let mut children = Ledger::new(node.count, operation)?;
        for slot in 0..node.count {
            let old = Child {
                upper: node.key(slot)?,
                reference: node.child(slot)?,
            };
            children.values.push(ChildWork {
                old,
                replacement: Replacement::one(old),
            });
        }
        Ok(Prepared::Branch(Frame {
            task,
            height: node.height,
            children,
            next_child: 0,
            next_input: task.start,
        }))
    }

    fn insert_leaf(
        &mut self,
        backend: &PackedBlobBackend,
        node: &Node<'_>,
        rows: &[Row],
        output: &mut Option<Bytes>,
        operation: &mut Operation<'_>,
    ) -> Result<Replacement, StoreError> {
        let count = node
            .count
            .checked_add(rows.len())
            .ok_or(StoreError::Quota)?;
        let first_count = split_count(count)?;
        let bytes = merged_leaf(node, rows, 0, first_count, output, operation)?;
        let first = self.append_page(backend, &bytes.value, operation)?;
        if first_count == count {
            return Ok(Replacement::one(first));
        }
        let bytes = merged_leaf(node, rows, first_count, count, output, operation)?;
        let second = self.append_page(backend, &bytes.value, operation)?;
        Ok(Replacement {
            first: Some(first),
            second: Some(second),
        })
    }

    fn finish_branch(
        &mut self,
        backend: &PackedBlobBackend,
        frame: &Frame,
        scratch: &mut PageScratch,
        operation: &mut Operation<'_>,
    ) -> Result<Replacement, StoreError> {
        // Revalidate old parent bytes after all child work and before output.
        let bytes = page_buffer(&mut scratch.input, operation)?;
        self.load(
            frame.task.reference,
            frame.task.root,
            false,
            frame.task.lower,
            frame.task.upper,
            bytes,
            operation,
        )?;
        let node = Node::parse(&bytes.value, frame.task.root)?;
        if node.height != frame.height || node.count != frame.children.values.len() {
            return Err(StoreError::Incompatible);
        }
        for (slot, child) in frame.children.values.iter().enumerate() {
            if node.key(slot)? != child.old.upper || node.child(slot)? != child.old.reference {
                return Err(StoreError::Incompatible);
            }
        }
        let count = frame
            .children
            .values
            .iter()
            .try_fold(0_usize, |sum, child| {
                sum.checked_add(child.replacement.count())
                    .ok_or(StoreError::Quota)
            })?;
        let first_count = split_count(count)?;
        let bytes = merged_branch(frame, 0, first_count, &mut scratch.output, operation)?;
        let first = self.append_page(backend, &bytes.value, operation)?;
        if first_count == count {
            return Ok(Replacement::one(first));
        }
        let bytes = merged_branch(frame, first_count, count, &mut scratch.output, operation)?;
        let second = self.append_page(backend, &bytes.value, operation)?;
        Ok(Replacement {
            first: Some(first),
            second: Some(second),
        })
    }
}

fn duplicate() -> StoreError {
    StoreError::InvalidComposition {
        reason: "Packed insertion requires confirmed absence",
    }
}

fn split_count(count: usize) -> Result<usize, StoreError> {
    if count == 0 || count > wire::MAX_ROWS * 2 {
        return Err(StoreError::Quota);
    }
    Ok(if count > wire::MAX_ROWS {
        count / 2
    } else {
        count
    })
}

fn merged_leaf<'a>(
    node: &Node<'_>,
    rows: &[Row],
    start: usize,
    end: usize,
    output: &'a mut Option<Bytes>,
    operation: &mut Operation<'_>,
) -> Result<&'a Bytes, StoreError> {
    if node.height != 0
        || start > end
        || end > node.count + rows.len()
        || end - start > wire::MAX_ROWS
    {
        return Err(StoreError::Incompatible);
    }
    // Check the whole affected leaf before appending either output page.
    for row in rows {
        if lookup(node, row.key)?.is_some() {
            return Err(duplicate());
        }
    }
    let out = page_buffer(output, operation)?;
    wire::begin_node(&mut out.value, 0);
    let mut old_slot = 0;
    let mut new_slot = 0;
    for slot in 0..end {
        let take_new = new_slot < rows.len()
            && (old_slot == node.count || rows[new_slot].key < node.key(old_slot)?);
        let (key, value) = if take_new {
            let row = rows[new_slot];
            new_slot += 1;
            (row.key, row.value)
        } else {
            let key = node.key(old_slot)?;
            let value = node.value(old_slot)?;
            old_slot += 1;
            (key, value)
        };
        if slot >= start {
            out.value.extend_from_slice(&key.0);
            out.value.extend_from_slice(&value.0);
        }
    }
    seal_pending(&mut out.value, 0)?;
    operation.check()?;
    Ok(out)
}

fn merged_branch<'a>(
    frame: &Frame,
    start: usize,
    end: usize,
    output: &'a mut Option<Bytes>,
    operation: &mut Operation<'_>,
) -> Result<&'a Bytes, StoreError> {
    if start > end || end - start > wire::MAX_ROWS {
        return Err(StoreError::Incompatible);
    }
    let out = page_buffer(output, operation)?;
    wire::begin_node(&mut out.value, frame.height);
    let mut slot = 0;
    for child in &frame.children.values {
        for replacement in [child.replacement.first, child.replacement.second]
            .into_iter()
            .flatten()
        {
            if slot >= start && slot < end {
                super::append_child(&mut out.value, replacement);
            }
            slot += 1;
        }
    }
    if end > slot {
        return Err(StoreError::Incompatible);
    }
    seal_pending(&mut out.value, frame.height)?;
    operation.check()?;
    Ok(out)
}
