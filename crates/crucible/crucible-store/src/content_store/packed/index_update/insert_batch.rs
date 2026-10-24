//! One bounded whole-group placement insertion with unchanged on-disk pages.
//!
//! Each affected subtree authenticates once on entry and each old parent is
//! freshly revalidated after child work. Only final affected pages are appended;
//! no intermediate point-update ancestors or process cache are retained. An
//! iterative, paid work stack keeps per-level ledgers off the native call stack.

use super::{Bytes, ContentId, IndexEntry, Key, Node, Operation, PackedBlobBackend};
use super::{Child, Root, Update, changed_header, lookup, seal_pending};
use super::{PageReference, StoreError, Value, wire};
use crate::content_store::batch;
use crate::owned_decode::DecodeScratch;

#[cfg(test)]
mod tests;

const MAX_REPLACEMENT_PAGES: usize = batch::MAX_PUBLICATION_OBJECTS.div_ceil(wire::MAX_ROWS) + 1;

// A node starts with at most 64 rows/references and receives at most 256
// inputs. Its balanced result occupies at most five unchanged-width pages.
#[derive(Clone, Copy)]
struct Replacement {
    children: [Option<Child>; MAX_REPLACEMENT_PAGES],
}

impl Replacement {
    fn empty() -> Self {
        Self {
            children: [None; MAX_REPLACEMENT_PAGES],
        }
    }

    fn one(child: Child) -> Self {
        let mut result = Self::empty();
        result.children[0] = Some(child);
        result
    }

    fn count(self) -> usize {
        self.children().count()
    }

    fn children(&self) -> impl Iterator<Item = Child> + Clone + '_ {
        self.children.iter().copied().flatten()
    }

    fn push(&mut self, child: Child) -> Result<(), StoreError> {
        let slot = self.count();
        let output = self.children.get_mut(slot).ok_or(StoreError::Quota)?;
        *output = Some(child);
        Ok(())
    }
}

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

// Fixed validation copies borrow the same control admission as their caller.
type ValidationControls = (
    wire::Header,
    wire::Header,
    Key,
    Value,
    Option<Key>,
    StoreError,
);

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
    ValidationControls,
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

// BatchControls prepays this fixed inline value. Boxing its leaf would add an
// independently allocated owner and a new admission/failure boundary.
#[expect(
    clippy::large_enum_variant,
    reason = "The admitted inline value requires no extra failure-path allocation."
)]
enum Prepared {
    Branch(Frame),
    Leaf(Replacement),
}

impl Update {
    /// Validates the entire unpublished object group before compaction writes.
    ///
    /// # Errors
    ///
    /// Refuses its original control admission, malformed/unordered/duplicate
    /// inputs or overflowing object counters before any page IO.
    pub(in crate::content_store::packed) fn validate_absent_batch(
        header: wire::Header,
        entries: &[(ContentId, IndexEntry)],
        operation: &Operation<'_>,
    ) -> Result<(), StoreError> {
        let _controls = operation.reserve_array::<ValidationControls>(1)?;
        validate_header(header, entries).map(|_| ())
    }

    /// Inserts the whole bounded group without publishing window ancestors.
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
        if entries.is_empty() || entries.len() > batch::MAX_PUBLICATION_OBJECTS {
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
        // One unpublished group validates all arithmetic before its page effects.
        // The former per-window arithmetic/native-effect ordering is retired.
        let header = validate_header(self.header, entries)?;

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
                    require_absent(&node, &rows.values)?;
                    merged_leaf(&node, &rows.values, 0, count, &mut output, operation)?;
                    Root::Inline(output.ok_or(StoreError::Incompatible)?)
                } else {
                    let mut output = None;
                    let children =
                        self.insert_leaf(backend, &node, &rows.values, &mut output, operation)?;
                    drop(output);
                    Root::Page(self.make_root_from_children(
                        backend,
                        children.children(),
                        operation,
                    )?)
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
                Root::Page(if children.count() == 1 {
                    children
                        .children()
                        .next()
                        .ok_or(StoreError::Incompatible)?
                        .reference
                } else {
                    self.make_root_from_children(backend, children.children(), operation)?
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
        let node = self.load(
            task.reference,
            task.root,
            false,
            task.lower,
            task.upper,
            bytes,
            operation,
        )?;
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
        let pages = output_pages(count)?;
        // Every duplicate is checked before the first output append, even when
        // a concentrated group produces more than two physical leaf pages.
        require_absent(node, rows)?;
        let mut replacement = Replacement::empty();
        for page in 0..pages {
            let (start, end) = output_range(count, pages, page)?;
            let bytes = merged_leaf(node, rows, start, end, output, operation)?;
            replacement.push(self.append_page(backend, &bytes.value, operation)?)?;
        }
        Ok(replacement)
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
        let node = self.load(
            frame.task.reference,
            frame.task.root,
            false,
            frame.task.lower,
            frame.task.upper,
            bytes,
            operation,
        )?;
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
        let pages = output_pages(count)?;
        let mut replacement = Replacement::empty();
        for page in 0..pages {
            let (start, end) = output_range(count, pages, page)?;
            let bytes = merged_branch(frame, start, end, &mut scratch.output, operation)?;
            replacement.push(self.append_page(backend, &bytes.value, operation)?)?;
        }
        Ok(replacement)
    }
}

fn duplicate() -> StoreError {
    StoreError::InvalidComposition {
        reason: "Packed insertion requires confirmed absence",
    }
}

// Production manifests already order ContentId exactly as Key. Whole-group
// arithmetic and geometry are checked without page reads or allocations.
fn validate_header(
    mut header: wire::Header,
    entries: &[(ContentId, IndexEntry)],
) -> Result<wire::Header, StoreError> {
    if entries.is_empty() || entries.len() > batch::MAX_PUBLICATION_OBJECTS {
        return Err(StoreError::Incompatible);
    }
    let mut prior = None;
    for (id, entry) in entries {
        let key = Key::object(*id);
        let value = Value::object(*entry);
        value.validate_for(key)?;
        if let Some(previous) = prior {
            match key.cmp(&previous) {
                std::cmp::Ordering::Greater => {}
                std::cmp::Ordering::Equal => return Err(duplicate()),
                std::cmp::Ordering::Less => return Err(StoreError::Incompatible),
            }
        }
        header = changed_header(header, key, None, Some(value))?;
        prior = Some(key);
    }
    Ok(header)
}

fn output_pages(count: usize) -> Result<usize, StoreError> {
    let maximum = wire::MAX_ROWS
        .checked_add(batch::MAX_PUBLICATION_OBJECTS)
        .ok_or(StoreError::Quota)?;
    if count == 0 || count > maximum {
        return Err(StoreError::Quota);
    }
    Ok(count.div_ceil(wire::MAX_ROWS))
}

fn output_range(count: usize, pages: usize, page: usize) -> Result<(usize, usize), StoreError> {
    if pages != output_pages(count)? || page >= pages {
        return Err(StoreError::Incompatible);
    }
    // Balanced contiguous ranges preserve the old two-page split and place
    // at least 32 rows in each output whenever a nonroot split is required.
    let start = page.checked_mul(count).ok_or(StoreError::Quota)? / pages;
    let end = page
        .checked_add(1)
        .and_then(|next| next.checked_mul(count))
        .ok_or(StoreError::Quota)?
        / pages;
    if end - start > wire::MAX_ROWS || (pages > 1 && end - start < wire::MIN_ROWS) {
        return Err(StoreError::Incompatible);
    }
    Ok((start, end))
}

fn require_absent(node: &Node<'_>, rows: &[Row]) -> Result<(), StoreError> {
    for row in rows {
        if lookup(node, row.key)?.is_some() {
            return Err(duplicate());
        }
    }
    Ok(())
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
        for replacement in child.replacement.children() {
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
