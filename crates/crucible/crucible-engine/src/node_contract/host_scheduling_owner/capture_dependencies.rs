//! Retains direct edges from the genuine unchanged-cut Host2 producer.
//!
//! The current plan belongs to the same original source and prepared Runtime7
//! continuation. It is data custody, never a capture ticket or source permit.
//! Snapshot edges name that runtime and each original body consumed by the typed
//! restoration context. Journal edges name exactly that runtime and snapshot.

use super::*;
use crate::node_contract::{HostSchedulingContinuationV2, NodeRuntime};
use crate::node_scheduling::InputPayload;
use std::mem::{align_of, size_of};

#[path = "capture_dependencies/restored17.rs"]
mod restored17;

const JOURNAL_MEDIA: &str =
    "application/vnd.crucible.host-scheduling-capture-journal+json;version=2";

/// Reports distinct prospective Host2 adjacency owners as requested-layout data.
#[derive(Clone, Copy, Debug)]
pub struct HostCaptureDependencyStorageData {
    source_born_growth: usize,
    returned_row_growth: usize,
    maximum_lookup_scratch: usize,
    maximum_dependency_count: usize,
}

impl HostCaptureDependencyStorageData {
    /// Returns the retained plan and its prospective journal-reference backing.
    ///
    /// The early factory walk precedes this plan's installation. The late quote
    /// charges the whole plan conservatively even when another view saw it.
    pub fn source_born_growth(&self) -> usize {
        self.source_born_growth
    }

    /// Returns both separately returned dependency vectors and fullref backing.
    pub fn returned_row_growth(&self) -> usize {
        self.returned_row_growth
    }

    /// Returns one returned row coexisting with its verification hash.
    pub fn maximum_lookup_scratch(&self) -> usize {
        self.maximum_lookup_scratch
    }

    /// Returns the largest retained direct-edge population after duplicate suppression.
    pub fn maximum_dependency_count(&self) -> usize {
        self.maximum_dependency_count
    }
}

/// Reports a known Host2 row's prospective copy and full-body verification storage.
#[derive(Clone, Copy, Debug)]
pub struct HostCaptureDependencyLookupData {
    returned_row_bytes: usize,
    verification_bytes: usize,
}

impl HostCaptureDependencyLookupData {
    /// Returns the independently returned vector and fullref clone backing.
    pub fn returned_row_bytes(&self) -> usize {
        self.returned_row_bytes
    }

    /// Returns the temporary hash backing used by the actual identity contract.
    pub fn verification_bytes(&self) -> usize {
        self.verification_bytes
    }

    /// Returns their checked simultaneous requested-layout sum.
    ///
    /// # Errors
    /// Refuses arithmetic overflow; the result grants no storage or native right.
    pub fn requested_bytes(&self) -> Result<usize, RuntimeError> {
        add(self.returned_row_bytes, self.verification_bytes)
    }
}

pub(super) struct OriginalHostDependencyPlan {
    runtime: ContentRef,
    snapshot: ContentRef,
    snapshot_dependencies: Vec<ContentRef>,
    journal_dependencies: [ContentRef; 2],
    journal: RefCell<Option<ContentRef>>,
}

fn add(left: usize, right: usize) -> Result<usize, RuntimeError> {
    left.checked_add(right).ok_or(RuntimeError::ResourceLimit)
}

fn within(bytes: usize, maximum: usize) -> Result<usize, RuntimeError> {
    if bytes > maximum {
        Err(RuntimeError::ResourceLimit)
    } else {
        Ok(bytes)
    }
}

fn reference_bytes(reference: &ContentRef) -> Result<usize, RuntimeError> {
    NodeRuntime::capture_reference_storage(reference)
}

fn row_bytes<'a>(mut rows: impl Iterator<Item = &'a ContentRef>) -> Result<usize, RuntimeError> {
    rows.try_fold(0usize, |bytes, reference| {
        add(
            add(bytes, size_of::<ContentRef>())?,
            reference_bytes(reference)?,
        )
    })
}

// These are requests made by this fixed canonical producer, not estimates of
// opaque existing String capacity. Existing references always use real capacity.
fn generated_hash_bytes() -> usize {
    "blake3-256".len() + "cnp.blob.v1".len() + 64
}
fn generated_snapshot_bytes() -> usize {
    generated_hash_bytes() + "application/json".len()
}
fn generated_journal_bytes() -> usize {
    generated_hash_bytes() + JOURNAL_MEDIA.len()
}

fn plan_header() -> Result<usize, RuntimeError> {
    add(
        size_of::<OriginalHostDependencyPlan>(),
        NodeRuntime::capture_protocol_shared_header_storage(
            1,
            align_of::<OriginalHostDependencyPlan>(),
            usize::MAX,
        )?,
    )
}

impl OriginalHostDependencyPlan {
    fn retained_storage_without_journal(&self) -> Result<usize, RuntimeError> {
        let mut bytes = add(plan_header()?, reference_bytes(&self.runtime)?)?;
        bytes = add(bytes, reference_bytes(&self.snapshot)?)?;
        bytes = add(
            bytes,
            self.snapshot_dependencies
                .capacity()
                .checked_mul(size_of::<ContentRef>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for reference in &self.snapshot_dependencies {
            bytes = add(bytes, reference_bytes(reference)?)?;
        }
        for reference in &self.journal_dependencies {
            bytes = add(bytes, reference_bytes(reference)?)?;
        }
        Ok(bytes)
    }

    fn retained_storage(&self) -> Result<usize, RuntimeError> {
        let mut bytes = self.retained_storage_without_journal()?;
        let journal = self
            .journal
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if let Some(reference) = journal.as_ref() {
            bytes = add(bytes, reference_bytes(reference)?)?;
        }
        Ok(bytes)
    }

    fn data(&self) -> Result<HostCaptureDependencyStorageData, RuntimeError> {
        let snapshot = row_bytes(self.snapshot_dependencies.iter())?;
        let journal = row_bytes(self.journal_dependencies.iter())?;
        Ok(HostCaptureDependencyStorageData {
            // This plan is installed after the early factory/source walk. Its
            // whole actual backing must join the late peak, not only the final
            // journal-reference growth. Exclude the actual journal here so the
            // fixed future allowance remains stable after producer completion.
            source_born_growth: add(
                self.retained_storage_without_journal()?,
                generated_journal_bytes(),
            )?,
            returned_row_growth: add(snapshot, journal)?,
            maximum_lookup_scratch: add(
                snapshot,
                NodeRuntime::capture_hash_storage(&self.snapshot.hash)?,
            )?
            .max(add(journal, generated_hash_bytes())?),
            maximum_dependency_count: self.snapshot_dependencies.len().max(2),
        })
    }

    fn retain_journal(
        &self,
        runtime: &ContentRef,
        snapshot: &ContentRef,
        journal: &ContentRef,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        if &self.runtime != runtime || &self.snapshot != snapshot {
            return Err(RuntimeError::ForeignAuthority);
        }
        if journal.media_type != JOURNAL_MEDIA || journal == snapshot {
            return Err(RuntimeError::InvalidReceipt);
        }
        let future = reference_bytes(journal)?;
        // The late preflight names this exact producer's future reference bank.
        within(future, generated_journal_bytes())?;
        within(add(self.retained_storage()?, future)?, maximum)?;
        let mut slot = self
            .journal
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        if slot.is_some() {
            return Err(RuntimeError::OutstandingObligations);
        }
        *slot = Some(journal.clone());
        Ok(())
    }

    fn lookup(
        &self,
        reference: &ContentRef,
        maximum_objects: usize,
    ) -> Result<Option<HostCaptureDependencyLookupData>, RuntimeError> {
        let Some(rows) = self.dependencies(reference)? else {
            return Ok(None);
        };
        if rows.len() > maximum_objects {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(Some(HostCaptureDependencyLookupData {
            returned_row_bytes: row_bytes(rows.iter())?,
            verification_bytes: NodeRuntime::capture_hash_storage(&reference.hash)?,
        }))
    }

    fn copy_dependencies(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum_objects: usize,
        maximum_scratch_bytes: usize,
    ) -> Result<Option<Vec<ContentRef>>, RuntimeError> {
        let Some(quote) = self.lookup(reference, maximum_objects)? else {
            return Ok(None);
        };
        within(quote.requested_bytes()?, maximum_scratch_bytes)?;
        reference
            .verify(bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let rows = self
            .dependencies(reference)?
            .ok_or(RuntimeError::InvalidReceipt)?;
        let mut copied = Vec::new();
        copied
            .try_reserve_exact(rows.len())
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let actual_slots = copied
            .capacity()
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        let requested_slots = rows
            .len()
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        within(
            add(
                quote
                    .requested_bytes()?
                    .checked_sub(requested_slots)
                    .ok_or(RuntimeError::ResourceLimit)?,
                actual_slots,
            )?,
            maximum_scratch_bytes,
        )?;
        copied.extend(rows.iter().cloned());
        Ok(Some(copied))
    }

    fn dependencies(&self, reference: &ContentRef) -> Result<Option<&[ContentRef]>, RuntimeError> {
        let journal = self
            .journal
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let snapshot_matches = reference == &self.snapshot;
        let journal_matches = journal.as_ref() == Some(reference);
        if snapshot_matches && journal_matches {
            return Err(RuntimeError::InvalidReceipt);
        }
        if snapshot_matches {
            return Ok(Some(&self.snapshot_dependencies));
        }
        if journal_matches {
            return Ok(Some(&self.journal_dependencies));
        }
        Ok(None)
    }
}

impl HostSchedulingSource {
    fn dependency_origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id()
            || self.owner_thread != thread::current().id()
            || self.edition != preservation::Edition::CompleteOriginalLineage
            || self.original_ticket.is_some()
            || self.archive_ticket.is_some()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(super) fn retained_dependency_storage(&self) -> Result<usize, RuntimeError> {
        self.dependency_origin()?;
        let plan = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        plan.as_ref().map_or(Ok(0), |plan| plan.retained_storage())
    }

    pub(crate) fn precharge_capture_dependency_plan(
        &self,
        runtime: &NodeRuntime,
        runtime_object: &InputPayload,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.dependency_origin()?;
        runtime.authenticate_host_scheduling_source(self)?;
        let runtime_bytes = reference_bytes(&runtime_object.reference)?;
        let mut rows = add(size_of::<ContentRef>(), runtime_bytes)?;
        for object in runtime.original_lineage_capture_objects() {
            rows = add(
                rows,
                add(size_of::<ContentRef>(), reference_bytes(&object.reference)?)?,
            )?;
        }
        let fixed = add(
            plan_header()?,
            add(runtime_bytes, generated_snapshot_bytes())?,
        )?;
        let journal_edges = add(runtime_bytes, generated_snapshot_bytes())?;
        // Old and new plans coexist until the fully checked new plan is stored.
        within(
            add(
                self.retained_dependency_storage()?,
                add(fixed, add(rows, journal_edges)?)?,
            )?,
            maximum,
        )
    }

    pub(crate) fn prepare_capture_dependency_plan(
        &self,
        snapshot: &HostSchedulingContinuationV2,
        runtime_object: &InputPayload,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.dependency_origin()?;
        let record = snapshot.record();
        if record.source != self.selection
            || !matches!(&record.runtime,
            HostSchedulingRuntimeRecord::OriginalLineage(runtime)
                if runtime.source_activation.world_binding_hash == self.world
                    && runtime.capture_cut == record.scheduling.capture_cut
                    && runtime.capture_ordinal == record.scheduling.capture_ordinal)
        {
            return Err(RuntimeError::InvalidReceipt);
        }
        let dependencies = std::iter::once(&runtime_object.reference)
            .chain(record.objects.iter().map(|object| &object.reference));
        let count = record
            .objects
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let fixed = add(
            plan_header()?,
            add(
                reference_bytes(&runtime_object.reference)?,
                reference_bytes(&snapshot.encoded().reference)?,
            )?,
        )?;
        let edge_heaps = add(
            reference_bytes(&runtime_object.reference)?,
            reference_bytes(&snapshot.encoded().reference)?,
        )?;
        let old = self.retained_dependency_storage()?;
        let requested_rows = row_bytes(dependencies.clone())?;
        within(
            add(old, add(fixed, add(requested_rows, edge_heaps)?)?)?,
            maximum,
        )?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(count)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let actual_slots = rows
            .capacity()
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        let requested_slots = count
            .checked_mul(size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?;
        within(
            add(
                old,
                add(
                    fixed,
                    add(
                        add(
                            requested_rows
                                .checked_sub(requested_slots)
                                .ok_or(RuntimeError::ResourceLimit)?,
                            actual_slots,
                        )?,
                        edge_heaps,
                    )?,
                )?,
            )?,
            maximum,
        )?;
        rows.extend(dependencies.cloned());
        rows.sort_unstable();
        rows.dedup();
        let plan = Rc::new(OriginalHostDependencyPlan {
            runtime: runtime_object.reference.clone(),
            snapshot: snapshot.encoded().reference.clone(),
            snapshot_dependencies: rows,
            journal_dependencies: [
                runtime_object.reference.clone(),
                snapshot.encoded().reference.clone(),
            ],
            journal: RefCell::new(None),
        });
        within(add(old, plan.retained_storage()?)?, maximum)?;
        // Only the private Core preflight installs this current lookup plan.
        // Old signed archives retain their own verified closure/rows; replacing
        // transient lookup data never refunds Core capture IDs or archive banks.
        *self
            .capture_dependencies
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OutstandingObligations)? = Some(plan);
        self.dependency_origin()
    }

    pub(super) fn retain_capture_journal_dependencies(
        &self,
        runtime: &ContentRef,
        snapshot: &ContentRef,
        journal: &ContentRef,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.dependency_origin()?;
        let plans = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let plan = plans.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        plan.retain_journal(runtime, snapshot, journal, maximum)?;
        // Keep this original association even if a later currentness fence or
        // the enclosing into-slot producer fails with its output already held.
        self.dependency_origin()
    }

    /// Borrows the current original Host2 plan for the same prepared Runtime7.
    ///
    /// # Errors
    /// Refuses another creator/edition, missing plan or another runtime object.
    pub fn original_complete_capture_dependency_preflight_data(
        &self,
        runtime: &ContentRef,
    ) -> Result<HostCaptureDependencyStorageData, RuntimeError> {
        self.dependency_origin()?;
        let plans = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let plan = plans.as_ref().ok_or(RuntimeError::UnsupportedFacet)?;
        if &plan.runtime != runtime {
            return Err(RuntimeError::ForeignAuthority);
        }
        let data = plan.data()?;
        self.dependency_origin()?;
        Ok(data)
    }

    /// Quotes one same-source born Host2 row without copying its references.
    ///
    /// # Errors
    /// Refuses foreign/busy source data or excessive edge count. Unknown rows
    /// return None; they are never accepted as intrinsic leaves.
    pub fn original_complete_capture_dependency_lookup_data(
        &self,
        reference: &ContentRef,
        maximum_objects: usize,
    ) -> Result<Option<HostCaptureDependencyLookupData>, RuntimeError> {
        self.dependency_origin()?;
        let plans = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let Some(plan) = plans.as_ref() else {
            return Ok(None);
        };
        let data = plan.lookup(reference, maximum_objects)?;
        self.dependency_origin()?;
        Ok(data)
    }

    /// Copies only direct edges retained by this actual Host2 producer.
    ///
    /// Full supplied bytes must satisfy the exact retained original fullref.
    /// The data row grants no source, continuation or archive permission.
    ///
    /// # Errors
    /// Refuses changed bytes, foreign/busy data, excess population or insufficient
    /// named scratch. Unknown rows return None before hashing or allocation.
    pub fn original_complete_capture_dependencies_data(
        &self,
        reference: &ContentRef,
        bytes: &[u8],
        maximum_objects: usize,
        maximum_scratch_bytes: usize,
    ) -> Result<Option<Vec<ContentRef>>, RuntimeError> {
        self.dependency_origin()?;
        let plans = self
            .capture_dependencies
            .try_borrow()
            .map_err(|_| RuntimeError::OutstandingObligations)?;
        let Some(plan) = plans.as_ref() else {
            return Ok(None);
        };
        let copied =
            plan.copy_dependencies(reference, bytes, maximum_objects, maximum_scratch_bytes)?;
        self.dependency_origin()?;
        Ok(copied)
    }
}

#[cfg(test)]
#[path = "capture_dependencies/tests.rs"]
mod tests;
