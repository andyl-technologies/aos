//! Checked multiwriter publication and custody of every concrete leaf outcome.
//!
//! Metadata bounds admit aggregate arrays before the first writer runs. Leaf
//! strings move into those arrays while each leaf keeps its original outcome,
//! diagnostic credit, and now-empty array allocations through outer acceptance.

use super::batch::{admission_under, allocation_under};
use super::*;
use crate::owned_decode::{DecodeBudget, DecodeScratch};

/// Bounds receipt metadata for one input of a checked publication.
///
/// The bounds cover returned placement headers and the sum of backend label
/// bytes, rather than object payloads or temporary backend work. Compositions
/// add their actual writable children's bounds with checked arithmetic. A
/// publisher must reject a receipt exceeding its declared bounds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CheckedPublicationMetadata {
    /// Maximum number of returned placements for one input object.
    pub maximum_placements: usize,
    /// Maximum total backend label bytes across those placements.
    pub maximum_backend_name_bytes: usize,
}

impl CheckedPublicationMetadata {
    pub(super) fn checked_add(self, other: Self) -> Result<Self, StoreError> {
        Ok(Self {
            maximum_placements: self
                .maximum_placements
                .checked_add(other.maximum_placements)
                .ok_or(StoreError::Quota)?,
            maximum_backend_name_bytes: self
                .maximum_backend_name_bytes
                .checked_add(other.maximum_backend_name_bytes)
                .ok_or(StoreError::Quota)?,
        })
    }
}

/// Identifies a refusal recorded by one checked composite callback adapter.
///
/// The private constructor carries no failure evidence by itself. Only the
/// originating adapter's retained first refusal gives the marker meaning.
#[derive(Debug)]
pub struct CompositeBoundaryRefusal(());

impl std::fmt::Display for CompositeBoundaryRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("checked composite boundary refused")
    }
}

impl std::error::Error for CompositeBoundaryRefusal {}

fn refusal_marker() -> StoreError {
    StoreError::CompositeBoundary {
        source: CompositeBoundaryRefusal(()),
    }
}

/// Retains a multiwriter failure and each earlier concrete publication token.
///
/// Earlier writers may already have published objects. Their original outcome
/// and diagnostic owners remain alive even when the current writer fails or
/// outer canonical acceptance refuses. Such a failure never proves absence.
pub struct CompositeScopeError {
    body: Option<Box<CompositeFailure>>,
}

struct CompositeFailure {
    first_boundary: Option<StoreError>,
    work: StoreError,
    prior: Vec<PutBatchReceipt>,
    _body_credit: DecodeScratch,
    _leaves_credit: DecodeScratch,
}

impl std::fmt::Debug for CompositeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompositeFailure")
            .field("first_boundary", &self.first_boundary)
            .field("work", &self.work)
            .field("prior", &self.prior)
            .finish_non_exhaustive()
    }
}

impl CompositeScopeError {
    /// Borrows the complete failure of the current writer or outer acceptance.
    ///
    /// The body is present throughout the public error's lifetime. Its private
    /// terminal drop takes it only after the final public borrow has ended.
    #[must_use]
    pub fn work_failure(&self) -> Option<&StoreError> {
        self.body.as_deref().map(|body| &body.work)
    }

    /// Borrows the first refusal recorded by this same operation's callback.
    #[must_use]
    pub fn first_boundary(&self) -> Option<&StoreError> {
        self.body
            .as_deref()
            .and_then(|body| body.first_boundary.as_ref())
    }

    /// Borrows all earlier returned concrete publication tokens in writer order.
    ///
    /// Their placement strings may have moved into the aggregate output, but
    /// their backend outcome and diagnostic custody have not been accepted or
    /// discarded. The slice length counts returned tokens, not durable writes.
    #[must_use]
    pub fn prior_publications(&self) -> &[PutBatchReceipt] {
        self.body
            .as_deref()
            .map_or(&[], |body| body.prior.as_slice())
    }
}

// A Box dereference move leaves its allocation for the helper's local cleanup.
// Returning the moved payload ends that cleanup before the caller can close any
// payload field, including the loan that paid for this exact Box allocation.
#[expect(
    clippy::boxed_local,
    reason = "the helper closes this original prepaid allocation before returning its loan-bearing payload"
)]
fn move_failure_payload(boxed: Box<CompositeFailure>) -> CompositeFailure {
    *boxed
}

impl Drop for CompositeScopeError {
    fn drop(&mut self) {
        if let Some(boxed) = self.body.take() {
            let body = move_failure_payload(boxed);
            drop(body);
        }
    }
}

impl std::fmt::Debug for CompositeScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.body.as_deref().fmt(formatter)
    }
}

impl std::fmt::Display for CompositeScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.work_failure() {
            Some(work) => work.fmt(formatter),
            None => formatter.write_str("closed composite publication failure"),
        }
    }
}

impl std::error::Error for CompositeScopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let work = self.work_failure()?;
        Some(work)
    }
}

pub(super) struct Accepted<T> {
    value: T,
    leaves: Vec<PutBatchReceipt>,
    failure_credit: DecodeScratch,
    leaves_credit: DecodeScratch,
}

impl<T> Accepted<T> {
    pub(super) fn value(&self) -> &T {
        &self.value
    }

    pub(super) fn release_diagnostic(&mut self) {
        for leaf in &mut self.leaves {
            leaf.release_diagnostic();
        }
    }

    pub(super) fn check(
        mut self,
        check: impl FnOnce(&mut T) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        if let Err(work) = check(&mut self.value) {
            let Self {
                value,
                leaves,
                failure_credit,
                leaves_credit,
            } = self;
            // Moved strings close before the leaf credits that still fund them.
            drop(value);
            return Err(failure(work, None, leaves, failure_credit, leaves_credit));
        }
        Ok(self)
    }
}

fn failure(
    work: StoreError,
    first_boundary: Option<StoreError>,
    prior: Vec<PutBatchReceipt>,
    body_credit: DecodeScratch,
    leaves_credit: DecodeScratch,
) -> StoreError {
    StoreError::CompositeScope {
        source: CompositeScopeError {
            body: Some(Box::new(CompositeFailure {
                first_boundary,
                work,
                prior,
                _body_credit: body_credit,
                _leaves_credit: leaves_credit,
            })),
        },
    }
}

struct Bounds {
    values: Vec<CheckedPublicationMetadata>,
    _credit: DecodeScratch,
}

struct Prepared {
    value: Vec<PutReceipt>,
    leaves: Vec<PutBatchReceipt>,
    failure_credit: DecodeScratch,
    leaves_credit: DecodeScratch,
    value_credit: DecodeScratch,
}

impl Prepared {
    fn fail(self, work: StoreError, first_boundary: Option<StoreError>) -> StoreError {
        let Self {
            value,
            leaves,
            failure_credit,
            leaves_credit,
            value_credit,
        } = self;
        drop(value);
        drop(value_credit);
        failure(work, first_boundary, leaves, failure_credit, leaves_credit)
    }
}

pub(super) fn metadata<'a>(
    mut writers: impl Iterator<Item = &'a dyn ImmutableBlobBackend>,
    kind: ObjectKind,
) -> Result<CheckedPublicationMetadata, StoreError> {
    writers.try_fold(CheckedPublicationMetadata::default(), |total, writer| {
        total.checked_add(writer.checked_publication_metadata(kind)?)
    })
}

pub(super) fn publish<'a>(
    writers: impl Iterator<Item = &'a dyn ImmutableBlobBackend> + Clone,
    original: &DecodeBudget,
    objects: &[(ContentId, BlobHandle)],
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<PutBatchReceipt, StoreError> {
    let mut selected = writers.clone();
    let first = selected.next().ok_or(StoreError::InvalidComposition {
        reason: "checked composite has no writable child",
    })?;
    if selected.next().is_none() {
        return first.put_many_if_absent_with_boundary(original, objects, boundary);
    }
    original
        .verify_live()
        .map_err(|error| admission_under(original, error))?;
    if objects.len() > 64 {
        return Err(StoreError::Quota);
    }
    let writer_count = writers.clone().count();
    let bound_count = writer_count
        .checked_mul(objects.len())
        .ok_or(StoreError::Quota)?;
    let bound_credit = original
        .reserve_scratch_array::<CheckedPublicationMetadata>(bound_count)
        .map_err(|error| admission_under(original, error))?;
    let mut bounds = Vec::new();
    bounds
        .try_reserve_exact(bound_count)
        .map_err(|error| allocation_under(original, error))?;
    let mut totals = [CheckedPublicationMetadata::default(); 64];
    for writer in writers.clone() {
        for (index, (id, _)) in objects.iter().enumerate() {
            let bound = writer.checked_publication_metadata(id.kind())?;
            totals[index] = totals[index].checked_add(bound)?;
            bounds.push(bound);
        }
    }
    let bounds = Bounds {
        values: bounds,
        _credit: bound_credit,
    };
    let value_bytes = objects
        .len()
        .checked_mul(std::mem::size_of::<PutReceipt>())
        .ok_or(StoreError::Quota)?;
    let value_bytes = totals[..objects.len()]
        .iter()
        .try_fold(value_bytes, |bytes, bound| {
            bound
                .maximum_placements
                .checked_mul(std::mem::size_of::<PlacementReceipt>())
                .and_then(|placement_bytes| bytes.checked_add(placement_bytes))
                .ok_or(StoreError::Quota)
        })?;
    let failure_credit = original
        .reserve_scratch_bytes(std::alloc::Layout::new::<CompositeFailure>().size() as u64)
        .map_err(|error| admission_under(original, error))?;
    let leaves_credit = original
        .reserve_scratch_array::<PutBatchReceipt>(writer_count)
        .map_err(|error| admission_under(original, error))?;
    let value_credit = original
        .reserve_scratch_bytes(value_bytes as u64)
        .map_err(|error| admission_under(original, error))?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(objects.len())
        .map_err(|error| allocation_under(original, error))?;
    for ((id, _), bound) in objects.iter().zip(totals) {
        let mut placements = Vec::new();
        placements
            .try_reserve_exact(bound.maximum_placements)
            .map_err(|error| allocation_under(original, error))?;
        value.push(PutReceipt {
            id: *id,
            placements,
        });
    }
    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(writer_count)
        .map_err(|error| allocation_under(original, error))?;
    let mut prepared = Prepared {
        value,
        leaves,
        failure_credit,
        leaves_credit,
        value_credit,
    };
    let mut first_boundary = None;
    for (writer_index, writer) in writers.enumerate() {
        let mut check = || {
            if first_boundary.is_some() {
                return Err(refusal_marker());
            }
            match checked_reader::check(original, boundary) {
                Ok(()) => Ok(()),
                Err(error) => {
                    first_boundary = Some(error);
                    Err(refusal_marker())
                }
            }
        };
        if let Err(error) = check() {
            return Err(prepared.fail(error, first_boundary.take()));
        }
        let leaf = match writer.put_many_if_absent_with_boundary(original, objects, &mut check) {
            Ok(leaf) => leaf,
            Err(error) => return Err(prepared.fail(error, first_boundary.take())),
        };
        // A child cannot turn a consumed refusal into success. Its concrete
        // returned outcome is converted while its original custody is intact.
        if first_boundary.is_some() {
            let error = match leaf.check(|_| Err(refusal_marker())) {
                Err(error) => error,
                Ok(leaf) => {
                    drop(leaf);
                    refusal_marker()
                }
            };
            return Err(prepared.fail(error, first_boundary.take()));
        }
        let start = writer_index * objects.len();
        let child_bounds = &bounds.values[start..start + objects.len()];
        let leaf = match leaf.check(|receipts| {
            validate_receipts(receipts, objects, child_bounds)?;
            for (aggregate, receipt) in prepared.value.iter_mut().zip(receipts) {
                aggregate.placements.append(&mut receipt.placements);
            }
            Ok(())
        }) {
            Ok(leaf) => leaf,
            Err(error) => return Err(prepared.fail(error, None)),
        };
        prepared.leaves.push(leaf);
    }
    let Prepared {
        value,
        leaves,
        failure_credit,
        leaves_credit,
        value_credit,
    } = prepared;
    Ok(PutBatchReceipt::new_composite(
        Accepted {
            value,
            leaves,
            failure_credit,
            leaves_credit,
        },
        value_credit,
        original.clone(),
    ))
}

fn validate_receipts(
    receipts: &[PutReceipt],
    objects: &[(ContentId, BlobHandle)],
    bounds: &[CheckedPublicationMetadata],
) -> Result<(), StoreError> {
    if receipts.len() != objects.len() {
        return Err(StoreError::InvalidComposition {
            reason: "checked composite receipt count differs from input",
        });
    }
    for ((receipt, (id, source)), bound) in receipts.iter().zip(objects).zip(bounds) {
        let name_bytes = receipt
            .placements
            .iter()
            .try_fold(0_usize, |bytes, placement| {
                bytes
                    .checked_add(placement.backend.len())
                    .ok_or(StoreError::Quota)
            })?;
        if receipt.id != *id
            || receipt.placements.len() > bound.maximum_placements
            || name_bytes > bound.maximum_backend_name_bytes
            || receipt
                .placements
                .iter()
                .any(|placement| placement.logical_length != source.logical_length())
        {
            return Err(StoreError::InvalidComposition {
                reason: "checked composite receipt exceeds declared metadata",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
