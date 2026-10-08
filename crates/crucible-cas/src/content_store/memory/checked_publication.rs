//! Bounded memory publication with exact visibility evidence and paid failures.

use super::*;
use crate::content_store::checked_reader;
use crate::owned_decode::{DecodeBudget, DecodeScratch};

/// Reports synchronous Memory map effects and backend authentication progress.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryPublicationOutcome {
    /// Number of new immutable map entries published by this operation.
    pub published_objects: u8,
    /// Number of inputs authenticated and accepted by the backend.
    ///
    /// This count includes existing entries and does not grant outer facade
    /// acceptance. Memory publication makes no durable-storage claim.
    pub accepted_objects: u8,
}

/// Retains a checked Memory failure with its exact publication evidence.
pub struct MemoryScopeError {
    body: Box<Failure>,
    _credit: DecodeScratch,
}

struct Failure {
    work: StoreError,
    outcome: MemoryPublicationOutcome,
}

impl MemoryScopeError {
    /// Borrows the original typed work or final-acceptance failure.
    #[must_use]
    pub fn work_failure(&self) -> &StoreError {
        &self.body.work
    }

    /// Returns observed synchronous map effects while their cause remains owned.
    #[must_use]
    pub fn outcome(&self) -> MemoryPublicationOutcome {
        self.body.outcome
    }
}

impl std::fmt::Debug for MemoryScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryScopeError")
            .field("work", &self.body.work)
            .field("outcome", &self.body.outcome)
            .finish()
    }
}

impl std::fmt::Display for MemoryScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "checked memory scope failed ({:?})",
            self.body.outcome
        )
    }
}

impl std::error::Error for MemoryScopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.work_failure())
    }
}

pub(in crate::content_store) struct Accepted<T> {
    value: T,
    outcome: MemoryPublicationOutcome,
    credit: DecodeScratch,
}

impl<T> Accepted<T> {
    pub(in crate::content_store) fn value(&self) -> &T {
        &self.value
    }

    pub(in crate::content_store) fn release_diagnostic(&mut self) {
        // Memory has no staging or worker diagnostic storage. Retain the paid
        // Failure extent so any later facade check still has an original payer.
    }

    pub(in crate::content_store) fn check(
        mut self,
        check: impl FnOnce(&mut T) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        match check(&mut self.value) {
            Ok(()) => Ok(self),
            Err(error) => {
                let Self {
                    value,
                    outcome,
                    credit,
                } = self;
                drop(value);
                Err(scope_error(error, outcome, credit))
            }
        }
    }
}

fn scope_error(
    work: StoreError,
    outcome: MemoryPublicationOutcome,
    credit: DecodeScratch,
) -> StoreError {
    StoreError::MemoryScope {
        source: MemoryScopeError {
            body: Box::new(Failure { work, outcome }),
            _credit: credit,
        },
    }
}

pub(super) fn publish(
    backend: &MemoryBlobBackend,
    original: &DecodeBudget,
    objects: &[(ContentId, BlobHandle)],
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<PutBatchReceipt, StoreError> {
    backend.require_namespace()?;
    checked_reader::check(original, boundary)?;
    if objects.len() > 64 {
        return Err(StoreError::Quota);
    }
    let receipt_credit = batch::admit_receipts(original, objects.len(), backend.name.len())?;
    // The concrete recursive StoreError geometry is included before effects;
    // wrapping an incoming cause grants no claim about its own prior funding.
    let credit = original
        .reserve_scratch_array::<Failure>(1)
        .map_err(|error| batch::admission_under(original, error))?;
    let mut outcome = MemoryPublicationOutcome::default();
    let result = (|| {
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(objects.len())
            .map_err(|error| batch::allocation_under(original, error))?;
        for (id, source) in objects {
            checked_reader::check(original, boundary)?;
            let bytes = source
                .read_all_with_boundary(original, backend.max_logical_bytes, boundary)
                .map_err(|error| match error {
                    StoreError::InvalidSourceLength { .. } => StoreError::Corrupt { id: *id },
                    other => other,
                })?;
            // Only a complete authenticated handle can elide this digest. A
            // range authenticates its whole source, not the exposed bytes as
            // an independently publishable object under the source identity.
            if source.authenticated_id != Some(*id) {
                validate_bytes(*id, &bytes)?;
            }
            checked_reader::check(original, boundary)?;
            let mut state = super::checked::lock(backend, original, boundary)?;
            if let Some(existing) = state.objects.get(id) {
                existing.bytes()?;
            } else {
                backend.check_unique_insertion(state.objects.len())?;
                let next_bytes = state
                    .logical_bytes
                    .checked_add(source.logical_length())
                    .ok_or(StoreError::Quota)?;
                if next_bytes > backend.max_logical_bytes {
                    return Err(StoreError::Quota);
                }
                let generation = state.generation.checked_add(1).ok_or(StoreError::Quota)?;
                let control_bytes =
                    (std::mem::size_of::<MemoryObject>() + 2 * std::mem::size_of::<usize>()) as u64;
                let object_credit = original
                    .reserve_scratch_bytes(control_bytes)
                    .map_err(|error| batch::admission_under(original, error))?;
                checked_reader::check(original, boundary)?;
                // The callback may revoke N independently of current A; check
                // the saved original again before any covered map insertion.
                backend.check_unique_insertion(state.objects.len())?;
                // Keep the independently admitted copy's actual payload payer,
                // which may be source S, separate from metadata/control payer A.
                // This loan is allocation custody, not future source permission.
                let object = MemoryBody::new(MemoryObject {
                    bytes: MemoryBytes::Checked(bytes),
                    custody: Default::default(),
                    _credit: Some(object_credit),
                });
                state.objects.insert(*id, object);
                state.generation = generation;
                state.logical_bytes = next_bytes;
                outcome.published_objects += 1;
            }
            outcome.accepted_objects += 1;
            drop(state);
            checked_reader::check(original, boundary)?;
            receipts.push(PutReceipt::one(
                *id,
                PlacementReceipt {
                    backend: backend.name.clone(),
                    durable: false,
                    logical_length: source.logical_length(),
                },
            ));
            checked_reader::check(original, boundary)?;
        }
        checked_reader::check(original, boundary)?;
        Ok(receipts)
    })();
    match result {
        Ok(value) => Ok(PutBatchReceipt::new_memory(
            Accepted {
                value,
                outcome,
                credit,
            },
            receipt_credit,
            original.clone(),
        )),
        Err(work) => Err(scope_error(work, outcome, credit)),
    }
}

#[cfg(test)]
pub(super) fn failure_allocation_bytes() -> usize {
    std::mem::size_of::<Failure>()
}
