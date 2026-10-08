//! Checked storage callbacks and reusable, originally prepaid RAM failures.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::content_store::StoreError;
use crate::owned_decode::DecodeBudget;

use super::{PreparedRamFailure, RamFailureAdmission, RamFailureCause, RamStoreError, Work};

/// Marks a refusal produced by the RAM adapter's current callback.
///
/// Its constructor is private. A direct marker is mapped back to cancellation
/// only when the same adapter recorded the original callback refusal.
#[derive(Debug)]
pub struct RamBoundaryRefusal(());

impl fmt::Display for RamBoundaryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RAM operation boundary refused")
    }
}

impl Error for RamBoundaryRefusal {}

/// Recognizes absence only through an entirely clean, uncommitted lookup scope.
pub(super) fn confirmed_absence(
    error: &RamStoreError,
    id: crate::content_store::ContentId,
) -> bool {
    match error {
        RamStoreError::Store(error) => error.confirmed_absence(id),
        _ => false,
    }
}

pub(super) struct WorkAccount<'a> {
    pub(super) original: &'a DecodeBudget,
    boundary_failure: Option<RamFailureCause<RamStoreError>>,
    validation_failure: Option<RamFailureCause<Infallible>>,
    boundary_slot: Option<PreparedRamFailure<RamStoreError>>,
    validation_slot: Option<PreparedRamFailure<Infallible>>,
}

impl<'a> WorkAccount<'a> {
    pub(super) fn new(original: &'a DecodeBudget) -> Result<Self, RamStoreError> {
        let boundary_slot =
            PreparedRamFailure::new(original).map_err(|error| admission(original, error))?;
        let validation_slot =
            PreparedRamFailure::new(original).map_err(|error| admission(original, error))?;
        Ok(Self {
            original,
            boundary_failure: None,
            validation_failure: None,
            boundary_slot: Some(boundary_slot),
            validation_slot: Some(validation_slot),
        })
    }
}

fn admission(original: &DecodeBudget, error: RamFailureAdmission) -> RamStoreError {
    match error {
        RamFailureAdmission::Original(error) => {
            crate::content_store::batch::admission_under(original, error).into()
        }
        RamFailureAdmission::Layout => RamStoreError::Limit("RAM failure allocation"),
    }
}

impl Work<'_> {
    pub(super) fn original(&self) -> &DecodeBudget {
        self.account.original
    }

    // Accepted RAM records are nonempty. Exhausted capacity therefore refuses
    // before metadata I/O, without inventing an unread object's byte length.
    // Only this guaranteed-refusal path invokes either boundary here.
    pub(super) fn reject_exhausted_nonempty_visit(&mut self) -> Result<(), RamStoreError> {
        let (visits, limit) = match self.visits.checked_add(1) {
            None => (self.visits, "object visits"),
            Some(visits) if self.io_bytes == u64::MAX => (visits, "I/O bytes"),
            Some(visits) if visits > self.limits.maximum_object_visits => (visits, "object visits"),
            Some(visits) if self.io_bytes >= self.limits.maximum_io_bytes => (visits, "I/O bytes"),
            Some(_) => return Ok(()),
        };

        self.checked(|original, boundary| {
            let verify = || {
                original
                    .verify_live()
                    .map_err(|error| crate::content_store::batch::admission_under(original, error))
            };
            verify()?;
            boundary()?;
            verify()?;
            boundary()?;
            verify()
        })?;

        // A failed second poll leaves both prior counters intact. Successful
        // polls account the attempted visit; no provider bytes were consumed.
        self.visits = visits;
        Err(RamStoreError::Limit(limit))
    }

    /// Keeps the actual first callback refusal and complete wrapped store error.
    ///
    /// Storage-only errors stay inline, so an ordinary NotFound can be followed
    /// by publication without consuming the reusable boundary failure slot.
    pub(super) fn checked<T>(
        &mut self,
        operation: impl FnOnce(
            &DecodeBudget,
            &mut dyn FnMut() -> Result<(), StoreError>,
        ) -> Result<T, StoreError>,
    ) -> Result<T, RamStoreError> {
        if let Some(failure) = &self.account.boundary_failure {
            return Err(RamStoreError::Boundary(failure.clone()));
        }
        let original = self.account.original;
        let mut first = None;
        let result = operation(original, &mut || {
            if first.is_some() {
                return Err(StoreError::RamBoundary {
                    source: RamBoundaryRefusal(()),
                });
            }
            match (self.boundary)() {
                Ok(()) => Ok(()),
                Err(error) => {
                    first = Some(error);
                    Err(StoreError::RamBoundary {
                        source: RamBoundaryRefusal(()),
                    })
                }
            }
        });

        match (first, result) {
            (None, result) => result.map_err(RamStoreError::from),
            (Some(first), Ok(value)) => {
                drop(value);
                Err(first)
            }
            (Some(first), Err(StoreError::RamBoundary { .. })) => Err(first),
            (Some(first), Err(storage)) => {
                // A retained failure poisons this Work; no second operation
                // can consume the linear reservation again.
                match self.account.boundary_slot.take() {
                    Some(slot) => {
                        let cause = slot.retain(Some(first), storage.into());
                        self.account.boundary_failure = Some(cause.clone());
                        Err(RamStoreError::Boundary(cause))
                    }
                    None => unreachable!("a live RAM Work retains its boundary slot"),
                }
            }
        }
    }

    /// Retains a complete RAM validation error inside the owning store receipt.
    pub(super) fn validation_error(&mut self, error: RamStoreError) -> StoreError {
        // A genuine storage error keeps its original category and full outcome.
        let error = match error {
            RamStoreError::Store(error) => return error,
            error => error,
        };
        if let Some(cause) = &self.account.validation_failure {
            return StoreError::RamValidation {
                source: cause.clone(),
            };
        }
        match self.account.validation_slot.take() {
            Some(slot) => {
                let cause = slot.retain(None, error);
                self.account.validation_failure = Some(cause.clone());
                StoreError::RamValidation { source: cause }
            }
            None => unreachable!("a live RAM Work retains its validation slot"),
        }
    }
}
