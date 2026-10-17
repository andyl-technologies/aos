//! Checked storage callbacks and reusable, originally prepaid RAM failures.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use crate::content_store::StoreError;
use crate::owned_decode::DecodeBudget;

use super::read_failure::RamReadValidation;
use super::read_failure::{FirstReadCause, RamReadContinuation};
use super::{PreparedRamFailure, RamFailureAdmission, RamStoreError, Work};

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
    state: RetainedReadState,
}

/// Moves the existing operation's prepaid slots and sticky first cause across
/// request boundaries without admitting another account or another slot.
pub(super) struct RetainedReadState {
    first_failure: Option<FirstReadCause>,
    boundary_slot: Option<PreparedRamFailure<RamStoreError>>,
    validation_slot: Option<PreparedRamFailure<Infallible>>,
}

impl RetainedReadState {
    pub(super) fn read_failure(&self) -> Option<StoreError> {
        self.first_failure.as_ref().map(FirstReadCause::error)
    }
}

impl<'a> WorkAccount<'a> {
    pub(super) fn new(original: &'a DecodeBudget) -> Result<Self, RamStoreError> {
        let boundary_slot =
            PreparedRamFailure::new(original).map_err(|error| admission(original, error))?;
        let validation_slot =
            PreparedRamFailure::new(original).map_err(|error| admission(original, error))?;
        Ok(Self {
            original,
            state: RetainedReadState {
                first_failure: None,
                boundary_slot: Some(boundary_slot),
                validation_slot: Some(validation_slot),
            },
        })
    }

    pub(super) fn from_retained(original: &'a DecodeBudget, state: RetainedReadState) -> Self {
        Self { original, state }
    }

    pub(super) fn into_retained(self) -> RetainedReadState {
        self.state
    }

    pub(super) fn check_boundary(
        &mut self,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<(), RamStoreError> {
        if let Some(first) = self.first_read_cause() {
            return Err(first.error().into());
        }
        if let Err(error) = self.original.verify_live() {
            let error = RamStoreError::from_admission(self.original, error);
            return Err(self.fail_read(error).into());
        }
        if let Err(first) = boundary() {
            let storage = StoreError::RamBoundary {
                source: RamBoundaryRefusal(()),
            };
            return Err(self.retain_boundary(first, storage));
        }
        if let Err(error) = self.original.verify_live() {
            let error = RamStoreError::from_admission(self.original, error);
            return Err(self.fail_read(error).into());
        }
        Ok(())
    }

    fn retain_boundary(&mut self, first: RamStoreError, storage: StoreError) -> RamStoreError {
        let slot = match self.state.boundary_slot.take() {
            Some(slot) => slot,
            None => unreachable!("a live operation retains its boundary prepayment"),
        };
        let cause = slot.retain(Some(first), storage.into());
        self.state.first_failure = Some(FirstReadCause::Boundary(cause.clone()));
        StoreError::RamReadBoundary { source: cause }.into()
    }

    fn first_read_cause(&self) -> Option<FirstReadCause> {
        self.state.first_failure.clone()
    }

    pub(super) fn read_failure(&self) -> Option<StoreError> {
        self.first_read_cause().map(|first| first.error())
    }

    /// Seals the first read error before a provider can consume its return value.
    pub(super) fn fail_read(&mut self, error: RamStoreError) -> StoreError {
        if let Some(first) = self.first_read_cause() {
            return first.error();
        }
        if let RamStoreError::Boundary(source) = error {
            self.state.first_failure = Some(FirstReadCause::Boundary(source.clone()));
            return StoreError::RamReadBoundary { source };
        }
        let slot = match self.state.validation_slot.take() {
            Some(slot) => slot,
            None => unreachable!("a live RAM read retains its validation prepayment"),
        };
        let source = slot.retain(None, error);
        self.state.first_failure = Some(FirstReadCause::Validation(source.clone()));
        StoreError::RamValidation { source }
    }

    /// Runs a checked continuation using the same original and first refusal.
    pub(super) fn checked<T>(
        &mut self,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
        operation: impl FnOnce(
            &DecodeBudget,
            &mut dyn FnMut() -> Result<(), StoreError>,
        ) -> Result<T, StoreError>,
    ) -> Result<T, RamStoreError> {
        if let Some(first) = &self.state.first_failure {
            return Err(match first {
                FirstReadCause::Boundary(failure) => RamStoreError::Boundary(failure.clone()),
                first => first.error().into(),
            });
        }
        let original = self.original;
        let mut first = None;
        let result = operation(original, &mut || {
            if first.is_some() {
                return Err(StoreError::RamBoundary {
                    source: RamBoundaryRefusal(()),
                });
            }
            match boundary() {
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
            (Some(first), Err(storage @ StoreError::RamBoundary { .. })) => {
                Err(self.retain_boundary(first, storage))
            }
            (Some(first), Err(storage)) => {
                // A retained failure poisons this Work; no second operation
                // can consume the linear reservation again.
                match self.state.boundary_slot.take() {
                    Some(slot) => {
                        let cause = slot.retain(Some(first), storage.into());
                        self.state.first_failure = Some(FirstReadCause::Boundary(cause.clone()));
                        Err(RamStoreError::Boundary(cause))
                    }
                    None => unreachable!("a live RAM Work retains its boundary slot"),
                }
            }
        }
    }

    /// Seals pending validation only after the provider has completed cleanup.
    pub(super) fn fail_validation_with_provider(
        &mut self,
        first: RamStoreError,
        provider: StoreError,
    ) -> StoreError {
        if let Some(first) = self.first_read_cause() {
            return first.error();
        }
        let slot = match self.state.boundary_slot.take() {
            Some(slot) => slot,
            None => unreachable!("a pending validation retains its larger prepayment"),
        };
        let source = RamReadValidation::new(slot.retain(Some(first), provider.into()));
        self.state.first_failure = Some(FirstReadCause::ValidationWithProvider(source.clone()));
        StoreError::RamReadValidation { source }
    }

    /// Keeps the same first cause and a distinct provider's complete cleanup.
    pub(super) fn reconcile_failed_read(&mut self, returned: StoreError) -> StoreError {
        let first = match self.first_read_cause() {
            Some(first) => first,
            None => unreachable!("a failed RAM read retains its first cause"),
        };
        if first.matches(&returned) {
            return returned;
        }
        // Preparation owns only a loan, not an allocated carrier. Moving the
        // unused slot into credit leaves no second allocation funded by it.
        let credit = match &first {
            FirstReadCause::Boundary(_) | FirstReadCause::ValidationWithProvider(_) => {
                match self.state.validation_slot.take() {
                    Some(slot) => slot.into_credit(),
                    None => unreachable!("the first boundary leaves validation credit unused"),
                }
            }
            FirstReadCause::Validation(_) => match self.state.boundary_slot.take() {
                Some(slot) => slot.into_credit(),
                None => unreachable!("the first validation leaves boundary credit unused"),
            },
        };
        StoreError::RamReadContinuation {
            source: RamReadContinuation::new(first, returned, credit),
        }
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
        self.account.checked(self.boundary, operation)
    }

    /// Retains a complete RAM validation error inside the owning store receipt.
    pub(super) fn validation_error(&mut self, error: RamStoreError) -> StoreError {
        // A genuine storage error keeps its original category and full outcome.
        let error = match error {
            RamStoreError::Store(error) => return error,
            error => error,
        };
        if let Some(first) = self.account.first_read_cause() {
            return first.error();
        }
        match self.account.state.validation_slot.take() {
            Some(slot) => {
                let cause = slot.retain(None, error);
                self.account.state.first_failure = Some(FirstReadCause::Validation(cause.clone()));
                StoreError::RamValidation { source: cause }
            }
            None => unreachable!("a live RAM Work retains its validation slot"),
        }
    }
}

pub(super) fn admit_object(
    limits: super::RamStoreLimits,
    visits: &mut u64,
    io_bytes: &mut u64,
    length: u64,
    maximum: u64,
) -> Result<(), RamStoreError> {
    if length > maximum {
        return Err(RamStoreError::Limit("single canonical object"));
    }
    *visits = visits
        .checked_add(1)
        .ok_or(RamStoreError::Limit("object visits"))?;
    *io_bytes = io_bytes
        .checked_add(length)
        .ok_or(RamStoreError::Limit("I/O bytes"))?;
    if *visits > limits.maximum_object_visits {
        return Err(RamStoreError::Limit("object visits"));
    }
    if *io_bytes > limits.maximum_io_bytes {
        return Err(RamStoreError::Limit("I/O bytes"));
    }
    Ok(())
}
