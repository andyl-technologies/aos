//! Retains each concrete native17 decoded owner through later field failures.
//!
//! These builders reconstruct inert data only. The separate whole borrowed pass
//! checks the exact grammar, aliases and target construction geometry before
//! any owning pass. Every caller installs its concrete attempt first. A failed
//! attempt remains poisoned with completed fields, the current child and all
//! initialized container backing; no decoded state supplies a live capability.
//!
//! Retaining object and pair fields require an enabled, unsuspended target
//! ledger before pricing or allocating their persistent child banks. The
//! enclosing operational reader supplies that independently admitted aggregate
//! bound in both passes. A disabled target helper's no-op is never admission.

use super::{HistoricalType, Ledger};
use crate::ProviderError;
use crate::retained_metadata::MetadataObserver;

mod atomic;
mod child;
mod containers;
pub(crate) mod fields;
mod json;
mod trees;
mod tuples;
mod units;

pub(crate) use atomic::{Native17AtomicAttempt, Native17BytesAttempt, Native17IdAttempt};
pub(crate) use child::Native17ChildSlot;
pub(crate) use containers::{
    Native17OptionAttempt, Native17VectorAttempt, preflight_vector_payload17_data,
    read_vector_payload17_into_data,
};
pub(crate) use fields::native17_struct;
pub(crate) use fields::{Native17Field, Native17Fields, Native17FieldsEnd, Native17ObjectAttempt};

/// Defines one complete concrete grammar and its separately retained owning pass.
pub(crate) trait Native17Build: HistoricalType {
    /// Keeps completed children and the current child before fallible descent.
    type Attempt: Default;

    /// Checks the same source rows and all future target/build allocations.
    ///
    /// Persistent child banks require an enabled, unsuspended target ledger.
    /// Its bound comes from the enclosing owner's independent admission.
    ///
    /// # Errors
    /// Refuses malformed data, mismatching rows, absent/suspended required
    /// target accounting or insufficient construction credit.
    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError>;

    /// Reconstructs into the same caller-owned attempt, retaining every failure.
    ///
    /// # Errors
    /// Refuses repeated attempts, invalid data, absent/suspended required target
    /// accounting, exhausted credit or reservation failure.
    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError>;

    /// Borrows only a fully assembled child without issuing live permission.
    fn output_data(attempt: &Self::Attempt) -> Option<&Self>;

    /// Moves a completed child into its already retained parent exactly once.
    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self>;

    /// Counts the actual independently retained backing of every partial child.
    ///
    /// # Errors
    /// Refuses requested-layout overflow or invalid child capacity data.
    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError>;

    /// Counts the actual backing of one completed inert child.
    ///
    /// # Errors
    /// Refuses requested-layout overflow or invalid child capacity data.
    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError>;
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual inert owner retention is the test observation"
)]
mod tests;
