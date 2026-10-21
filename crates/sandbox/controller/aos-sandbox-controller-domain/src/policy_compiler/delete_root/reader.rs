//! Prices and projects the sole opaque native target at actual Delete callers.

use aos_sandbox_policy::native::{RootFinalityReadKindV1 as Kind,
    RootFinalityReadOriginalV1 as Target, RootReadonlyErrorV1};
use aos_sandbox_model::{ResourceDimension, ResourceVector};
use crate::journal::JournalError;
use crate::journal::historical_observation::root_readonly_error_v1;

pub(super) fn fixed_demand_v1(kind: Kind) -> Result<ResourceVector, JournalError> {
    use std::mem::size_of;
    let native = Target::fixed_construction_demand_v1(kind)
        .map_err(root_readonly_error_v1)?;
    // New constructor-call projections coexist with the existing upper
    // Result slots; native callee/ABI carriers are separately priced below.
    let construction_projection = size_of::<Result<(), JournalError>>().checked_mul(3)
        .and_then(|bytes| bytes.checked_add(size_of::<Result<(), super::RootDeleteErrorV1>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(size_of::<super::RootDeleteErrorV1>().checked_mul(3)?))
        // The later checked-add closure captures this actual usize by reference;
        // its constructor and FnOnce receiver are separate from quote Results.
        .and_then(|bytes| bytes.checked_add(size_of::<&usize>().checked_mul(2)?))
        .ok_or(JournalError::JournalTooLarge)?;
    let controls = size_of::<Kind>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(size_of::<RootReadonlyErrorV1>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(size_of::<JournalError>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(size_of::<Result<ResourceVector, JournalError>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(size_of::<Option<usize>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(construction_projection))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
    native.checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, controls))
        .map_err(JournalError::ReceivingAccounting)
}

/// Bounds inert Delete constructors before an accepted purpose is built.
pub(crate) fn inert_reader_construction_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;

    // Pending owns Controller + Source + Preparation(3) + Cleanup(2) +
    // Completion(3). Planning's separate accepted purpose owns two targets.
    // Session construction remains after its own SessionFixed admission.
    let target_constructors = 10_usize.max(2);
    let targets = Target::construction_control_bytes_v1()?
        .checked_mul(target_constructors)?;

    // The helper has a constructor/return/caller Option, one checked
    // multiply and one checked addition. The listener's closed-branch match
    // and its scalar locals have their own actual caller supplier.
    let quote_controls = size_of::<Option<usize>>().checked_mul(5)?
        // Only target count, target bytes and quote controls are local here.
        .checked_add(size_of::<usize>().checked_mul(3)?)?;
    targets.checked_add(quote_controls)
}
