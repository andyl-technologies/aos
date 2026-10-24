//! Quotes the locked ordinary String/Value map insertion and drained retirement.
//!
//! Rows describe logical requested backing, constructor returns and typed
//! controls. They do not authorize an operation, account compiler activation
//! frames, measure allocator residency, or cover unwinding/allocator abort.
//! Only the safe ordinary serde_json 1.0.150 BTreeMap path is selected here.
//! Source/compiler upgrades require a new audit, even when public sizes match.

use crate::ProviderError;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, mem::size_of};

#[path = "map_insert/insertion.rs"]
mod insertion;
#[path = "map_insert/layouts.rs"]
mod layouts;
#[path = "map_insert/nodes.rs"]
mod nodes;
#[path = "map_insert/retirement.rs"]
mod retirement;

// CTFE only: these arrays are source-role declarations, not run-time scratch.
const fn total<const N: usize>(values: [usize; N]) -> usize {
    let mut result = 0usize;
    let mut index = 0;
    while index < N {
        result = match result.checked_add(values[index]) {
            Some(value) => value,
            None => return usize::MAX,
        };
        index += 1;
    }
    result
}

const MAP_NEW_T: usize = total([
    size_of::<BTreeMap<String, Value>>(), // BTreeMap::new return
    size_of::<Map<String, Value>>(),      // serde_json Map::new return
    layouts::OPTIONAL_ROOT,               // BTreeMap initializer's actual None root
]);

const MAP_NEW_S: usize = size_of::<()>() // Global, PhantomData and unit new arguments
    + size_of::<usize>(); // initialized length zero

// Same source-defined node formula as requested_storage::tree_storage_data.
// This is reported backing, not a claim that an insertion allocates m+1 nodes.
const REPORTED_NODE: usize = size_of::<usize>()
    + 2 * size_of::<u16>()
    + 12 * size_of::<usize>()
    + 11 * (size_of::<String>() + size_of::<Value>())
    + 8 * (8 - 1);

/// Names the actual quote arguments, arithmetic, nested row and return windows.
///
/// The caller admits this independent row before entering any quote helper.
/// Const-evaluated role declarations add no run-time array/iterator workspace.
pub(in super::super) fn map_fixed_counter_data() -> usize {
    super::sequences::fixed_counter_data() // actual nested String-drop DATA prework
        + size_of::<usize>() // m / objects actual parameter
        + size_of::<usize>() // members retirement parameter
        + size_of::<usize>() // maximum parameter
        + size_of::<usize>() // nodes / checked addition output
        + size_of::<usize>() // retained / checked multiplication output
        + size_of::<Option<usize>>() // checked arithmetic output
        + size_of::<Result<usize, ProviderError>>() // mapped arithmetic output
        + size_of::<Result<std::convert::Infallible, ProviderError>>() // actual Result ? residual
        + size_of::<std::ops::ControlFlow<Result<std::convert::Infallible, ProviderError>, usize>>() // scalar Try branch
        + size_of::<std::ops::ControlFlow<Result<std::convert::Infallible, ProviderError>, [usize; 3]>>() // nested row Try branch
        + size_of::<std::ops::ControlFlow<Result<std::convert::Infallible, ProviderError>, ()>>() // profile Try branch
        + size_of::<[usize; 3]>() // nested String drop row
        + size_of::<Result<[usize; 3], ProviderError>>() // nested quote return
        + size_of::<[usize; 3]>() // outer local and return initializer
        + size_of::<Result<[usize; 3], ProviderError>>() // outer return envelope
        + size_of::<[usize; 3]>() // bounded's owned row argument
        + size_of::<[usize; 3]>() // bounded's returned row
        + size_of::<usize>() * 2 // add left/right argument windows
        + size_of::<usize>() // bounded scalar total local
        + size_of::<Result<(), ProviderError>>() // profile/bound outcome
        + size_of::<ProviderError>() // constructed refusal
        + size_of::<bool>() // profile and branch outcomes
}

/// Quotes a fresh map and its series of actual owned-key insertions.
///
/// `members` is the actual source object's initialized length, never a policy
/// ceiling. Search, split propagation and parent-link loops are iterative. The
/// fixed T/S roster sums their nested active functions; it is not multiplied by
/// the number of completed calls. Physical node allocations are at most members
/// in this fresh insertion-only tree. Reported backing instead uses the existing
/// conservative census of one container plus each member for nonempty maps.
///
/// # Errors
/// Refuses incompatible public geometry, checked overflow or an over-limit row.
pub(in super::super) fn map_insertion_series_data(
    members: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    check_profile()?;
    let retained = if members == 0 {
        0
    } else {
        members
            .checked_add(1)
            .and_then(|nodes| nodes.checked_mul(REPORTED_NODE))
            .ok_or_else(refused)?
    };
    let row = if members == 0 {
        [retained, MAP_NEW_T, MAP_NEW_S + map_fixed_counter_data()]
    } else {
        // The occupied-key branch is included even though the defining source
        // iterator has unique keys. A replaced deep Value is returned intact;
        // only the redundant input String is shallowly destroyed in BTreeMap.
        let key_drop = super::sequences::string_drop_data(maximum)?;
        [
            retained,
            add(MAP_NEW_T, add(insertion::TRANSIENT, key_drop[1])?)?,
            add(
                map_fixed_counter_data(),
                add(MAP_NEW_S, add(insertion::SCRATCH, key_drop[2])?)?,
            )?,
        ]
    };
    bounded(row, maximum)
}

/// Quotes fully drained forward map retirement and its shallow yielded keys.
///
/// `objects` includes actual empty objects; `members` is their actual total
/// initialized population. They bound operation counts, not private layouts.
/// Values are moved immediately into the caller's preallocated guarded work
/// stack. This row excludes destruction of an undrained iterator or deep Value.
///
/// # Errors
/// Refuses incompatible public geometry or a row exceeding the actual limit.
pub(in super::super) fn map_retirement_data(
    objects: usize,
    members: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    check_profile()?;
    if members != 0 && objects == 0 {
        return Err(refused());
    }
    let row = if objects == 0 {
        [0, 0, map_fixed_counter_data()]
    } else {
        let key_drop = super::sequences::string_drop_data(maximum)?;
        [
            0,
            add(
                retirement::TRANSIENT,
                if members == 0 { 0 } else { key_drop[1] },
            )?,
            add(
                map_fixed_counter_data(),
                add(
                    retirement::SCRATCH,
                    if members == 0 { 0 } else { key_drop[2] },
                )?,
            )?,
        ]
    };
    bounded(row, maximum)
}

fn check_profile() -> Result<(), ProviderError> {
    if layouts::profile_matches()
        && insertion::TRANSIENT != usize::MAX
        && insertion::SCRATCH != usize::MAX
        && retirement::TRANSIENT != usize::MAX
        && retirement::SCRATCH != usize::MAX
    {
        Ok(())
    } else {
        Err(ProviderError::Frame(
            "unsupported locked map construction geometry",
        ))
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn bounded(row: [usize; 3], maximum: usize) -> Result<[usize; 3], ProviderError> {
    let bytes = add(add(row[0], row[1])?, row[2])?;
    if bytes > maximum {
        return Err(refused());
    }
    Ok(row)
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native Import18 map construction")
}

#[cfg(test)]
#[path = "map_insert/tests.rs"]
mod tests;
