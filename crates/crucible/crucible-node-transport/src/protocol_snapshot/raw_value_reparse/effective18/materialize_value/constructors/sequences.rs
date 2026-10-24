//! Quotes actual empty-bank sequence constructors for the guarded materializer.
//!
//! The closed callers instantiate Work, BuildFrame and Value banks. Counts come
//! from the same actual flat source, not a caller capacity or admission token.
//! R is additional requested backing only; parent/tree headers remain separate.
//! T names actual initializer/return windows and S names fixed source controls.
//! Every result is demand DATA, never permission to allocate or retire a tree.

use super::super::*;
use std::mem::size_of;

#[path = "sequences/controls.rs"]
mod controls;
#[path = "sequences/dispatch.rs"]
mod dispatch;
#[path = "sequences/layout.rs"]
mod layout;

fn failure() -> ProviderError {
    ProviderError::ResourceExhausted("guarded materializer sequence constructor")
}

fn plus(first: usize, second: usize) -> Result<usize, ProviderError> {
    first.checked_add(second).ok_or_else(failure)
}

fn times(first: usize, second: usize) -> Result<usize, ProviderError> {
    first.checked_mul(second).ok_or_else(failure)
}

fn finish(row: [usize; 3], maximum: usize) -> Result<[usize; 3], ProviderError> {
    if plus(plus(row[0], row[1])?, row[2])? > maximum {
        return Err(failure());
    }
    Ok(row)
}

/// Names quotation's own fixed controls before any supplier metadata query.
///
/// Actual typed constructors are named in their returned full S before effects.
/// This row covers only these allocation-free DATA queries, not a source walk.
pub(in super::super) fn fixed_counter_data() -> usize {
    size_of::<[usize; 3]>() * 3
        + size_of::<Result<[usize; 3], ProviderError>>() * 2
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Option<usize>>() * 2
        + size_of::<usize>() * 16
        + size_of::<bool>() * 2
        + size_of::<ProviderError>() * 2
        + dispatch::query_try_scratch()
}

/// Quotes one actual empty Vec<T>::new -> try_reserve_exact(count) bank.
///
/// The materializer uses this for Work, BuildFrame and Value. Existing nonempty
/// bank growth, element Clone/Drop and allocator backend residency are not covered.
/// The actual std allocation/deallocation dispatch through its ABI is named.
/// Root the bank before its reserve; observe actual capacity before deep work.
///
/// # Errors
/// Refuses checked layout/storage overflow or the actual signed allocation limit.
pub(in super::super) fn vec_reservation_data<T: 'static>(
    count: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let backing = times(count, size_of::<T>())?;
    if backing > isize::MAX as usize {
        return Err(failure());
    }
    finish(
        [
            backing,
            controls::new_reserve_transient::<T>(),
            plus(fixed_counter_data(), controls::new_reserve_scratch::<T>())?,
        ],
        maximum,
    )
}

/// Quotes actual no-growth push/pop moves for an already reserved typed bank.
///
/// Push/pop counts are independent proven operation bounds over the real source,
/// never the bank's capacity used as demand. The closed caller proves no growth
/// before moving deep inputs; this helper does not establish their custody.
/// Child construction, child Drop and backing remain separately retained.
///
/// # Errors
/// Refuses checked cumulative move-window arithmetic or the supplied full bound.
pub(in super::super) fn vec_push_pop_data<T: 'static>(
    pushes: usize,
    pops: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let transient = plus(
        times(pushes, controls::push_transient::<T>())?,
        times(pops, controls::pop_transient::<T>())?,
    )?;
    finish(
        [
            0,
            transient,
            plus(
                fixed_counter_data(),
                plus(controls::push_scratch::<T>(), controls::pop_scratch::<T>())?,
            )?,
        ],
        maximum,
    )
}

/// Quotes empty String -> try_reserve_exact(len) -> push_str of those same bytes.
///
/// Unlike String::clone/from, this reaches SpecExtend<u8> and append_elements'
/// genuine no-growth reserve call. The parent roots the String before reserve
/// and observes capacity before push_str. No UTF-8 parsing or new Value pass runs.
///
/// # Errors
/// Refuses checked quote arithmetic, signed allocation limit or the full bound.
pub(in super::super) fn string_copy_data(
    length: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let reserve = vec_reservation_data::<u8>(length, maximum)?;
    finish(
        [
            reserve[0],
            plus(reserve[1], controls::string_transient())?,
            plus(reserve[2], controls::string_scratch())?,
        ],
        maximum,
    )
}

/// Quotes actual consuming array iteration and exhausted scalar bank teardown.
///
/// Only Value is instantiated by the actual retirement loop. Every element must
/// move into the pre-admitted retirement owner; an early deep IntoIter Drop is a
/// separate caller defect, not authorized here. No backing is allocated/cloned.
///
/// # Errors
/// Refuses checked cumulative move-window arithmetic or the supplied full bound.
pub(in super::super) fn vec_into_iter_data<T: 'static>(
    items: usize,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    finish(
        [
            0,
            plus(
                controls::into_iter_transient::<T>(),
                times(items, controls::into_iter_item_transient::<T>())?,
            )?,
            plus(fixed_counter_data(), controls::into_iter_scratch::<T>())?,
        ],
        maximum,
    )
}

/// Quotes only a Vec<T> shell's ordinary drop and backing deallocation.
///
/// Value/BuildFrame children must already be drained by the actual guard. Any
/// remaining Work String-key child Drop is an independently priced scalar call.
/// The supplied row never authorizes recursive or arbitrary user element Drop.
///
/// # Errors
/// Refuses the complete fixed control row above the supplied bound.
pub(in super::super) fn vec_shell_drop_data<T: 'static>(
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    finish(
        [
            0,
            0,
            plus(
                fixed_counter_data(),
                controls::vec_shell_drop_scratch::<T>(),
            )?,
        ],
        maximum,
    )
}

/// Quotes actual shallow String field-drop and its Vec<u8> backing release.
///
/// This applies to a real map key discarded by occupied-entry handling, too.
/// It includes no Clone, deep Value retirement or allocator backend residency.
/// Its actual std deallocation dispatch through the ABI remains named.
///
/// # Errors
/// Refuses the complete fixed control row above the supplied bound.
pub(in super::super) fn string_drop_data(maximum: usize) -> Result<[usize; 3], ProviderError> {
    finish(
        [
            0,
            0,
            plus(
                fixed_counter_data(),
                plus(
                    size_of::<&mut String>(),
                    controls::vec_shell_drop_scratch::<u8>(),
                )?,
            )?,
        ],
        maximum,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "sequences/tests.rs"]
mod tests;

/// Quotes the actual typed usize access paths used for frames and array slots.
///
/// The closed caller uses BuildFrame/Value only. Actual private indices prove
/// in-bounds Index/IndexMut before effects; this supplies no range/user index or
/// out-of-bounds panic construction. No T value is cloned or moved by access.
///
/// # Errors
/// Refuses the complete fixed control row above the supplied bound.
pub(in super::super) fn vec_access_data<T: 'static>(
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    finish(
        [
            0,
            0,
            plus(fixed_counter_data(), controls::access_scratch::<T>())?,
        ],
        maximum,
    )
}
