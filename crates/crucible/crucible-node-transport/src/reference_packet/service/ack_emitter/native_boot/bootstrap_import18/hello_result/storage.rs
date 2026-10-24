//! Combines complete Hello result clones with physical constructor controls.
//!
//! Kernel entropy is written into an already retained fixed array. Its syscall
//! owns no userspace allocation; the real result then owns two fresh Bytes
//! vectors and the complete original provider manifest clone.

use super::attempt::Attempt;
use crate::ProviderError;
use crate::handshake::HelloResult;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use std::mem::size_of;

type ConstructorTransientFields = [usize; 7];

/// Quotes actual initial result construction without issuing a Hello response.
///
/// # Errors
/// Refuses unsupported clone geometry, invalid declarations, checked overflow
/// or a complete peak above the independently selected original restriction.
pub(super) fn construction_data(
    launch: &PacketNative5SourceLaunch,
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut row =
        super::super::hello_registrar::hello_result_clone_construction_data(launch, maximum)?;
    let fields: ConstructorTransientFields = [
        size_of::<HelloResult>(),
        size_of::<Option<HelloResult>>(),
        size_of::<crucible_node_format::Bytes>() * 2,
        size_of::<Vec<u8>>() * 2,
        size_of::<Result<usize, rustix::io::Errno>>(),
        size_of::<Result<(), ProviderError>>() * 2,
        size_of::<ProviderError>(),
    ];
    let constructor = fields.into_iter().try_fold(0usize, |sum, field| {
        sum.checked_add(field).ok_or_else(refused)
    })?;
    // Field-clone controls coexist with the enclosing result initializer and
    // destination move. Unlike the registrar's separate retained slot phases,
    // these constructor headers cannot reuse the clone control window.
    row[1] = row[1].checked_add(constructor).ok_or_else(refused)?;
    row[2] = row[2].max(counter_scratch_data());
    let peak = row.into_iter().try_fold(0usize, |sum, axis| {
        sum.checked_add(axis).ok_or_else(refused)
    })?;
    if maximum == 0 || peak > maximum {
        return Err(refused());
    }
    Ok(row)
}

/// Names real clone quoting, physical entropy and row-combination controls.
pub(super) fn counter_scratch_data() -> usize {
    super::super::hello_registrar::hello_result_clone_counter_scratch_data()
        + Attempt::counter_scratch_data()
        + size_of::<ConstructorTransientFields>()
        + size_of::<std::array::IntoIter<usize, 7>>()
        + size_of::<std::array::IntoIter<usize, 3>>()
        + size_of::<&PacketNative5SourceLaunch>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<Option<usize>>() * 2
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<usize>() * 5
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original import18 SDK Hello result construction")
}
