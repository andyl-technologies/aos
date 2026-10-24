//! Compares final startup axes with the genuine original construction inputs.
//!
//! The full storage row includes ingress, actions and fixed construction. This
//! equality never substitutes that aggregate for spendable action partitioning.

use super::settled_data17::invalid;
use super::*;

/// Checks the actual prefix rows against the exact pre-new17 snapshot and additions.
///
/// The caller first authenticates the real prefix17/private claim and actual
/// imported construction inputs. This DATA equality does not install a reserve.
/// The suffix is already included in the old native row and is never added twice.
///
/// # Errors
/// Refuses changed old rows, omitted/changed Prepare, checked overflow or any
/// unequal final native retained, transient or scratch axis.
pub fn authenticate_original_native_settled_final_rows_data(
    existing: &PacketRestoredSettledNativeExistingRowsData,
    storage: &PacketRestoredSettledNativeStorageData,
    construction: &PacketNativeSettledConstructionStorageData,
    final_native_birth: &PacketNativeStartupAllocationRow,
    final_restore_prepare: &Option<PacketNativeStartupAllocationRow>,
) -> Result<(), ProviderError> {
    if existing != storage.existing_rows_data()
        || existing.restore_prepare != *final_restore_prepare
    {
        return Err(invalid());
    }

    let add = |old: U64, first: usize, second: usize| -> Result<U64, ProviderError> {
        let first = u64::try_from(first).map_err(|_| invalid())?;
        let second = u64::try_from(second).map_err(|_| invalid())?;
        Ok(U64::new(
            old.get()
                .checked_add(first)
                .and_then(|v| v.checked_add(second))
                .ok_or_else(invalid)?,
        ))
    };

    let expected = PacketNativeStartupAllocationRow {
        retained_requested_bytes: add(
            existing.native_birth.retained_requested_bytes,
            storage.retained_requested_bytes_data(),
            construction.native_retained_requested_bytes(),
        )?,
        maximum_simultaneous_transient_bytes: add(
            existing.native_birth.maximum_simultaneous_transient_bytes,
            storage.transient_requested_bytes_data(),
            construction.native_transient_requested_bytes(),
        )?,
        declared_counter_scratch_bytes: add(
            existing.native_birth.declared_counter_scratch_bytes,
            storage.counter_scratch_bytes_data(),
            original_native_settled_carrier_counter_scratch_data(),
        )?,
    };
    expected.requested_peak_data()?;
    if expected != *final_native_birth {
        return Err(invalid());
    }
    Ok(())
}
