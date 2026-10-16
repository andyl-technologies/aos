//! Linear native backing failures preserving the first original worker refusal.
//!
//! Native page reads retain their complete error inline. Shared observation is
//! owned by the page service's originally admitted final worker-error carrier.

use crucible_cas::ram::RamStoreError;
use crucible_qemu::ram_source::{QemuRamReadBoundaryError, QemuRamSourceError};

pub(super) fn read_with_boundary<T>(
    boundary: &mut dyn FnMut() -> Result<(), QemuRamReadBoundaryError>,
    operation: impl FnOnce(&mut dyn FnMut() -> Result<(), RamStoreError>) -> Result<T, RamStoreError>,
) -> Result<T, QemuRamSourceError> {
    let mut first = None;
    let result = operation(&mut || {
        if first.is_some() {
            return Err(RamStoreError::Canceled);
        }
        match boundary() {
            Ok(()) => Ok(()),
            Err(error) => {
                first = Some(error);
                Err(RamStoreError::Canceled)
            }
        }
    });

    match (first, result) {
        (None, Ok(value)) => Ok(value),
        (Some(first), Ok(value)) => {
            drop(value);
            Err(first.into())
        }
        (Some(first), Err(RamStoreError::Canceled)) => Err(first.into()),
        (first, Err(source)) => {
            let kind = first.as_ref().map_or_else(
                || super::ram_backing_failure_kind(&source),
                |first| first.operational_kind(),
            );
            Err(QemuRamSourceError::RamBackingFailure {
                kind,
                source,
                first,
            })
        }
    }
}

#[cfg(test)]
mod tests;
