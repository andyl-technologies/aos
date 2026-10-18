//! Admits immutable private observation assets before worker or Source birth.
//!
//! These paths select the authored guest. They grant no process or native role;
//! the ordinary Main factory still admits every launch. One shared input body
//! retains its original decoder custody instead of copying paths into workers.

use crucible_engine::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Selects one existing positive native assertion program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativePluginFlightKind {
    /// Compares four-vCPU reference and preempted runs through exact idle wake.
    FourVcpu,
    /// Exercises real block recovery and the existing hot-fork preparation checks.
    BlockRecovery,
}

/// Retains the immutable deployed assets for one native assertion program.
#[derive(Clone, Debug)]
pub struct NativePluginFlightInputs {
    // Keep this graph free of Weak or raw body aliases so final strong drop
    // destroys the allocation before this wrapper returns its input loans.
    pub(super) body: Arc<NativePluginFlightInputBody>,
    _custody: DecodeCustody,
}

#[derive(Debug)]
pub(super) struct NativePluginFlightInputBody {
    pub(super) kind: NativePluginFlightKind,
    pub(super) kernel: PathBuf,
    pub(super) initrd: PathBuf,
    pub(super) firmware: PathBuf,
}

/// Reports admission or allocation failure before an input body is published.
#[derive(Debug, thiserror::Error)]
pub enum NativePluginFlightInputError {
    /// An original decoder account refused the actual containing extent.
    #[error(transparent)]
    Admission(#[from] DecodeAdmissionError),
    /// A prepaid path allocation failed.
    #[error(transparent)]
    Allocation(#[from] std::collections::TryReserveError),
    /// An authored asset path was not absolute.
    #[error("native observation requires absolute immutable guest asset paths")]
    RelativePath,
}

impl NativePluginFlightInputs {
    /// Copies one deployed asset tuple under the supplied original input account.
    ///
    /// The containing Arc header, body and each exact path capacity are charged
    /// before allocation. Worker aliases copy only existing Arc handles, whose
    /// inline storage is part of the actual Main worker body query.
    ///
    /// # Errors
    /// Refuses relative paths, expired or exhausted input credit, or allocation failure.
    pub fn new_admitted(
        kind: NativePluginFlightKind,
        kernel: &Path,
        initrd: &Path,
        firmware: &Path,
        budget: &DecodeBudget,
    ) -> Result<Self, NativePluginFlightInputError> {
        if [kernel, initrd, firmware]
            .iter()
            .any(|path| !path.is_absolute())
        {
            return Err(NativePluginFlightInputError::RelativePath);
        }
        budget.verify_live()?;
        budget.charge_array::<NativePluginFlightInputBody>(1)?;
        budget.charge_array::<usize>(2)?;
        let kernel = copy_path(kernel, budget)?;
        let initrd = copy_path(initrd, budget)?;
        let firmware = copy_path(firmware, budget)?;
        Ok(Self {
            body: Arc::new(NativePluginFlightInputBody {
                kind,
                kernel,
                initrd,
                firmware,
            }),
            _custody: budget.custody(),
        })
    }
}

fn copy_path(path: &Path, budget: &DecodeBudget) -> Result<PathBuf, NativePluginFlightInputError> {
    let bytes = path.as_os_str().as_encoded_bytes().len();
    budget.charge_array::<u8>(bytes)?;
    let mut output = std::ffi::OsString::new();
    output.try_reserve_exact(bytes)?;
    output.push(path.as_os_str());
    Ok(output.into())
}

#[cfg(test)]
mod tests;
