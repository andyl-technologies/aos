//! Retains the actual native executable measurement before ACK normalization.
//!
//! Measurement runs once under the original process, cut, policy and SDK guards.
//! Its full reference survives terminal refusal. Borrowed kernel DATA creates no
//! ACK, Source/Birth funding, model, opaque Initial/Recipe or native phase grant.

use super::super::original_prepare_executable_reference_retained_backing_data;
use super::super::{
    measure_original_restore_current_executable,
    original_prepare_executable_measurement_construction_data,
};
use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapKernelView, native_import18_bootstrap_kernel_wire_data,
    native_import18_bootstrap_operands_counter_scratch_data,
};
use crate::retained_metadata::{
    MetadataObserver, RetainedProtocolMetadataFacts, requested_metadata_backing_storage_data,
};
use crucible_node_format::{ContentRef, U64};

/// Admits the measured output beside every original bootstrap owner.
pub(in super::super) trait OriginalImport18BootstrapKernelAdmission {
    /// Admits measurement and its surviving full reference before reading the image.
    ///
    /// # Errors
    /// Refuses unavailable original funding or incomplete enclosing custody.
    fn construct_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        row: [usize; 3],
    ) -> Result<(), ProviderError>;

    /// Observes all surviving owners after either measurement outcome.
    ///
    /// # Errors
    /// Refuses incomplete whole-owner observation or insufficient original credit.
    fn finish_data(
        &self,
        original: &OriginalImport18RawBootstrap,
        measured_backing: usize,
    ) -> Result<(), ProviderError>;
}

/// Retains the same pre-read cut, spent occurrence and actual measured reference.
pub(super) struct Attempt {
    cut: OperationalDeadline,
    /// Records the spent occurrence before the first input or admission guard.
    pub(super) started: bool,
    /// Records completed construction and terminal observation, without ACK authority.
    pub(super) complete: bool,
    /// Retains the independently quoted retained, transient and counter axes.
    pub(super) row: Option<[usize; 3]>,
    /// Keeps the actual full measurement, including after terminal refusal.
    pub(super) executable: Option<ContentRef>,
}

impl Attempt {
    /// Initializes fixed slots before any private input is read.
    pub(super) fn empty_data(cut: OperationalDeadline) -> Self {
        Self {
            cut,
            started: false,
            complete: false,
            row: None,
            executable: None,
        }
    }

    fn guard(&self, cut: OperationalDeadline) -> Result<(), ProviderError> {
        if cut != self.cut || self.cut.is_expired() {
            return Err(refused());
        }
        Ok(())
    }

    /// Counts actual surviving reference capacities even after terminal refusal.
    ///
    /// # Errors
    /// Refuses checked metadata traversal or requested-backing overflow.
    pub(super) fn retained_backing_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        if let Some(executable) = &self.executable {
            observer.observe(executable)?;
        }
        requested_metadata_backing_storage_data(&observer.finish())
    }
}

impl OriginalImport18RawBootstrap {
    /// Measures the current native executable once under original initial custody.
    ///
    /// The constructor stores its real output before terminal guards and whole
    /// census. Failed completion contains the actual SDK lease and spends this
    /// occurrence while preserving every surviving original owner.
    ///
    /// # Errors
    /// Refuses retry, incomplete policy/SDK, stale original cut/process/custody,
    /// short admission, image measurement or either terminal observation.
    pub(in super::super) fn construct_bootstrap_kernel_data(
        &mut self,
        admission: &dyn OriginalImport18BootstrapKernelAdmission,
    ) -> Result<(), ProviderError> {
        if self.bootstrap_kernel.started {
            return Err(refused());
        }
        self.bootstrap_kernel.started = true;
        let outcome = self.construct_current_bootstrap_kernel(admission);
        let terminal = self.guard_bootstrap_kernel_inputs();
        if let Err(error) = outcome.and(terminal) {
            let _ = self.hello_registrar.contain_admission_data();
            return Err(error);
        }
        self.bootstrap_kernel.complete = true;
        Ok(())
    }

    fn guard_bootstrap_kernel_inputs(&self) -> Result<(), ProviderError> {
        self.bootstrap_kernel.guard(self.cut)?;
        self.with_bootstrap_policy_wire_data(|_| Ok(()))
    }

    fn construct_current_bootstrap_kernel(
        &mut self,
        admission: &dyn OriginalImport18BootstrapKernelAdmission,
    ) -> Result<(), ProviderError> {
        self.guard_bootstrap_kernel_inputs()?;
        self.admit_source_row(self.initial_construction.as_ref().ok_or_else(refused)?.row)?;
        let row = construction_data(self.bounds.requested_peak)?;
        self.bootstrap_kernel.row = Some(row);
        admission.construct_data(self, row)?;
        self.guard_bootstrap_kernel_inputs()?;

        let outcome = measure_original_restore_current_executable().map(|executable| {
            self.bootstrap_kernel.executable = Some(executable);
        });
        let terminal = self.guard_bootstrap_kernel_inputs();
        let census = self
            .bootstrap_kernel
            .retained_backing_data()
            .and_then(|actual| admission.finish_data(self, actual));
        outcome?;
        terminal?;
        census
    }

    /// Lends the actual measured native and authenticated controller kernel roles.
    ///
    /// Both guard sets run around either callback outcome under the same pre-read
    /// cut and process/thread identity. The caller separately funds normalization.
    /// Only Copy DATA returns; neither measured reference nor launch owner moves.
    ///
    /// # Errors
    /// Refuses absent/refused measurement, stale originals or SDK, invalid kernel
    /// coordinates, callback refusal or a failed terminal guard.
    pub(in super::super) fn with_bootstrap_kernel_wire_data<R: Copy>(
        &self,
        inspect: impl FnOnce(&PacketNativeImport18BootstrapKernelView<'_>) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.with_bootstrap_policy_wire_data(|_| {
            self.bootstrap_kernel.guard(self.cut)?;
            if !self.bootstrap_kernel.complete {
                return Err(refused());
            }
            let executable = self
                .bootstrap_kernel
                .executable
                .as_ref()
                .ok_or_else(refused)?;
            let bodies = self.typed_bodies_data()?;
            let launch = bodies.launch.launch_data();
            let view = native_import18_bootstrap_kernel_wire_data(
                launch.controller_pid,
                launch.controller_uid,
                &launch.controller_executable,
                U64::new(u64::from(std::process::id())),
                U64::new(u64::from(rustix::process::geteuid().as_raw())),
                executable,
            )?;
            let outcome = inspect(&view);
            let terminal = self.bootstrap_kernel.guard(self.cut);
            let output = outcome?;
            terminal?;
            Ok(output)
        })
    }

    /// Quotes original guards and the actual kernel loan's Copy result layout.
    ///
    /// Callback serialization and retained output backing remain separate.
    ///
    /// # Errors
    /// Refuses checked layout accumulation overflow for the concrete result.
    pub(in super::super) fn bootstrap_kernel_loan_counter_scratch_data<R: Copy>()
    -> Result<usize, ProviderError> {
        [
            counter_scratch_data(),
            size_of::<R>(),
            size_of::<R>(),
            size_of::<Result<R, ProviderError>>(),
            size_of::<Result<R, ProviderError>>(),
        ]
        .into_iter()
        .try_fold(
            Self::bootstrap_policy_loan_counter_scratch_data::<R>()?,
            |sum, field| sum.checked_add(field).ok_or_else(refused),
        )
    }
}

/// Quotes the actual surviving reference and sequential measurement construction.
///
/// This component does not fund DOM/JCS, callback outputs or ACK construction.
/// Headers are already fields of the original root, before its first read.
///
/// # Errors
/// Refuses checked accumulation or a complete component above the restriction.
pub(in crate::reference_packet::service) fn construction_data(
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut row = original_prepare_executable_measurement_construction_data();
    row[0] = original_prepare_executable_reference_retained_backing_data();
    let guards = OriginalImport18RawBootstrap::bootstrap_policy_loan_counter_scratch_data::<()>()?;
    row[2] = row[2]
        .max(guards)
        .checked_add(counter_scratch_data())
        .ok_or_else(refused)?;
    if row
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .is_none_or(|sum| sum > maximum)
    {
        return Err(refused());
    }
    Ok(row)
}

/// Names actual constructor, loan, kernel-coordinate and metadata controls.
pub(in crate::reference_packet::service) fn counter_scratch_data() -> usize {
    size_of::<Attempt>()
        + size_of::<PacketNativeImport18BootstrapKernelView<'static>>()
        + size_of::<Result<PacketNativeImport18BootstrapKernelView<'static>, ProviderError>>()
        + size_of::<Option<ContentRef>>()
        + size_of::<&OriginalImport18RawBootstrap>() * 3
        + size_of::<&mut OriginalImport18RawBootstrap>() * 2
        + size_of::<&dyn OriginalImport18BootstrapKernelAdmission>()
        + size_of::<MetadataObserver<'static>>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<ContentRef>()
        + size_of::<Result<ContentRef, ProviderError>>()
        + size_of::<[usize; 3]>() * 2
        + size_of::<Result<(), ProviderError>>() * 4
        + size_of::<Result<usize, ProviderError>>() * 2
        + size_of::<U64>() * 4
        + native_import18_bootstrap_operands_counter_scratch_data()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original bootstrap kernel DATA refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_absent_policy_kernel_quote_keeps_exact_restriction_and_result_layout() {
        let row = construction_data(usize::MAX).unwrap();
        let peak = row
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .unwrap();
        assert_eq!(construction_data(peak).unwrap(), row);
        assert!(construction_data(peak - 1).is_err());
        assert_eq!(construction_data(peak + 4096).unwrap(), row);
        let unit = OriginalImport18RawBootstrap::bootstrap_kernel_loan_counter_scratch_data::<()>()
            .unwrap();
        let large = OriginalImport18RawBootstrap::bootstrap_kernel_loan_counter_scratch_data::<
            [u8; 4096],
        >()
        .unwrap();
        assert!(large >= unit + 8192);
    }
}
