//! Borrows the genuine lower Controller profile through upper semantic roles.
//!
//! Domain keeps semantic role admission and authority dispatch. The complete
//! measured self-profile and its private C/native observations live in Broker.
//! A wrapper accepts only that already-constructed opaque original, never raw
//! fields, files, decoded models, equality or a financial snapshot.

use std::path::Path;
use std::os::fd::AsFd as _;

use aos_sandbox_broker::controller_receiving::profile::{
    ControllerExternalProfileObservationOriginalV1, ControllerSelfProfileOriginalV1,
};
use aos_sandbox_core::ResourceVector;
use aos_systemd::FixedPid1PropertyArchiveV1;

use crate::normal_root::NormalRootStartupErrorV1;

pub use aos_sandbox_broker::controller_receiving::profile::{
    ControllerProfileFailureViewV1, ControllerProfileLocalCurrentnessOriginalV1,
    ControllerProfileRequestedCountsV1,
};

/// Retains the same genuine measured Controller profile.
///
/// Only an actual completed lower admission supplies its opaque profile. Upper
/// admission and semantic results remain independently required.
pub struct ProductionControllerNormalRootProfileV1 {
    pub(super) original: ControllerSelfProfileOriginalV1,
}

impl ProductionControllerNormalRootProfileV1 {
    /// Moves one complete original admission into its existing Domain wrapper.
    ///
    /// This performs no observation, allocation, financial entry or role grant.
    /// The opaque lower type has no public raw-field or descriptor constructor.
    #[doc(hidden)]
    #[must_use]
    pub fn from_admitted_original_v1(original: ControllerSelfProfileOriginalV1) -> Self {
        Self { original }
    }

    pub(crate) fn lower_original_v1(&self) -> &ControllerSelfProfileOriginalV1 {
        &self.original
    }

    /// Borrows the exact original profile pathname as readonly comparison DATA.
    #[must_use]
    pub fn profile_path(&self) -> &Path {
        self.original.profile_path()
    }

    /// Describes one actual local comparison without admitting or funding it.
    #[must_use]
    pub fn local_currentness_receiving_demand_v1(&self) -> Option<ResourceVector> {
        self.original.local_currentness_receiving_demand_v1()
    }

    /// Captures only the actual local original under the caller's prepaid purpose.
    ///
    /// # Errors
    /// Retains changed, unavailable or repeated native local observations.
    pub fn observe_local_currentness_retaining_v1(
        &self,
        original: &mut ControllerProfileLocalCurrentnessOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        self.original.observe_local_currentness_retaining_v1(original).map_err(Into::into)
    }

    /// Describes a full observation using the SAME existing mechanical archive.
    ///
    /// The archive's real upper lifetime, row/worker and simultaneous receiver
    /// obligations remain separate. These counts cannot construct a payer.
    #[must_use]
    pub fn external_currentness_receiving_demand_v1(
        &self,
        archive: &FixedPid1PropertyArchiveV1,
    ) -> Option<ResourceVector> {
        ControllerExternalProfileObservationOriginalV1::receiving_demand_v1(&self.original, archive)
    }

    /// Runs the fixed complete observation through the actual upper archive.
    ///
    /// This method enters no C scope and completes no upper purpose. The real
    /// enclosing purpose must prepay and retain both owner and same archive.
    ///
    /// # Errors
    /// Retains local, property, delivery, canonical or independent-post refusal.
    pub fn observe_external_currentness_retaining_v1(
        &self,
        original: &mut ControllerExternalProfileObservationOriginalV1,
        archive: &mut FixedPid1PropertyArchiveV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        original.observe_once(&self.original, archive).map_err(Into::into)
    }

    /// Captures the fixed external prefix before the actual scheduling wait.
    ///
    /// # Errors
    /// Retains unavailable or changed original local observations.
    #[doc(hidden)]
    pub fn capture_external_prefix_once_v1(&self, original: &mut ControllerExternalProfileObservationOriginalV1)
        -> Result<(), NormalRootStartupErrorV1>
    { original.capture_prefix_once_v1(&self.original).map_err(Into::into) }

    /// Completes that same comparison under the caller's actual worker slot.
    ///
    /// # Errors
    /// Retains property, delivery, canonical or independently owed local refusal.
    #[doc(hidden)]
    pub fn observe_external_prepared_under_slot_once_v1(
        &self, original: &mut ControllerExternalProfileObservationOriginalV1,
        archive: &mut FixedPid1PropertyArchiveV1,
        slot: &mut aos_systemd::FixedPid1PropertyWorkerSlotV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        original.observe_prepared_under_slot_once_v1(&self.original, archive, slot).map_err(Into::into)
    }

    /// Completes the received fixed comparison after actual worker-slot disposal.
    ///
    /// # Errors
    /// Retains decoding, canonicalization and independently owed local refusal.
    #[doc(hidden)]
    pub fn finish_external_prepared_properties_once_v1(
        &self, original: &mut ControllerExternalProfileObservationOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        original.finish_prepared_properties_once_v1(&self.original).map_err(Into::into)
    }

    /// Retains the same fixed local post when native property entry was refused.
    ///
    /// # Errors
    /// Retains the original incomplete comparison or local post refusal.
    #[doc(hidden)]
    pub fn observe_external_local_post_without_properties_once_v1(
        &self, original: &mut ControllerExternalProfileObservationOriginalV1,
    ) -> Result<(), NormalRootStartupErrorV1> {
        original.observe_local_post_without_properties_once_v1(&self.original).map_err(Into::into)
    }

    /// Borrows the same original native/semantic failure without cloning it.
    #[must_use]
    pub fn failure_view_v1(&self) -> Option<ControllerProfileFailureViewV1<'_>> {
        self.original.failure_view_v1()
    }

    /// Reports actual measured-profile representation counts without IO.
    ///
    /// # Errors
    /// Refuses checked arithmetic or unsupported existing image widths.
    pub fn profile_receiving_requested_counts_v1(
        &self,
    ) -> Result<ControllerProfileRequestedCountsV1, crate::ResourceReservationErrorV1> {
        Self::profile_receiving_requested_counts_for_runtime_files_v1(
            self.original.schema().runtime_files.len(),
        )
    }

    /// Reports the same native receiver's counts for a bounded DATA pin count.
    ///
    /// # Errors
    /// Refuses checked arithmetic or unsupported existing image widths.
    pub fn profile_receiving_requested_counts_for_runtime_files_v1(
        runtime_files: usize,
    ) -> Result<ControllerProfileRequestedCountsV1, crate::ResourceReservationErrorV1> {
        ControllerSelfProfileOriginalV1::profile_receiving_requested_counts_for_runtime_files_v1(runtime_files)
            .map_err(Into::into)
    }

    /// Reports the same closed startup envelope's passive representation counts.
    ///
    /// # Errors
    /// Refuses unsupported shapes, incomplete counts or checked arithmetic.
    pub fn startup_envelope_requested_counts_for_runtime_files_v1(
        runtime_files: usize,
        shape: crate::ControllerRuntimeStartupShapeV1,
        credentials: crate::ControllerRuntimeCredentialShapeV1,
    ) -> Result<crate::ControllerRuntimeRequestedCountsV1, crate::ResourceReservationErrorV1> {
        ControllerSelfProfileOriginalV1::startup_envelope_requested_counts_for_runtime_files_v1(
            runtime_files, shape, credentials,
        ).map_err(Into::into)
    }

    // The real Producer scope remains below this wrapper on the same C.
    // These cost projections cannot replace its entry or positive disposal.
    pub(crate) fn create_storage_producer_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, crate::ResourceReservationErrorV1> {
        self.original.create_storage_producer_receiving_demand_v1().map_err(Into::into)
    }

    pub(crate) fn create_storage_producer_traffic_v1(
        &self, producer_calls: usize,
    ) -> Option<(u64, u64)> {
        self.original.create_storage_producer_traffic_v1(producer_calls)
    }

    pub(crate) fn create_storage_producer_traffic_bound_v1(
        producer_calls: usize,
    ) -> Option<(u64, u64)> {
        ControllerSelfProfileOriginalV1::create_storage_producer_traffic_bound_v1(producer_calls)
    }

    pub(crate) fn has_same_baseline_original(
        &self,
        original: &aos_sandbox_broker::controller_receiving::ControllerReceivingOriginalV1,
    ) -> bool {
        self.original.has_same_baseline_original(original)
    }

    pub(crate) fn original_startup_pool_bounds(
        &self,
        original: &aos_sandbox_broker::controller_receiving::ControllerReceivingOriginalV1,
    ) -> Result<(ResourceVector, ResourceVector, ResourceVector), crate::ResourceReservationErrorV1> {
        self.original.original_startup_pool_bounds(original).map_err(Into::into)
    }

    pub(crate) fn original_process_stat(&self) -> Result<rustix::fs::Stat, rustix::io::Errno> {
        rustix::fs::fstat(self.original.original_process().as_fd())
    }
}
