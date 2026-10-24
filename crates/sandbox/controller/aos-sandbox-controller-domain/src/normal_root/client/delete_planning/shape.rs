//! Prices the planning opening's native peak and reached cumulative traffic.

use super::super::root_connection::ControllerRootConnectionOriginalV1;
use super::{
    CreateStorageRootPeerReceivingOriginalsV1, OpeningLocal,
    ProductionControllerNormalRootProfileV1, RootDeletePlanningClientOriginalV1,
    RootStrictChunkOriginalV1,
};
use crate::journal::JournalError;
use crate::policy_compiler::RootSubjectReadinessV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::delete_root::planning::{
    DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3, DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2,
    DELETE_ROOT_PLANNING_OPEN_BYTES_V3,
};
use std::mem::size_of;

impl RootDeletePlanningClientOriginalV1<'_> {
    pub(super) fn fixed_demand_v1(
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<ResourceVector, JournalError> {
        let invalid = || JournalError::ProtectedBoundary;
        // This same supplier includes the first retained peer, a hostile chunk
        // and the separately owed whole-opening peer after simultaneously.
        let native = CreateStorageRootPeerReceivingOriginalsV1::delete_native_peak_v1(profile)
            .ok_or_else(invalid)?;
        let geometry = CreateStorageRootPeerReceivingOriginalsV1::receiving_geometry_v1()
            .map_err(|_| invalid())?;
        let (subject_bytes, subject_files) = geometry.receive_obligations_v1();
        let memory = size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(size_of::<OpeningLocal>().checked_mul(3)?))
            .and_then(|bytes| {
                bytes.checked_add(size_of::<RootStrictChunkOriginalV1>().checked_mul(3)?)
            })
            .and_then(|bytes| bytes.checked_add(subject_bytes.checked_mul(6)?))
            .and_then(|bytes| {
                bytes.checked_add(
                    DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3
                        .checked_add(DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2)?
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| {
                bytes.checked_add(RootSubjectReadinessV1::receiving_construction_bytes_v1()?)
            })
            .ok_or_else(invalid)?;
        let files = u64::try_from(subject_files).map_err(|_| invalid())?;
        let wire = DELETE_ROOT_PLANNING_OPEN_BYTES_V3
            .checked_add(DELETE_ROOT_PLANNING_CHALLENGE_BYTES_V3)
            .and_then(|bytes| bytes.checked_add(DELETE_ROOT_PLANNING_OBSERVATION_BYTES_V2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let output = u64::try_from(DELETE_ROOT_PLANNING_OPEN_BYTES_V3).map_err(|_| invalid())?;
        let connection =
            ControllerRootConnectionOriginalV1::receiving_demand_v1().ok_or_else(invalid)?;
        native
            .checked_add(connection)
            .and_then(|sum| {
                sum.checked_add(
                    ResourceVector::ZERO
                        .with(D::MemoryBytes, memory)
                        .with(D::OpenFiles, files)
                        .with(D::Pids, 1)
                        .with(D::NetworkBytes, wire)
                        .with(D::OutputBytes, output),
                )
            })
            .map_err(JournalError::ReceivingAccounting)
    }

    pub(super) fn peer_traffic_v1(samples: usize) -> Result<ResourceVector, JournalError> {
        let (network, log) = CreateStorageRootPeerReceivingOriginalsV1::query_traffic_v1(samples)
            .ok_or(JournalError::ProtectedBoundary)?;
        Ok(ResourceVector::ZERO
            .with(D::NetworkBytes, network)
            .with(D::LogBytes, log))
    }
}
