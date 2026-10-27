//! Joins source-owned public/compiler models before canonical Execution growth.
//!
//! The outer C18 has already entered before this recipe reads its held map.
//! Byte/row counts come from that same Controller and the exact bounded body;
//! no decoded payload, caller ceiling or startup readiness bit chooses funding.

use std::mem::size_of;

use aos_linux_descriptors::boot::RootOriginalKernelBootIdAttemptV1;
use aos_sandbox_protocol::public_api::method::PublicApiAuditMethodV1;
use aos_sandbox_protocol::public_api::mutation::PublicMutationEnvelopeDataV1;

use super::*;

impl ExecutionPublicAdmissionScopeV2 {
    pub(crate) fn prepare_compiler_receiving_once_v2(
        &mut self,
        controller: &mut Journal,
        peer: &crate::public_api_session::PublicApiPeer,
        encoded: &[u8],
    ) -> Result<(), JournalError> {
        self.require_current_v2(controller)?;
        if self.prefix.compiler_geometry.is_some() || self.prefix.compiler_funding.is_some() {
            self.prefix.first.get_or_insert(First::Reentry);
            return Err(JournalError::ProtectedBoundary);
        }

        self.prefix.compiler_geometry = Some(compiler_receiving_demand_v2(controller, peer, encoded));
        let Some(demand) = self.prefix.compiler_geometry.as_ref()
            .and_then(|result| result.as_ref().ok()).copied()
        else {
            self.prefix.first = Some(First::CompilerGeometry);
            return Err(JournalError::ProtectedBoundary);
        };

        self.prefix.compiler_funding = Some((|| {
            let bank = self.bank.lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?;
            let mut loan = self.financial.resume_public_admission_v2(
                &bank, controller, self.profile.as_ref(),
            )?;
            let complete = loan.prefix_demand_v2().checked_add(demand)?;
            let returned = loan.require_complete_v2(
                &bank, controller, self.profile.as_ref(), Demand::from_demand_v1(complete),
            );
            let parked = loan.park_public_admission_v2();
            returned.and(parked)
        })());
        if !matches!(self.prefix.compiler_funding, Some(Ok(()))) {
            self.prefix.compiler_funding_native_selected = self.financial.failure().is_some();
            self.prefix.first = Some(First::CompilerFunding);
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

fn compiler_receiving_demand_v2(
    controller: &Journal,
    peer: &crate::public_api_session::PublicApiPeer,
    encoded: &[u8],
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    let bad = || ResourceReservationErrorV1::Conflict;
    let envelope = PublicMutationEnvelopeDataV1::decode_v1(encoded).map_err(|_| bad())?;
    if envelope.method_v1() != PublicApiAuditMethodV1::CreateExecution {
        return Err(bad());
    }

    let peer = peer.retained_recheck_demand_v1().ok_or_else(bad)?;
    let mut record_bytes = 0_usize;
    let mut record_count = 0_usize;
    for (_, key, value) in controller.all_records() {
        record_bytes = record_bytes.checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len())).ok_or_else(bad)?;
        record_count = record_count.checked_add(1).ok_or_else(bad)?;
    }
    let authorization = crate::public_mutation_compiler::delete_admission::geometry::
        authorization_model_bytes_v1(record_bytes, record_count).ok_or_else(bad)?;
    let compiler = crate::production_operation_compiler::
        public_execution_compiler_receiving_bytes_v2(encoded.len(), envelope.protobuf_body_v1().len())
        .ok_or_else(bad)?;
    let accepted = crate::reconciler::accepted_public_effect_models_receiving_bytes_retaining_v4(controller)?;
    let projection = aos_sandbox_protocol::public_api::projection::geometry::sandbox_source_receiving_bytes_v1(controller.historical_read_view_v1().rows_data_v2()).ok_or_else(bad)?;
    let boot = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1().ok_or_else(bad)?;
    let memory = size_of::<super::compiler::ExecutionPublicCompilerOriginalV2>().checked_mul(2)
        .and_then(|bytes| bytes.checked_add(authorization))
        .and_then(|bytes| bytes.checked_add(compiler))
        .and_then(|bytes| bytes.checked_add(accepted))
        .and_then(|bytes| bytes.checked_add(boot))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .and_then(|bytes| bytes.checked_add(projection)).ok_or_else(bad)?;
    let files = u64::try_from(RootOriginalKernelBootIdAttemptV1::MAXIMUM_RETAINED_FILES_V1)
        .map_err(|_| bad())?;
    let names = u64::try_from(RootOriginalKernelBootIdAttemptV1::receiving_metadata_cells_v1())
        .map_err(|_| bad())?;
    let native = ResourceVector::ZERO.with(D::MemoryBytes, memory)
        .with(D::OpenFiles, files).with(D::MetadataEntries, names);

    // Holder lookup has two retained peer checks, protected authorization has
    // two, and the compiler has one final independent peer check.
    Ok(native.checked_add(peer)?.checked_add(peer)?.checked_add(peer)?
        .checked_add(peer)?.checked_add(peer)?
        .checked_add(controller.create_storage_semantic_append_demand_v1()?)?)
}
