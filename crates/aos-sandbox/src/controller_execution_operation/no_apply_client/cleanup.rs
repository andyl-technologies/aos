//! Binds fresh cleanup Source/C18 to the same finite NoApply native sender.
//!
//! Historical64/39 packets are comparison inputs. Only the opaque completed
//! acquisition borrower unlocks new42; it grants no Apply or ordinary execution.

use super::*;
mod completion;
pub use completion::ControllerExecutionNoApplyRecoveredMetadataV2;
use crate::policy_compiler::provisioning_current::create_finality::authorization::RootRecoveryAdmissionReferenceDataV2;
use aos_sandbox_core::RawPairedClockSample;
use aos_sandbox_protocol::host_execution_availability::observation::HostExecutionAvailabilityObservationV2;

pub(super) struct CleanupOriginV2 {
    pub(super) admission: RootRecoveryAdmissionReferenceDataV2,
    pub(super) first: RawPairedClockSample,
    pub(super) nonce: [u8; 32],
    pub(super) availability: HostExecutionAvailabilityObservationV2,
    pub(super) acquisition: Option<Vec<u8>>,
    pub(super) acquisition_funding: Option<Result<(), ResourceReservationErrorV1>>,
    pub(super) acquisition_fields: Option<Result<
        aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionFieldsV2,
        aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionDataErrorV2>>,
}

impl ControllerExecutionNoApplyOriginalV2 {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::controller_execution_operation) fn borrow_cleanup_no_apply_client_once_v2<
        'turn,
        'original,
    >(
        &'turn mut self,
        controller: &'turn mut Journal,
        bank: &'turn ControllerResourceBankOpeningV1,
        profile: &'turn ProductionControllerNormalRootProfileV1,
        mut receiving: ControllerExecutionReadReceivingLoanV1<'turn, 'original>,
        admission: RootRecoveryAdmissionReferenceDataV2,
        first: RawPairedClockSample,
        cutoff: u64,
        nonce: [u8; 32],
        terminal: ClosedHostTerminalArchiveDataV2,
        availability: HostExecutionAvailabilityObservationV2,
        host_journal: &Journal,
        host_socket: &SeqpacketSocket,
        host_transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<
        ControllerExecutionNoApplyClientLoanV2<'turn, 'turn, 'original>,
        ResourceReservationErrorV1,
    > {
        if self.entered {
            self.reentry
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.entered = true;
        self.geometry = Some(Self::fixed_demand_v2().and_then(|demand| {
            let bytes = size_of::<CleanupOriginV2>()
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(8192_usize.checked_mul(4)?))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(crate::JournalError::JournalTooLarge)?;
            demand
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                .map_err(crate::JournalError::ReceivingAccounting)
        }));
        let demand = self
            .geometry
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.funding = Some(receiving.admit_stage_v1(
            bank,
            controller,
            profile,
            Demand::from_demand_v1(demand),
        ));
        if !matches!(self.funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let source = terminal.marker().fields().source;
        self.association = Some((|| {
            if receiving.operation_v1().as_bytes() != &source.fields().create_operation
                || nonce[..16] == [0; 16]
                || first.boottime_nanoseconds() >= cutoff
                || first.host_boot_id() != admission.original.host_boot_id()
                || cutoff > admission.cutoff
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            if availability.fields().bound_source_digest != *source.digest().as_bytes()
                || availability.fields().boot != source.fields().host_boot
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
            Ok((source, cutoff, host_transcript.session_binding()))
        })());
        let (source, cutoff, host_session) = self
            .association
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        self.native = Some(Box::new(Native {
            cleanup: Some(Box::new(CleanupOriginV2 {
                admission,
                first,
                nonce,
                availability,
                acquisition: None,
                acquisition_funding: None,
                acquisition_fields: None,
            })),
            session: ExecutionAvailabilitySessionNativeOriginalV2::new(),
            io: Default::default(),
            nonce: std::array::from_fn(|_| RetainedKernelNonceOriginalV1::new()),
            entropy: std::array::from_fn(|_| None),
            source,
            cutoff,
            host_session,
            active: 1,
            terminal: Some(Ok(terminal)),
            lease: None,
            read_nonce: None,
            signed_current_outcome: None,
            current_outcome_packet: None,
            retirement_issued: false,
            settlement: None,
            settlement_geometry: None,
            settlement_funding: None,
            root_demand: ResourceVector::ZERO,
            root_refusal: None,
            controller_geometry: None,
            controller_funding: None,
            controller: None,
        }));
        let native = self
            .native
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        native
            .session
            .capture_cleanup_once_v2(host_journal, host_socket, host_transcript)?;
        let mut request = [0; 16];
        request.copy_from_slice(&nonce[..16]);
        native.entropy[1] = Some(Ok(request));
        let base = *receiving.complete;
        Ok(ControllerExecutionNoApplyClientLoanV2 {
            native,
            reentry: &mut self.reentry,
            controller,
            bank,
            profile,
            source: Source::Cleanup(receiving),
            base,
        })
    }
}

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    /// Installs only the completed native Root reply on this same fresh loan.
    ///
    /// # Errors
    /// Refuses a foreign, failed or repeated acquisition, changed actual
    /// Source/C, or unpayable retained packet. No DATA-only path unlocks42.
    #[doc(hidden)]
    pub fn install_root_acquisition_once_v2(
        &mut self,
        root: &mut crate::normal_root::RootExecutionNoApplyClientAcquisitionBorrowV2<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.root_owned_acquisition_selection_v2()?;
        root.require_same_cleanup_original_v2(self)
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let bytes = root
            .canonical_acquisition_data_v2()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        let demand = ResourceVector::ZERO.with(
            D::MemoryBytes,
            u64::try_from(bytes.len()).map_err(|_| ResourceReservationErrorV1::Conflict)?,
        );
        let complete = self.complete_transport_base_v2(demand)?;
        let funded = self.require_transport_complete_v2(complete);
        let cleanup = self
            .native
            .cleanup
            .as_mut()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        cleanup.acquisition_funding = Some(funded);
        if !matches!(cleanup.acquisition_funding, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        cleanup.acquisition_fields = Some(aos_sandbox_protocol::host_execution_no_apply::recovery_acquisition::RootNoApplyRecoveryAcquisitionDataV2::decode_canonical(bytes)
            .map(|packet| packet.fields_v2()));
        if !matches!(cleanup.acquisition_fields, Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        cleanup.acquisition = Some(bytes.to_vec());
        self.base = self.base.checked_add(demand)?;
        Ok(())
    }

    pub(crate) fn root_owned_acquisition_selection_v2(&self)
        -> Result<crate::policy_compiler::execution_no_apply_root::RootNoApplyAcquisitionSelectionDataV2, ResourceReservationErrorV1>
    {
        let native = self.native()?;
        let cleanup = native
            .cleanup
            .as_deref()
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if native.active != 1 || cleanup.acquisition.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let terminal = native
            .terminal
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(crate::policy_compiler::execution_no_apply_root::RootNoApplyAcquisitionSelectionDataV2 {
            admission: cleanup.admission, controller_nonce: cleanup.nonce, controller_first: cleanup.first,
            cleanup_cutoff: native.cutoff, host_session: native.host_session,
            historical_availability: cleanup.availability, accepted_source: native.source,
            marker: terminal.marker(), terminal_archive: *terminal.archive_head().as_bytes(),
            signed_terminal: *terminal.signed_terminal_outcome().as_bytes(),
        })
    }
}
