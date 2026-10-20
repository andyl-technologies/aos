//! Holds both actual client Sessions beside the same C18 and retained SDK flights.
//!
//! The sole provisioning driver performs request preparation, native IO, exact
//! signed outcome commit/readback and independently owed posts. Empty originals
//! create no receiver or readiness. The caller retains this SDK original across
//! refusal; the opaque borrower cannot detach either Session or its lower owner.

use super::*;
use crate::recovery::{ProtectedBrokerSessionOwnerV1, RetainedStorageClientOwnerPostV1};
use aos_sandbox::Journal;
use aos_sandbox::controller_execution_operation::{
    ControllerExecutionAvailabilityClientLoanV2,
    ControllerExecutionAvailabilityPositiveRetirementV2, ControllerExecutionPositiveDisposalV1,
    ExecutionPublicAdmissionScopeV2,
};
use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
use aos_sandbox_broker_session_protocol::VerifiedBrokerSessionTranscriptV1;
use aos_sandbox_linux::seqpacket::{
    ConnectionPeerIdentity, RetainedSeqpacketReceiveErrorV1, SeqpacketSocket,
};

/// Retains both whole availability flights and their actual original failures.
#[must_use = "retain both native prefixes through acceptance and final disposition"]
pub struct ExecutionAvailabilitySessionIoOriginalV2 {
    host: ProvisioningFlightV1,
    storage: ProvisioningFlightV1,
    host_bind: ProvisioningFlightV1,
    storage_bind: ProvisioningFlightV1,
    entry: Option<Result<(), ResourceReservationErrorV1>>,
    protected: Option<BrokerSessionSecurityError>,
    admission: Option<Result<(), ResourceReservationErrorV1>>,
    bind_preparation: Option<Result<(), ResourceReservationErrorV1>>,
    bind_completion: Option<Result<(), ResourceReservationErrorV1>>,
    retirement: Option<
        Result<ControllerExecutionAvailabilityPositiveRetirementV2, ResourceReservationErrorV1>,
    >,
    entered: bool,
}

impl ExecutionAvailabilitySessionIoOriginalV2 {
    /// Constructs empty inline destinations without allocation, IO or admission.
    #[must_use]
    pub fn new() -> Self {
        Self {
            host: ProvisioningFlightV1::new(ProvisioningKindV4::ExecutionAvailability),
            storage: ProvisioningFlightV1::new(ProvisioningKindV4::ExecutionAvailability),
            host_bind: ProvisioningFlightV1::new(ProvisioningKindV4::ExecutionAvailability),
            storage_bind: ProvisioningFlightV1::new(ProvisioningKindV4::ExecutionAvailability),
            entry: None,
            protected: None,
            admission: None,
            bind_preparation: None,
            bind_completion: None,
            retirement: None,
            entered: false,
        }
    }

    /// Borrows the retained first native, protected or financial failure.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.entry
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.protected.as_ref().map(|cause| cause as _))
            .or_else(|| self.host.failure())
            .or_else(|| self.storage.failure())
            .or_else(|| {
                self.admission
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.bind_preparation
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.host_bind.failure())
            .or_else(|| self.storage_bind.failure())
            .or_else(|| {
                self.bind_completion
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.retirement
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    /// Identifies when the first stopping marker belongs to the same C18 owner.
    ///
    /// Runtime uses this solely to borrow that owner's richer original cause.
    /// An earlier SDK failure cannot select a later independently owed post.
    #[must_use]
    pub fn original_failure_selected_v2(&self) -> bool {
        if self.entry.as_ref().is_some_and(Result::is_err) {
            return true;
        }
        if self.host.first.is_some() {
            return self.host.selected_original_failure();
        }
        if self.storage.first.is_some() {
            return self.storage.selected_original_failure();
        }
        if self.admission.as_ref().is_some_and(Result::is_err)
            || self.bind_preparation.as_ref().is_some_and(Result::is_err)
        {
            return true;
        }
        if self.host_bind.first.is_some() {
            return self.host_bind.selected_original_failure();
        }
        if self.storage_bind.first.is_some() {
            return self.storage_bind.selected_original_failure();
        }
        self.bind_completion.as_ref().is_some_and(Result::is_err)
            || self.retirement.as_ref().is_some_and(Result::is_err)
    }

    /// Retires all four positive SDK prefixes under the genuine Source/C18 token.
    ///
    /// Every packet, capture, signed outcome and native post stays resident until
    /// this same-operation, same-Journal disposal interval. The caller retires
    /// the upper C18 prefix before completing the still-borrowed native token.
    ///
    /// # Errors
    /// Refuses failed or incomplete flights, a missing actual lower association,
    /// a different operation or a different Controller Journal. Refusal preserves
    /// all original destinations and cannot reset a failed attempt.
    pub fn retire_positive_v2(
        &mut self,
        disposal: &ControllerExecutionPositiveDisposalV1<'_>,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !self.entered
            || !self.host.completed
            || !self.storage.completed
            || !self.host_bind.completed
            || !self.storage_bind.completed
            || !matches!(self.bind_completion, Some(Ok(())))
            || self.failure_v2().is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.retirement
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?
            .require_positive_disposal_v2(disposal)?;

        drop(std::mem::replace(self, Self::new()));
        Ok(())
    }

    /// Borrows the actual completed64/65 association for read-only NoApply.
    ///
    /// This is not an Apply disposal or a reconstructed source/deadline token.
    /// The borrow prevents retirement while the same Host continuation is held.
    ///
    /// # Errors
    /// Refuses any incomplete flight, failed post or missing native association.
    pub(super) fn no_apply_retirement_original_v2(
        &self,
    ) -> Result<&ControllerExecutionAvailabilityPositiveRetirementV2, OutputPreparationClosedV1> {
        if !self.entered || !self.host.completed || !self.storage.completed
            || !self.host_bind.completed || !self.storage_bind.completed
            || !matches!(self.bind_completion, Some(Ok(()))) || self.failure_v2().is_some() {
            return Err(OutputPreparationClosedV1);
        }
        self.retirement.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(OutputPreparationClosedV1)
    }

    pub(crate) fn borrow_pair_v2<'turn>(
        &'turn mut self,
        host: &'turn mut DormantAuthenticatedBrokerSessionV1,
        storage: &'turn mut DormantAuthenticatedBrokerSessionV1,
        scope: &'turn mut ExecutionPublicAdmissionScopeV2,
        controller: &'turn mut Journal,
    ) -> Result<ExecutionAvailabilityClientSessionBorrowV2<'turn>, OutputPreparationClosedV1> {
        if self.entered {
            if self.failure_v2().is_none() {
                self.protected
                    .get_or_insert(BrokerSessionSecurityError::Currentness);
            }
            return Err(OutputPreparationClosedV1);
        }
        self.entered = true;
        let pair = (|| {
            if host.require_execution_availability_client_v2()?
                != BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
                || storage.require_execution_availability_client_v2()?
                    != BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            Ok((
                host.owner.execution_availability_client_journal_v2()?,
                storage.owner.execution_availability_client_journal_v2()?,
            ))
        })();
        let (host_journal, storage_journal) = match pair {
            Ok(pair) => pair,
            Err(cause) => {
                self.protected = Some(cause);
                return Err(OutputPreparationClosedV1);
            }
        };
        let native = match scope.borrow_availability_client_once_v2(
            controller,
            host_journal,
            &host.socket,
            &host.transcript,
            storage_journal,
            &storage.socket,
            &storage.transcript,
        ) {
            Ok(native) => {
                self.entry = Some(Ok(()));
                native
            }
            Err(cause) => {
                self.entry = Some(Err(cause));
                return Err(OutputPreparationClosedV1);
            }
        };
        Ok(ExecutionAvailabilityClientSessionBorrowV2 {
            host,
            storage,
            original: self,
            native,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unadmitted_body_captures_stay_empty_through_refusal_and_diagnostics() {
        for kind in [
            ProvisioningKindV4::Storage,
            ProvisioningKindV4::StartStorage,
            ProvisioningKindV4::Network,
            ProvisioningKindV4::Mount,
            ProvisioningKindV4::Host,
            ProvisioningKindV4::HostCatalog,
            ProvisioningKindV4::MaintenanceCatalog,
            ProvisioningKindV4::MaintenanceStorage,
            ProvisioningKindV4::DeletePreparation,
            ProvisioningKindV4::DeleteApply,
            ProvisioningKindV4::DeleteNetwork,
            ProvisioningKindV4::DeleteMount,
            ProvisioningKindV4::ExecutionAvailability,
            ProvisioningKindV4::ExecutionNoApply,
        ] {
            let mut flight = ProvisioningFlightV1::new(kind);
            assert!(flight.initialize_admitted_body_once_v5().is_err());
            assert!(flight.failure().is_none());

            flight.fixed = Some(Err(ResourceReservationErrorV1::Conflict));
            flight.mark(First::Fixed);
            flight.final_native = Some(Err(ResourceReservationErrorV1::Conflict));

            assert!(flight.initialize_admitted_body_once_v5().is_err());
            assert!(flight.failure().is_some());
            assert!(flight.authenticated(false).is_none());
            assert!(flight.request_originals.is_none());
            assert!(flight.outcome.is_none());
            assert!(flight.predecessor_originals.is_none());
        }
    }

    #[test]
    fn earlier_sdk_failure_keeps_actual_cause_before_later_native_post() {
        let mut original = ExecutionAvailabilitySessionIoOriginalV2::new();
        original.entry = Some(Ok(()));
        original.host.first = Some(First::Shared);
        original.host.shared.inner.protected_failure =
            Some(BrokerSessionSecurityError::Currentness);
        let first = original
            .host
            .shared
            .inner
            .protected_failure
            .as_ref()
            .unwrap() as *const _;

        original.host.final_native = Some(Err(ResourceReservationErrorV1::Conflict));
        original.storage.first = Some(First::Fixed);
        original.storage.fixed_original_selected = true;
        original.storage.fixed = Some(Err(ResourceReservationErrorV1::Conflict));

        assert!(!original.original_failure_selected_v2());
        assert!(std::ptr::eq(
            original
                .failure_v2()
                .unwrap()
                .downcast_ref::<BrokerSessionSecurityError>()
                .unwrap(),
            first
        ));
    }
    #[test]
    fn accepted_bind_failure_keeps_cause_and_all_four_flight_originals() {
        let mut original = ExecutionAvailabilitySessionIoOriginalV2::new();
        original.entry = Some(Ok(()));
        original.host.completed = true;
        original.storage.completed = true;
        original.admission = Some(Ok(()));
        original.bind_preparation = Some(Ok(()));
        original.host_bind.first = Some(First::Shared);
        original.host_bind.shared.inner.protected_failure =
            Some(BrokerSessionSecurityError::Currentness);
        let first = original
            .host_bind
            .shared
            .inner
            .protected_failure
            .as_ref()
            .unwrap() as *const _;

        original.host_bind.final_native = Some(Err(ResourceReservationErrorV1::Conflict));
        original.storage_bind.first = Some(First::Fixed);
        original.storage_bind.fixed_original_selected = true;
        original.storage_bind.fixed = Some(Err(ResourceReservationErrorV1::Conflict));
        original.bind_completion = Some(Err(ResourceReservationErrorV1::Conflict));
        original.retirement = Some(Err(ResourceReservationErrorV1::Conflict));

        assert!(!original.original_failure_selected_v2());
        assert!(std::ptr::eq(
            original
                .failure_v2()
                .unwrap()
                .downcast_ref::<BrokerSessionSecurityError>()
                .unwrap(),
            first
        ));
        assert!(original.host.completed && original.storage.completed);
        assert!(original.host_bind.final_native.as_ref().unwrap().is_err());
        assert!(original.storage_bind.fixed.as_ref().unwrap().is_err());
        assert!(original.bind_completion.as_ref().unwrap().is_err());
    }
}

impl Default for ExecutionAvailabilitySessionIoOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

/// Continuously borrows the actual Host/Storage Sessions and same paid C18.
#[must_use = "keep both Sessions, native owner and SDK originals through admission"]
pub struct ExecutionAvailabilityClientSessionBorrowV2<'turn> {
    host: &'turn mut DormantAuthenticatedBrokerSessionV1,
    storage: &'turn mut DormantAuthenticatedBrokerSessionV1,
    original: &'turn mut ExecutionAvailabilitySessionIoOriginalV2,
    native: ControllerExecutionAvailabilityClientLoanV2<'turn>,
}

#[derive(Clone, Copy)]
pub(super) enum AvailabilityClientPhaseV2 {
    Preaccept,
    AcceptedBind,
}

impl ExecutionAvailabilityClientSessionBorrowV2<'_> {
    /// Executes genuine Host64 through the sole retained provisioning driver.
    ///
    /// # Errors
    /// Preserves repeated-entry, financial, Session, native, transport, signed
    /// response, protected predecessor and independently owed post failures.
    pub fn host_preaccept_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
            &mut self.original.host,
            self.host,
            &mut self.native,
            &AvailabilityClientPhaseV2::Preaccept,
            false,
        )
    }

    /// Executes genuine Storage65 while retaining the completed Host64 original.
    ///
    /// # Errors
    /// Refuses missing Host completion, changed original Sessions, reentry,
    /// financial/native/transport failures and incomplete independent posts.
    pub fn storage_preaccept_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
            &mut self.original.storage,
            self.storage,
            &mut self.native,
            &AvailabilityClientPhaseV2::Preaccept,
            false,
        )
    }

    /// Appends the prepared request while both actual client Sessions stay held.
    ///
    /// The same lower C18 owner performs its native pair checks and sole Core
    /// admission/append engine. Neither successful IO nor comparison DATA can
    /// replace this concrete transition or detach a readiness capability.
    ///
    /// # Errors
    /// Retains incomplete flights, reentry, physical Session substitution and
    /// actual native/financial/admission/post failures in their original owners.
    /// An ambiguous accepted append cannot be retried through this method.
    pub fn admit_prepared_public_request_once_v2(
        &mut self,
        maximum_pending_operations: usize,
    ) -> Result<aos_sandbox::AcceptOutcome, OutputPreparationClosedV1> {
        if self.original.admission.is_some()
            || !self.original.host.completed
            || !self.original.storage.completed
            || self.original.failure_v2().is_some()
        {
            return Err(OutputPreparationClosedV1);
        }
        let pair = (|| {
            Ok((
                self.host.owner.execution_availability_client_journal_v2()?,
                self.storage
                    .owner
                    .execution_availability_client_journal_v2()?,
            ))
        })();
        let (host_journal, storage_journal) = match pair {
            Ok(pair) => pair,
            Err(cause) => {
                self.original.protected = Some(cause);
                return Err(OutputPreparationClosedV1);
            }
        };
        match self.native.admit_prepared_public_request_once_v2(
            maximum_pending_operations,
            host_journal,
            &self.host.socket,
            &self.host.transcript,
            storage_journal,
            &self.storage.socket,
            &self.storage.transcript,
        ) {
            Ok(outcome) => {
                self.original.admission = Some(Ok(()));
                Ok(outcome)
            }
            Err(cause) => {
                self.original.admission = Some(Err(cause));
                Err(OutputPreparationClosedV1)
            }
        }
    }

    /// Prepares the actual protected accepted source while both Sessions remain held.
    ///
    /// # Errors
    /// Retains missing admission, reentry and the original source/financial cause.
    pub fn prepare_accepted_bind_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if self.original.bind_preparation.is_some()
            || !matches!(self.original.admission, Some(Ok(())))
            || self.original.failure_v2().is_some()
        {
            return Err(OutputPreparationClosedV1);
        }
        let result = self.native.prepare_accepted_bind_once_v2();
        let succeeded = result.is_ok();
        self.original.bind_preparation = Some(result);
        if succeeded {
            Ok(())
        } else {
            Err(OutputPreparationClosedV1)
        }
    }

    /// Binds Host64 to the same protected accepted Create through the shared driver.
    ///
    /// # Errors
    /// Retains incomplete preparation, reentry and all native/transport/post failures.
    pub fn host_accepted_bind_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !matches!(self.original.bind_preparation, Some(Ok(())))
            || self.original.failure_v2().is_some()
        {
            return Err(OutputPreparationClosedV1);
        }
        StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
            &mut self.original.host_bind,
            self.host,
            &mut self.native,
            &AvailabilityClientPhaseV2::AcceptedBind,
            false,
        )
    }

    /// Binds Storage65 while retaining the same completed Host binding and pair.
    ///
    /// # Errors
    /// Retains missing Host binding, reentry and every native/transport/post failure.
    pub fn storage_accepted_bind_once_v2(&mut self) -> Result<(), OutputPreparationClosedV1> {
        if !self.original.host_bind.completed || self.original.failure_v2().is_some() {
            return Err(OutputPreparationClosedV1);
        }
        StorageProvisioningSessionIoOriginalV1::run_flight_once_v4(
            &mut self.original.storage_bind,
            self.storage,
            &mut self.native,
            &AvailabilityClientPhaseV2::AcceptedBind,
            false,
        )
    }

    /// Confirms all four actual flights before returning the retained acceptance.
    ///
    /// # Errors
    /// Refuses incomplete transport posts, reentry and any retained native failure.
    pub fn finish_accepted_bind_once_v2(
        &mut self,
    ) -> Result<aos_sandbox::AcceptOutcome, OutputPreparationClosedV1> {
        if self.original.bind_completion.is_some()
            || !self.original.host_bind.completed
            || !self.original.storage_bind.completed
            || self.original.failure_v2().is_some()
        {
            return Err(OutputPreparationClosedV1);
        }
        match self.native.finish_accepted_bind_once_v2() {
            Ok(outcome) => {
                self.original.bind_completion = Some(Ok(()));
                let retirement = self.native.positive_retirement_original_once_v2();
                let succeeded = retirement.is_ok();
                self.original.retirement = Some(retirement);
                if succeeded {
                    Ok(outcome)
                } else {
                    Err(OutputPreparationClosedV1)
                }
            }
            Err(cause) => {
                self.original.bind_completion = Some(Err(cause));
                Err(OutputPreparationClosedV1)
            }
        }
    }

    /// Borrows original failures without detaching the continuous native owner.
    #[must_use]
    pub fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        if self.original.original_failure_selected_v2() {
            self.native
                .failure_v2()
                .or_else(|| self.original.failure_v2())
        } else {
            self.original
                .failure_v2()
                .or_else(|| self.native.failure_v2())
        }
    }
}

impl DormantAuthenticatedBrokerSessionV1 {
    pub(in crate::handshake) fn require_execution_availability_client_v2(
        &self,
    ) -> Result<BrokerMethod, BrokerSessionSecurityError> {
        let method = match self.transcript.protocol() {
            BrokerSessionProtocolV1::Host => {
                BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2
            }
            BrokerSessionProtocolV1::Storage => {
                BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2
            }
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        self.owner.execution_availability_client_journal_v2()?;
        if self.transcript.audience()
            != aos_proto::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // This prepayment selector is passive. The genuine Core C18 stage
        // admits and captures the actual native transport currentness later.
        crate::handshake::require_negotiated_method(&self.transcript, method)?;
        Ok(method)
    }

    pub(super) fn execution_availability_coordinates_v2(
        &self,
        header: &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        self.require_execution_availability_client_v2()?;
        self.execution_client_coordinates_data_v2(header)
    }

    pub(super) fn execution_client_coordinates_data_v2(
        &self,
        header: &aos_sandbox_protocol::authorization_artifact::start_resource_plan::StartResourceRequestHeaderDataV2,
    ) -> Result<crate::DormantBrokerRequestCoordinatesV1, BrokerSessionSecurityError> {
        let (major, minor) = self.transcript.protocol_version();
        if header.protocol_major != u32::from(major)
            || header.protocol_minor != u32::from(minor)
            || header.audience != self.transcript.audience()
            || header.request_id == [0; 16]
            || header.deadline_boottime_nanoseconds == 0
            || header.maximum_response_bytes == 0
            || header.maximum_response_bytes > self.transcript.negotiated_maximum_response_bytes()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(
            crate::DormantBrokerRequestCoordinatesV1::from_session_data_v1(
                header.request_id,
                header.deadline_boottime_nanoseconds,
                header.maximum_response_bytes,
                aos_sandbox_core::ProtocolVersion::new(major, minor),
                self.transcript.audience(),
            ),
        )
    }
}

impl ProvisioningMemberV4 for ControllerExecutionAvailabilityClientLoanV2<'_> {
    type Prepared = AvailabilityClientPhaseV2;
    member::common_turns!();

    fn matches_kind_v2(&self, kind: ProvisioningKindV4, _: &Self::Prepared) -> bool {
        matches!(kind, ProvisioningKindV4::ExecutionAvailability)
    }

    fn flight_owner_inline_bytes_v4() -> Option<usize> {
        size_of::<ExecutionAvailabilitySessionIoOriginalV2>().checked_mul(2)?
            .checked_add(ProvisioningFlightV1::body_slots_receiving_bytes_v5(4)?)
    }

    fn extra_inline_bytes_v4(&self) -> Option<usize> {
        Some(0)
    }

    fn request_packet_bound_v4(&self, _: &Self::Prepared, inventory: bool) -> Option<usize> {
        if inventory {
            None
        } else {
            aos_sandbox_protocol::session::authenticated_request_packet_bound_from_clear_v1(4096)
        }
    }

    fn admit_v4(
        &mut self,
        phase: &Self::Prepared,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        shape: aos_sandbox::StorageProvisioningSessionIoShapeDataV1,
        inventory: bool,
    ) -> Result<(), ResourceReservationErrorV1> {
        if inventory {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        match (phase, transcript.protocol()) {
            (AvailabilityClientPhaseV2::Preaccept, BrokerSessionProtocolV1::Host) => {
                self.admit_host_preaccept_io_once_v2(journal, socket, transcript, shape)
            }
            (AvailabilityClientPhaseV2::Preaccept, BrokerSessionProtocolV1::Storage) => {
                self.admit_storage_preaccept_io_once_v2(journal, socket, transcript, shape)
            }
            (AvailabilityClientPhaseV2::AcceptedBind, BrokerSessionProtocolV1::Host) => {
                self.admit_host_accepted_bind_io_once_v2(journal, socket, transcript, shape)
            }
            (AvailabilityClientPhaseV2::AcceptedBind, BrokerSessionProtocolV1::Storage) => {
                self.admit_storage_accepted_bind_io_once_v2(journal, socket, transcript, shape)
            }
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }

    fn prepare_request_v4(
        &mut self,
        flight: &mut ProvisioningFlightV1,
        session: &mut DormantAuthenticatedBrokerSessionV1,
        phase: &Self::Prepared,
        inventory: bool,
        maximum_request: usize,
    ) -> bool {
        let inputs = (|| {
            if inventory {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let method = session.require_execution_availability_client_v2()?;
            let journal = self.session_journal_v1(&session.owner)?;
            let header = self
                .availability_request_header_data_v2(journal, &session.transcript)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let coordinates = session.execution_availability_coordinates_v2(&header)?;
            let proposal = self
                .proposal_data_v2()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let (phase, accepted_source) = match phase {
                AvailabilityClientPhaseV2::Preaccept => (
                    aos_proto::aos::sandbox::local::v1::ExecutionAvailabilityPhaseV2::EXECUTION_AVAILABILITY_PHASE_PREACCEPT,
                    Vec::new(),
                ),
                AvailabilityClientPhaseV2::AcceptedBind => (
                    aos_proto::aos::sandbox::local::v1::ExecutionAvailabilityPhaseV2::EXECUTION_AVAILABILITY_PHASE_ACCEPTED_BIND,
                    self.accepted_bind_source_data_v2()
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?
                        .encode_canonical().to_vec(),
                ),
            };
            let body = aos_proto::aos::sandbox::local::v1::PrepareExecutionAvailabilityRequestV2 {
                header: Some(coordinates.request_header()).into(),
                phase: phase.into(),
                canonical_proposal: proposal.encode_canonical().to_vec(),
                canonical_accepted_source: accepted_source,
                ..Default::default()
            }
            .encode_to_vec();
            Ok((
                coordinates,
                BrokerRequestEnvelope {
                    method: method.into(),
                    body,
                    ..Default::default()
                },
            ))
        })();
        match inputs {
            Ok((coordinates, envelope)) => {
                flight.shared.inner.coordinates = Some(Ok(coordinates));
                flight.unsigned = Some(envelope);
                match flight.unsigned.as_ref() {
                    Some(envelope) => flight.shared.inner.prepare_captured_engine_v1(
                        session,
                        envelope.clone(),
                        Some(maximum_request),
                        match flight.request_originals.as_mut() {
                            Some(capture) => Some(capture.as_mut()),
                            None => return false,
                        },
                    ),
                    None => false,
                }
            }
            Err(cause) => {
                flight.shared.inner.coordinates = Some(Err(cause));
                flight.mark(First::Coordinates);
                false
            }
        }
    }

    fn bind_request_v4(
        &mut self,
        _: &Self::Prepared,
        request: &AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.bind_availability_request_once_v2(request)
    }

    fn observe_owner_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        peer: &ConnectionPeerIdentity,
    ) -> RetainedStorageClientOwnerPostV1 {
        owner.observe_execution_availability_client_owner_v2(transcript, peer)
    }

    fn compare_predecessor_v4(
        owner: &mut ProtectedBrokerSessionOwnerV1,
        currentness: &crate::recovery::ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
        originals: &mut crate::recovery::OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        owner.compare_execution_availability_predecessor_v2(currentness, peer, originals)
    }

    fn finish_terminal_v4(
        &mut self,
        _: &Self::Prepared,
        journal: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.finish_availability_terminal_once_v2(journal, outcome)
    }

    fn observe_terminal_post_v4(
        &mut self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.observe_availability_terminal_post_once_v2(journal, socket, transcript)
    }
}
