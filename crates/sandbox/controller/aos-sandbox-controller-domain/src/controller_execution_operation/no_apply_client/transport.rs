//! Selects the finite closed39/42/43 programme on the same actual Source loan.
//!
//! Seal and ACK require this same owner's actual native Controller prepare
//! and terminal CAS with their independently completed Root/native posts.

use aos_sandbox_api::aos::sandbox::local::v1::{
    BrokerMethod, BrokerRequestEnvelope, RequestHeader,
    TerminalHostExecutionArgumentNoApplyRequestV1,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    current_lease_transport::encode_host_no_apply_current_lease_query_v2,
    held_settlement_transport::{
        HostNoApplyHeldCommandV2, encode_host_held_no_apply_settlement_request_v2,
    },
};
use buffa::Message as _;

use super::*;

impl ControllerExecutionNoApplyClientLoanV2<'_, '_, '_> {
    pub(crate) fn no_apply_io_original_v2(
        &mut self,
    ) -> &mut crate::controller_resource_reservation::ExecutionNoApplyIoOriginalV2 {
        &mut self.native.io
    }

    /// Returns this owner's finite actual Host method as comparison DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn no_apply_method_data_v2(&self) -> BrokerMethod {
        match self.native.active {
            0 => BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
            1 | 3 | 4 => BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
            2 => BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
            _ => BrokerMethod::BROKER_METHOD_UNSPECIFIED,
        }
    }

    /// Returns the selected finite native phase, without advancing it.
    #[doc(hidden)]
    #[must_use]
    pub fn no_apply_phase_data_v2(&self) -> usize {
        self.native.active
    }

    pub(crate) fn no_apply_cutoff_data_v2(&self) -> Result<u64, ResourceReservationErrorV1> {
        let native = self.native()?;
        let mut cutoff = native.cutoff;
        if let Some(cleanup) = native.cleanup.as_deref() {
            if let Some(Ok(acquisition)) = &cleanup.acquisition_fields {
                cutoff = cutoff.min(acquisition.cutoff);
            }
        }
        if let Some(Ok(lease)) = &native.lease {
            cutoff = cutoff.min(lease.fields().native_cutoff);
        }
        Ok(cutoff)
    }

    pub(crate) fn require_transport_journal_v2(
        &self,
        journal: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.native.session.require_journal_v2(journal)
    }

    pub(crate) fn require_transport_session_v2(
        &self,
        journal: &Journal,
        socket: &SeqpacketSocket,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), ControllerExecutionAvailabilitySessionCurrentnessErrorV2> {
        ExecutionAvailabilitySessionNativeOriginalV2::observe_same_v2(
            Some(&self.native.session),
            journal,
            socket,
            transcript,
        )
    }

    pub(crate) fn no_apply_request_id_data_v2(
        &self,
    ) -> Result<[u8; 16], ResourceReservationErrorV1> {
        let native = self.native()?;
        native
            .entropy
            .get(native.active)
            .and_then(Option::as_ref)
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    /// Borrows the bounded command extent of the actual selected finite phase.
    ///
    /// No extent is supplied for Seal/ACK until a genuine native C continuation
    /// selects them. A caller cannot use this value as receiving permission.
    #[must_use]
    pub fn no_apply_request_bound_v2(&self) -> Option<usize> {
        let native = self.native().ok()?;
        if native.active == 1 && native.cleanup.as_deref()
            .is_some_and(|cleanup| cleanup.acquisition.is_none()) {
            return None;
        }
        if native.active <= 1 || native.active == 2 && native.read_nonce.is_some()
            || matches!(native.active, 3 | 4) && self.settlement_command_v2().is_ok() {
            Some(8192)
        } else {
            None
        }
    }

    /// Encodes the actual closed source/terminal or fresh Root-nonce command.
    ///
    /// # Errors
    /// Refuses another phase/nonce/deadline or a missing real preceding outcome.
    #[doc(hidden)]
    pub fn no_apply_request_envelope_v2(
        &self,
        header: &RequestHeader,
    ) -> Result<BrokerRequestEnvelope, ResourceReservationErrorV1> {
        let native = self.native()?;
        if header.request_id.as_slice() != self.no_apply_request_id_data_v2()?
            || header.deadline_boottime_nanoseconds == 0
            || header.deadline_boottime_nanoseconds > self.no_apply_cutoff_data_v2()?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let body = match native.active {
            0 => TerminalHostExecutionArgumentNoApplyRequestV1 {
                header: Some(header.clone()).into(),
                canonical_attempt: native.source.encode_canonical().to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
            1 => {
                if let Some(cleanup) = native.cleanup.as_deref() {
                    let packet = cleanup.acquisition.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
                    let body = encode_host_held_no_apply_settlement_request_v2(header,
                        &HostNoApplyHeldCommandV2::RecoveryPreliminary {
                            canonical_root_acquisition: packet.clone(),
                        }).map_err(|_| ResourceReservationErrorV1::Conflict)?;
                    return Ok(BrokerRequestEnvelope {
                        method: self.no_apply_method_data_v2().into(), body, ..Default::default()
                    });
                }
                let terminal = native
                    .terminal
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                encode_host_held_no_apply_settlement_request_v2(
                    header,
                    &HostNoApplyHeldCommandV2::Preliminary {
                        marker: terminal.marker(),
                        archive_head: terminal.archive_head(),
                        signed_terminal_outcome: terminal.signed_terminal_outcome(),
                    },
                )
                .map_err(|_| ResourceReservationErrorV1::Conflict)?
            }
            2 => encode_host_no_apply_current_lease_query_v2(
                header,
                *native
                    .lease
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
                native
                    .read_nonce
                    .ok_or(ResourceReservationErrorV1::Conflict)?,
            )
            .map_err(|_| ResourceReservationErrorV1::Conflict)?,
            3 | 4 => encode_host_held_no_apply_settlement_request_v2(
                header, &self.settlement_command_v2()?,
            ).map_err(|_| ResourceReservationErrorV1::Conflict)?,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        Ok(BrokerRequestEnvelope {
            method: self.no_apply_method_data_v2().into(),
            body,
            ..Default::default()
        })
    }

    /// Prepares the fresh43 query while retaining C, Source and the actual Session.
    ///
    /// This nonce is comparison DATA from the genuine Root opening. The Root
    /// verifier must match its own retained paid nonce before issuing a floor.
    /// A wrong nonce can produce neither a floor nor Controller settlement.
    ///
    /// # Errors
    /// Refuses missing preliminary completion, duplicate/zero Root nonce,
    /// failed current originals or failed separately paid request entropy.
    pub fn prepare_root_nonce_query_once_v2(
        &mut self,
        root_nonce: [u8; 32],
    ) -> Result<(), ResourceReservationErrorV1> {
        self.native()?;
        if self.native.active != 2
            || self.native.read_nonce.is_some()
            || root_nonce == [0; 32]
            || self.native.entropy[2].is_some()
        {
            self.reentry
                .get_or_insert(ResourceReservationErrorV1::Conflict);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_transport_current_v2()?;
        // Root's independently captured final C model must match this same
        // continuously held whole-journal cut before its fresh43 opening.
        self.controller_cut_data_v2()?;
        self.native.read_nonce = Some(root_nonce);
        self.native.entropy[2] = Some(self.native.nonce[2].observe_once());
        self.no_apply_request_id_data_v2().map(|_| ())
    }

    pub(crate) fn require_no_apply_request_data_v2(
        &self,
        request: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodRequestV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let native = self.native()?;
        if request.method() != self.no_apply_method_data_v2()
            || request.request_id() != self.no_apply_request_id_data_v2()?
            || request.session_binding() != native.host_session
            || request.deadline_boottime_nanoseconds() > self.no_apply_cutoff_data_v2()?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let valid = match native.active {
            0 => request
                .host_before_argument_no_apply_data_v2()
                .is_some_and(|original| original.source() == native.source),
            1 => {
                if let Some(cleanup) = native.cleanup.as_deref() {
                    return if request.host_held_no_apply_settlement_data_v2()
                        .is_some_and(|original| matches!(original.command_v2(),
                            HostNoApplyHeldCommandV2::RecoveryPreliminary { canonical_root_acquisition }
                            if cleanup.acquisition.as_ref() == Some(canonical_root_acquisition))) {
                        Ok(())
                    } else { Err(ResourceReservationErrorV1::Conflict) };
                }
                let terminal = native
                    .terminal
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                request
                    .host_held_no_apply_settlement_data_v2()
                    .is_some_and(|original| {
                        matches!(original.command_v2(), HostNoApplyHeldCommandV2::Preliminary {
                        marker, archive_head, signed_terminal_outcome,
                    } if *marker == terminal.marker() && *archive_head == terminal.archive_head()
                        && *signed_terminal_outcome == terminal.signed_terminal_outcome())
                    })
            }
            2 => {
                let comparison = native
                    .lease
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                request
                    .host_no_apply_current_lease_query_data_v2()
                    .is_some_and(|original| {
                        original.comparison_v2() == *comparison
                            && Some(original.read_nonce_v2()) == native.read_nonce
                    })
            }
            3 | 4 => request.host_held_no_apply_settlement_data_v2()
                .is_some_and(|original| self.settlement_command_v2()
                    .is_ok_and(|command| original.command_v2() == &command)),
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(ResourceReservationErrorV1::Conflict)
        }
    }

    pub(crate) fn retain_no_apply_terminal_once_v2(
        &mut self,
        outcome: &aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        let active = self.native.active;
        match active {
            0 => {
                if self.native.terminal.is_some() {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                self.native.terminal = Some(aos_sandbox_protocol::host_execution_no_apply::
                    closed_host_terminal_archive_data_v2(outcome));
                let terminal = self
                    .native
                    .terminal
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if terminal.marker().fields().source != self.native.source {
                    self.reentry
                        .get_or_insert(ResourceReservationErrorV1::Conflict);
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                self.native.active = 1;
                self.native.entropy[1] = Some(self.native.nonce[1].observe_once());
                self.no_apply_request_id_data_v2().map(|_| ())
            }
            1..=4 => {
                use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodErrorV1 as Error;
                let previous = self.native.lease.as_ref().and_then(|value| value.as_ref().ok()).copied();
                let decoded = if active != 2 {
                    outcome.recorded_host_held_no_apply_lease_v2()
                } else {
                    outcome.recorded_host_no_apply_current_lease_v2()
                };
                self.native.lease =
                    Some(decoded.and_then(|value| value.ok_or(Error::InconsistentCrossLink)));
                let lease = self
                    .native
                    .lease
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let terminal = self
                    .native
                    .terminal
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                let fields = lease.fields();
                if active >= 2 {
                    let expected = previous.ok_or(ResourceReservationErrorV1::Conflict)?.fields();
                    let mut immutable = fields;
                    immutable.current_session = expected.current_session;
                    immutable.signed_current_request = expected.signed_current_request;
                    immutable.current_request = expected.current_request;
                    immutable.observed_clock = expected.observed_clock;
                    if immutable != expected || fields.observed_clock < expected.observed_clock {
                        self.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
                        return Err(ResourceReservationErrorV1::Conflict);
                    }
                }
                if fields.accepted_source != self.native.source
                    || fields.marker != aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(terminal.marker())
                    || fields.terminal_archive_head != *terminal.archive_head().as_bytes()
                    || fields.signed_terminal_outcome != *terminal.signed_terminal_outcome().as_bytes()
                    || fields.current_session != self.native.host_session
                    || fields.scope != if self.native.cleanup.is_some() {
                        aos_sandbox_protocol::host_execution_no_apply::current_lease::HostNoApplyLeaseScopeV2::RecoveryCleanup
                    } else {
                        aos_sandbox_protocol::host_execution_no_apply::current_lease::HostNoApplyLeaseScopeV2::Active
                    } {
                    self.reentry.get_or_insert(ResourceReservationErrorV1::Conflict);
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                self.native.active += 1;
                if active == 2 {
                    self.native.current_outcome_packet = Some(
                        aos_sandbox_broker_session_protocol::projection::decode_canonical_response_v1(
                            outcome.canonical_packet(),
                        ),
                    );
                    let packet = self.native.current_outcome_packet.as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .ok_or(ResourceReservationErrorV1::Conflict)?;
                    self.native.signed_current_outcome = Some(
                        aos_sandbox_broker_session_protocol::complete_signed_outcome_digest_v1(
                            packet.signed_artifact(),
                        ),
                    );
                }
                Ok(())
            }
            _ => Err(ResourceReservationErrorV1::Conflict),
        }
    }
}
