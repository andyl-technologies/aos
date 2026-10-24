//! Completes one resource on its original Root connection and actual Start turn.
//!
//! The wire fields remain comparison DATA. Only the genuine Entry, the four
//! ordered resource turns, exact acknowledgement, hostile EOF, independent
//! native posts and physical disposal can issue the completed original below.

use super::*;
use crate::journal::StartResourceNativePositionsOriginalV2;
use aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::{
    RESOURCE_CLOSED_BYTES_V2, ResourceCompletionBindingDataV2, ResourceCompletionClosedDataV2,
    ResourceCompletionProofDataV2, ResourceCompletionPurposeDataV3,
};

/// Borrows exact resource exchanges without granting completion or native custody.
#[doc(hidden)]
#[derive(Clone, Copy)]
pub struct RootStartResourceExchangeDataV2<'held> {
    /// The actual resource Session's final names, NEXT and held byte boundary.
    pub session_native: &'held [u8; 64],
    /// The complete signed resource request from that same Session.
    pub resource_request: &'held [u8],
    /// Its complete authenticated terminal response.
    pub resource_outcome: &'held [u8],
    /// The distinct fresh signed Inventory request from the same Session.
    pub inventory_request: &'held [u8],
    /// Its complete authenticated terminal response.
    pub inventory_outcome: &'held [u8],
}

impl<'held> RootStartResourceExchangeDataV2<'held> {
    fn packets(self) -> [&'held [u8]; 4] {
        [
            self.resource_request,
            self.resource_outcome,
            self.inventory_request,
            self.inventory_outcome,
        ]
    }

    fn packet_bytes(self) -> Result<usize, ResourceReservationErrorV1> {
        use aos_sandbox_broker_session_protocol::projection::{
            AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES as REQUEST,
            AUTHENTICATED_RESPONSE_MAXIMUM_BYTES as RESPONSE,
        };
        self.packets()
            .into_iter()
            .zip([REQUEST, RESPONSE, REQUEST, RESPONSE])
            .try_fold(0_usize, |total, (packet, maximum)| {
                if packet.is_empty() || packet.len() > maximum {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                total
                    .checked_add(packet.len())
                    .ok_or(ResourceReservationErrorV1::Conflict)
            })
    }
}

#[derive(Clone, Copy)]
enum TerminalFirstV2 {
    Funding,
    Positions,
    Copy,
    Proof,
    Admission,
    Send,
    RequestEnd,
    Receive,
    Reply,
    ReplyEof,
    Disposition,
    Reentry,
}

pub(super) struct ResourceTerminalOriginalV2 {
    identity: Arc<()>,
    native_turn: u64,
    positions: StartResourceNativePositionsOriginalV2,
    positions_result: Option<Result<(), ResourceReservationErrorV1>>,
    packets: [Vec<u8>; 4],
    growth: [Option<Result<(), std::collections::TryReserveError>>; 4],
    session_native: [u8; 64],
    binding: Option<Result<ResourceCompletionBindingDataV2, HistoryErrorV1>>,
    digest: Option<Result<[u8; 32], HistoryErrorV1>>,
    sender: FixedDeadlineStreamIoV1<4096>,
    sent: Option<Result<(), HistoryErrorV1>>,
    scratch: [u8; 4096],
    data_failure: Option<ApplyRootDataErrorV1>,
    request_end: Option<Result<(), rustix::io::Errno>>,
    received: RetainedSubjectStreamReadV1,
    preparation: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    extension: Option<Result<(), aos_sandbox_linux::unix_stream::SubjectStreamReadErrorV1>>,
    chunk: Option<Box<RootStrictChunkOriginalV1>>,
    reply: Option<Result<ResourceCompletionClosedDataV2, HistoryErrorV1>>,
    eof: FixedDeadlineStreamIoV1<1>,
    eof_byte: [u8; 1],
    ended: Option<Result<(), HistoryErrorV1>>,
    disposition: Option<Result<(), ResourceReservationErrorV1>>,
    complete: ResourceVector,
    first: Option<TerminalFirstV2>,
}

impl ResourceTerminalOriginalV2 {
    fn new(identity: Arc<()>, native_turn: u64, complete: ResourceVector) -> Self {
        Self {
            identity,
            native_turn,
            positions: StartResourceNativePositionsOriginalV2::new(),
            positions_result: None,
            packets: Default::default(),
            growth: Default::default(),
            session_native: [0; 64],
            binding: None,
            digest: None,
            sender: Default::default(),
            sent: None,
            scratch: [0; 4096],
            data_failure: None,
            request_end: None,
            received: Default::default(),
            preparation: None,
            extension: None,
            chunk: None,
            reply: None,
            eof: Default::default(),
            eof_byte: [0; 1],
            ended: None,
            disposition: None,
            complete,
            first: None,
        }
    }

    fn proof(&self) -> Result<ResourceCompletionProofDataV2<'_>, HistoryErrorV1> {
        let binding = *positive(&self.binding)?;
        let (controller_native, source_native) = self
            .positions
            .data_v2()
            .map_err(|_| HistoryErrorV1::Correlation)?;
        Ok(ResourceCompletionProofDataV2 {
            binding,
            controller_native,
            source_native,
            session_native: &self.session_native,
            resource_request: &self.packets[0],
            resource_outcome: &self.packets[1],
            inventory_request: &self.packets[2],
            inventory_outcome: &self.packets[3],
        })
    }

    pub(super) fn failure_with_admission<'held>(&'held self,
        admission: &'held Option<Result<(), ResourceReservationErrorV1>>,
    ) -> Option<&'held (dyn Error + 'static)> {
        let cause = match self.first? {
            TerminalFirstV2::Positions => self
                .positions
                .failure()
                .or_else(|| cause(&self.positions_result)),
            TerminalFirstV2::Copy => self.growth.iter().find_map(cause),
            TerminalFirstV2::Proof => cause(&self.binding).or_else(|| cause(&self.digest)),
            TerminalFirstV2::Send => self.sender.failure().or_else(|| cause(&self.sent)),
            TerminalFirstV2::RequestEnd => cause(&self.request_end),
            TerminalFirstV2::Receive => self
                .chunk
                .as_deref()
                .and_then(|chunk| chunk.failure(&self.received))
                .or_else(|| self.received.failure())
                .or_else(|| cause(&self.preparation)),
            TerminalFirstV2::Reply => cause(&self.reply),
            TerminalFirstV2::ReplyEof => self.eof.failure().or_else(|| cause(&self.ended)),
            TerminalFirstV2::Disposition => cause(&self.disposition),
            TerminalFirstV2::Admission => cause(admission),
            TerminalFirstV2::Funding | TerminalFirstV2::Reentry => {
                None
            }
        };
        cause
            .or_else(|| self.data_failure.as_ref().map(|cause| cause as _))
            .or(Some(&CLOSED))
    }
}

/// Retains completed comparison DATA after the actual Root native child retires.
///
/// Its private constructor belongs to the exact same-socket final proof path.
/// Decoding a proof or acknowledgement cannot create this original.
#[doc(hidden)]
#[must_use = "retain this original through later resource and Host completion"]
pub struct RootStartResourceCompletedOriginalV2 {
    identity: Arc<()>,
    profile: Arc<ProductionControllerNormalRootProfileV1>,
    parent: OperationId,
    native_turn: u64,
    binding: ResourceCompletionBindingDataV2,
    controller_native: [u8; 64],
    source_native: [u8; 64],
    session_native: [u8; 64],
    packets: [Vec<u8>; 4],
    opening_query: [u8; QUERY_BYTES_V1],
    opening_reply: RetainedSubjectStreamReadV1,
    closed: ResourceCompletionClosedDataV2,
}

impl RootStartResourceCompletedOriginalV2 {
    /// Joins the actual completed resource to the same Entry before SDK disposal.
    ///
    /// # Errors
    /// Refuses another resource, Entry identity, profile, current C or final turn.
    /// Joins the actual completed network resource to its same Entry and C.
    ///
    /// # Errors
    /// Refuses another purpose, Entry identity, profile, current C or final turn.
    pub fn require_network_disposition_v2(&self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_disposition_v2(HostResourcePurposeDataV1::NetworkPrepare, entry, controller)
    }

    /// Joins the actual completed storage resource to its same Entry and C.
    ///
    /// # Errors
    /// Refuses another purpose, Entry identity, profile, current C or final turn.
    pub fn require_storage_disposition_v2(&self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_disposition_v2(HostResourcePurposeDataV1::StorageGuestRoot, entry, controller)
    }

    /// Joins the actual completed mount resource to its same Entry and C.
    ///
    /// # Errors
    /// Refuses another purpose, Entry identity, profile, current C or final turn.
    pub fn require_mount_disposition_v2(&self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_disposition_v2(HostResourcePurposeDataV1::MountNamespace, entry, controller)
    }

    /// Completes only the actual Host purpose through the common original engine.
    ///
    /// # Errors
    /// Refuses another purpose or any incomplete native, IO or disposal obligation.
    #[doc(hidden)]
    pub fn require_host_disposition_v2(&self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_disposition_v2(HostResourcePurposeDataV1::HostLaunch, entry, controller)
    }

    fn require_resource_disposition_v2(
        &self,
        expected: HostResourcePurposeDataV1,
        entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        if self.binding.purpose != expected.into() {
            return Err(CLOSED);
        }
        entry
            .require_completed_resource_context_v2(
                self.parent,
                self.native_turn,
                &self.identity,
                &self.profile,
                controller,
            )
            .map_err(|_| CLOSED)
    }

    pub(crate) fn completed_model_turn_data_v2(&self) -> u64 { self.native_turn }

    /// Joins a historical disposed resource to the genuine current Host loan.
    ///
    /// This checks the retained exact old turn marker, not old-turn currentness.
    /// The new loan independently checks actual current C, Source and Start.
    ///
    /// # Errors
    /// Refuses another Entry, role, parent, profile, disposed turn or current loan.
    #[doc(hidden)]
    pub fn completed_model_association_v2(
        &self, loan: &OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
    ) -> Result<[u8; 32], RootHostLaunchClientClosedV1> {
        let aos_sandbox_protocol::domain_ledger::provisioning_root::host_launch::completion::
            ResourceCompletionPurposeDataV3::Start(purpose) = self.binding.purpose else {
            return Err(CLOSED);
        };
        loan.require_disposed_resource_models_v2(self.parent, self.native_turn,
            &self.identity, &self.profile, purpose, controller).map_err(|_| CLOSED)?;
        Ok(self.closed.proof_digest)
    }

    /// Measures the actual remaining comparison DATA without refunding spent IO.
    ///
    /// # Errors
    /// Refuses checked representation arithmetic overflow.
    pub fn completed_receiving_demand_v2(
        &self,
    ) -> Result<ResourceVector, RootHostLaunchClientClosedV1> {
        let memory = self
            .packets
            .iter()
            .try_fold(size_of::<Self>(), |bytes, packet| {
                bytes.checked_add(packet.capacity())
            })
            .ok_or(CLOSED)?
            .checked_add(
                self.opening_reply.retained_backing_bytes_v2(),
            )
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(CLOSED)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory))
    }

    /// Borrows the exact completed proof fields for the later Host comparison.
    #[must_use]
    pub fn comparison_data_v2(&self) -> ResourceCompletionProofDataV2<'_> {
        ResourceCompletionProofDataV2 {
            binding: self.binding,
            controller_native: &self.controller_native,
            source_native: &self.source_native,
            session_native: &self.session_native,
            resource_request: &self.packets[0],
            resource_outcome: &self.packets[1],
            inventory_request: &self.packets[2],
            inventory_outcome: &self.packets[3],
        }
    }
}

impl RootHostLaunchClientOriginalV1 {
    /// Sends exact final comparison DATA on this resource's existing Root socket.
    ///
    /// # Errors
    /// Retains failed funding, both reached native samples, allocation, transport,
    /// hostile framing, temporal comparison and independently attributed IO.
    /// The actual Entry still owes C-after and Root-after after any refusal.
    /// Sends the actual network exchange under its selected final Root turn.
    ///
    /// # Errors
    /// Retains the common funding/native/IO refusal and refuses another purpose.
    pub fn send_network_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
        exchange: RootStartResourceExchangeDataV2<'_>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::NetworkPrepare)?;
        self.send_resource_final_proof_once_v2(loan, controller, exchange)
    }

    /// Sends the actual storage exchange under its selected final Root turn.
    ///
    /// # Errors
    /// Retains the common funding/native/IO refusal and refuses another purpose.
    pub fn send_storage_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
        exchange: RootStartResourceExchangeDataV2<'_>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::StorageGuestRoot)?;
        self.send_resource_final_proof_once_v2(loan, controller, exchange)
    }

    /// Sends the actual mount exchange under its selected final Root turn.
    ///
    /// # Errors
    /// Retains the common funding/native/IO refusal and refuses another purpose.
    pub fn send_mount_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
        exchange: RootStartResourceExchangeDataV2<'_>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::MountNamespace)?;
        self.send_resource_final_proof_once_v2(loan, controller, exchange)
    }

    /// Completes only the actual Host purpose through the common original engine.
    ///
    /// # Errors
    /// Refuses another purpose or any incomplete native, IO or disposal obligation.
    #[doc(hidden)]
    pub fn send_host_final_proof_once_v2(&mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>, controller: &Journal,
        exchange: RootStartResourceExchangeDataV2<'_>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)?;
        self.send_resource_final_proof_once_v2(loan, controller, exchange)
    }

    pub(crate) fn send_resource_final_proof_once_v2(
        &mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
        exchange: RootStartResourceExchangeDataV2<'_>,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.selected_resource_purpose_v2()?;
        if self.terminal_entry.is_some() {
            if let Some(terminal) = self.terminal.as_mut() {
                terminal.first.get_or_insert(TerminalFirstV2::Reentry);
            }
            return Err(CLOSED);
        }
        self.require_final_proof_turn_v2(loan, controller)?;
        self.terminal_entry = Some((|| {
            let bytes = exchange
                .packet_bytes()?
                .checked_mul(2)
                .and_then(|bytes| {
                    bytes.checked_add(size_of::<ResourceTerminalOriginalV2>().checked_mul(2)?)
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        size_of::<RootStartResourceCompletedOriginalV2>().checked_mul(2)?,
                    )
                })
                .and_then(|bytes| bytes.checked_add(2 * RESOURCE_CLOSED_BYTES_V2))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(ResourceReservationErrorV1::Conflict)?;
            let complete = self
                .final_proof_funding_v2()?
                .checked_add(loan.resource_completion_native_demand_v2(controller)?)?
                .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))?;
            self.terminal_complete_demand = Some(complete);
            let returned = loan.require_complete_v1(controller, complete);
            if returned.is_err() && loan.failure_v1().is_some() {
                self.funding_original = true;
            }
            returned
        })());
        if !matches!(self.terminal_entry, Some(Ok(()))) {
            return Err(CLOSED);
        }
        let complete = self.terminal_complete_demand.ok_or(CLOSED)?;
        self.terminal = Some(Box::new(ResourceTerminalOriginalV2::new(
            loan.retained_resource_identity_v2(),
            loan.native_turn_v1(),
            complete,
        )));
        let returned = self.send_final_inner_v2(loan, controller, exchange);
        if let Err(first) = returned {
            if let Some(terminal) = self.terminal.as_mut() {
                terminal.first.get_or_insert(first);
            }
            return Err(CLOSED);
        }
        Ok(())
    }

    fn send_final_inner_v2(
        &mut self,
        loan: &mut OriginalStartHostRootLoanV1<'_, '_>,
        controller: &Journal,
        exchange: RootStartResourceExchangeDataV2<'_>,
    ) -> Result<(), TerminalFirstV2> {
        use std::os::fd::AsFd as _;
        let purpose = self.selected_resource_purpose_v2().map_err(|_| TerminalFirstV2::Proof)?;
        let terminal = self.terminal.as_mut().ok_or(TerminalFirstV2::Funding)?;
        terminal.positions_result = Some(
            loan.observe_resource_completion_positions_v2(controller, &mut terminal.positions),
        );
        if !matches!(terminal.positions_result, Some(Ok(()))) {
            return Err(TerminalFirstV2::Positions);
        }
        for (index, packet) in exchange.packets().into_iter().enumerate() {
            terminal.growth[index] = Some(terminal.packets[index].try_reserve_exact(packet.len()));
            if !matches!(terminal.growth[index], Some(Ok(()))) {
                return Err(TerminalFirstV2::Copy);
            }
            terminal.packets[index].extend_from_slice(packet);
        }
        terminal.session_native = *exchange.session_native;
        let state = self.state.as_mut().ok_or(TerminalFirstV2::Proof)?;
        terminal.binding = Some((|| {
            let StartOpeningAdmissionV2::Resource(admission) = *positive(&state.reply)? else {
                return Err(HistoryErrorV1::Correlation);
            };
            let reply = HostResourceReplyDataV1::decode_v1(state.received.bytes())?;
            Ok(ResourceCompletionBindingDataV2 {
                purpose: purpose.into(),
                root_nonce: admission.root_nonce,
                controller_nonce: admission.controller_nonce,
                query_digest: admission.query_digest,
                reply_digest: reply.digest_v1()?,
            })
        })());
        terminal.digest = Some(
            terminal
                .proof()
                .and_then(ResourceCompletionProofDataV2::digest_v2),
        );
        let proof = terminal.proof().map_err(|_| TerminalFirstV2::Proof)?;
        let bytes = proof
            .encoded_bytes_v2()
            .map_err(|_| TerminalFirstV2::Proof)?;
        positive(&terminal.digest).map_err(|_| TerminalFirstV2::Proof)?;
        let mut funding = RootClientFundingV1 {
            complete: terminal.complete,
            observations: &mut self.observations,
            wire: &mut self.wire,
            output: &mut self.output,
            received_bound: &mut self.received_bound,
            admission: &mut self.admission,
            funding_original: &mut self.funding_original,
        };
        let mut borrowed = RootClientLoanV1::Start(loan);
        funding
            .charge(&mut borrowed, controller, 0, bytes, bytes)
            .map_err(|_| TerminalFirstV2::Admission)?;
        // Borrow the fixed proof fields separately from the retained IO leaves.
        let (controller_native, source_native) = terminal
            .positions
            .data_v2()
            .map_err(|_| TerminalFirstV2::Positions)?;
        let proof = ResourceCompletionProofDataV2 {
            binding: *positive(&terminal.binding).map_err(|_| TerminalFirstV2::Proof)?,
            controller_native,
            source_native,
            session_native: &terminal.session_native,
            resource_request: &terminal.packets[0],
            resource_outcome: &terminal.packets[1],
            inventory_request: &terminal.packets[2],
            inventory_outcome: &terminal.packets[3],
        };
        resource_stream::send_subject_v1(
            RootSubjectDataV1::ResourceCompletion(proof),
            &mut state.connection,
            &mut terminal.sender,
            &mut terminal.sent,
            &mut terminal.scratch,
            &mut terminal.data_failure,
            state.cutoff,
        )
        .map_err(|_| TerminalFirstV2::Send)?;
        terminal.request_end = Some(rustix::net::shutdown(
            state
                .connection
                .stream()
                .map_err(|_| TerminalFirstV2::RequestEnd)?
                .as_fd(),
            rustix::net::Shutdown::Write,
        ));
        if !matches!(terminal.request_end, Some(Ok(()))) {
            return Err(TerminalFirstV2::RequestEnd);
        }

        let peer = self
            .turns
            .final_proof_peer_v2()
            .ok_or(TerminalFirstV2::Receive)?;
        let state = self.state.as_mut().ok_or(TerminalFirstV2::Receive)?;
        let terminal = self.terminal.as_mut().ok_or(TerminalFirstV2::Receive)?;
        RootReplyReceiveV1 {
            connection: &mut state.connection,
            received: &mut terminal.received,
            preparation: &mut terminal.preparation,
            extension: &mut terminal.extension,
            chunk: &mut terminal.chunk,
            data_failure: &mut terminal.data_failure,
            peer_before: peer,
            profile: &state.profile,
            cutoff: state.cutoff,
        }
        .receive_fixed_reply_v2(
            RESOURCE_CLOSED_BYTES_V2,
            &mut borrowed,
            controller,
            &mut funding,
        )
        .map_err(|_| TerminalFirstV2::Receive)?;
        terminal.reply = Some((|| {
            let closed = ResourceCompletionClosedDataV2::decode_v2(terminal.received.bytes())?;
            let StartOpeningAdmissionV2::Resource(admission) = *positive(&state.reply)? else {
                return Err(HistoryErrorV1::Correlation);
            };
            // The ACK repeats Root's original advertised bound. Both sides
            // independently tighten their actual IO and post deadlines; those
            // local wall projections need not produce identical nanoseconds.
            if closed.binding != *positive(&terminal.binding)?
                || closed.proof_digest != *positive(&terminal.digest)?
                || closed.cutoff_ns != admission.cutoff_ns
            {
                return Err(HistoryErrorV1::Correlation);
            }
            Ok(closed)
        })());
        positive(&terminal.reply).map_err(|_| TerminalFirstV2::Reply)?;
        terminal.ended = Some(
            terminal.eof.run_once(
                state
                    .connection
                    .stream_mut()
                    .map_err(|_| TerminalFirstV2::ReplyEof)?,
                &mut terminal.eof_byte,
                state.cutoff,
                DeadlineStreamDirectionV1::Eof,
            ),
        );
        if !matches!(terminal.ended, Some(Ok(()))) || !terminal.eof.completed_exact() {
            return Err(TerminalFirstV2::ReplyEof);
        }
        Ok(())
    }

    /// Issues completion after the same final turn's independent C and Root posts.
    ///
    /// # Errors
    /// Refuses incomplete/foreign posts, final time comparison or physical
    /// disposition. Every failed native owner remains retained on this client.
    /// Issues only the actual completed network original after all final posts.
    ///
    /// # Errors
    /// Refuses another purpose, an incomplete final turn or physical disposal.
    pub fn finish_network_resource_once_v2(&mut self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::NetworkPrepare)?;
        self.finish_resource_once_v2(entry, controller)
    }

    /// Issues only the actual completed storage original after all final posts.
    ///
    /// # Errors
    /// Refuses another purpose, an incomplete final turn or physical disposal.
    pub fn finish_storage_resource_once_v2(&mut self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::StorageGuestRoot)?;
        self.finish_resource_once_v2(entry, controller)
    }

    /// Issues only the actual completed mount original after all final posts.
    ///
    /// # Errors
    /// Refuses another purpose, an incomplete final turn or physical disposal.
    pub fn finish_mount_resource_once_v2(&mut self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::MountNamespace)?;
        self.finish_resource_once_v2(entry, controller)
    }

    /// Completes only the actual Host purpose through the common original engine.
    ///
    /// # Errors
    /// Refuses another purpose or any incomplete native, IO or disposal obligation.
    #[doc(hidden)]
    pub fn finish_host_resource_once_v2(&mut self,
        entry: &crate::AcceptedStartEntryOriginalV1, controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        self.require_resource_purpose_v2(HostResourcePurposeDataV1::HostLaunch)?;
        self.finish_resource_once_v2(entry, controller)
    }

    pub(crate) fn finish_resource_once_v2(
        &mut self,
        entry: &crate::AcceptedStartEntryOriginalV1,
        controller: &Journal,
    ) -> Result<(), RootHostLaunchClientClosedV1> {
        let purpose = self.selected_resource_purpose_v2()?;
        if self.completed_resource.is_some() {
            return Err(CLOSED);
        }
        let state = self.state.as_ref().ok_or(CLOSED)?;
        let terminal = self.terminal.as_ref().ok_or(CLOSED)?;
        if terminal.first.is_some()
            || positive(&terminal.binding).map_err(|_| CLOSED)?.purpose
                != ResourceCompletionPurposeDataV3::Start(purpose)
            || self.failure().is_some()
            || !matches!(self.terminal_entry, Some(Ok(())))
            || !matches!(terminal.request_end, Some(Ok(())))
            || !matches!(terminal.ended, Some(Ok(())))
            || !terminal.eof.completed_exact()
            || terminal.chunk.is_some()
        {
            return Err(CLOSED);
        }
        entry
            .require_completed_resource_context_v2(
                state.parent,
                terminal.native_turn,
                &terminal.identity,
                &state.profile,
                controller,
            )
            .map_err(|_| CLOSED)?;
        self.require_final_proof_completed_v2(positive(&terminal.reply).map_err(|_| CLOSED)?)?;

        let terminal = self.terminal.as_mut().ok_or(CLOSED)?;
        terminal.disposition = Some(
            terminal
                .positions
                .retire_positive_once_v2()
                .map_err(ResourceReservationErrorV1::Journal),
        );
        if !matches!(terminal.disposition, Some(Ok(()))) {
            terminal.first = Some(TerminalFirstV2::Disposition);
            return Err(CLOSED);
        }
        let mut state = self.state.take().ok_or(CLOSED)?;
        let terminal = self.terminal.take().ok_or(CLOSED)?;
        let (controller_native, source_native) =
            terminal.positions.data_v2().map_err(|_| CLOSED)?;
        let completed = RootStartResourceCompletedOriginalV2 {
            identity: terminal.identity,
            profile: Arc::clone(&state.profile),
            parent: state.parent,
            native_turn: terminal.native_turn,
            binding: *positive(&terminal.binding).map_err(|_| CLOSED)?,
            controller_native: *controller_native,
            source_native: *source_native,
            session_native: terminal.session_native,
            packets: terminal.packets,
            opening_query: state.query_bytes,
            opening_reply: std::mem::take(&mut state.received),
            closed: *positive(&terminal.reply).map_err(|_| CLOSED)?,
        };
        // No completion is visible until the real connection, anchors, clocks,
        // samplers and attributed IO destinations have physically retired.
        drop(state);
        // All selected purpose intervals are positively complete. Retire their
        // actual clock/Result backing and the last unused negative spare before
        // publishing the smaller completed DATA representation.
        self.turns = Default::default();
        self.next_refusal = None;
        self.completed_resource = Some(Box::new(completed));
        self.terminal_complete = true;
        Ok(())
    }

    /// Borrows only the privately issued completed resource original.
    ///
    /// # Errors
    /// Refuses unfinished native disposal or any retained whole-flight failure.
    pub fn borrow_completed_resource_v2(
        &self,
    ) -> Result<&RootStartResourceCompletedOriginalV2, RootHostLaunchClientClosedV1> {
        if !self.terminal_complete || self.failure().is_some() || self.state.is_some() {
            return Err(CLOSED);
        }
        self.completed_resource.as_deref().ok_or(CLOSED)
    }
}


impl RootStartResourceCompletedOriginalV2 {
    /// Borrows the digest already checked by this actual completed Root exchange.
    ///
    /// The private issuer retained the exact signed packets and native positions
    /// through ACK, hostile EOF, all posts and physical Root disposition. This
    /// copied commitment is historical DATA and cannot construct completion.
    #[must_use]
    pub fn closed_proof_digest_data_v2(&self) -> [u8; 32] {
        self.closed.proof_digest
    }
}
