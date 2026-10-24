//! Positively retires the same held Client Session before its narrow HELLO.
//!
//! The Runtime idle owner transfers its actual Security Session here before
//! any fallible operation. Failure keeps that Session, terminal originals and
//! every reached independent post resident. Only complete positive retirement
//! drops the old transport and moves the SAME Journal/floor/endpoint onward.

use super::*;
use aos_sandbox_controller_domain::{
    CreateStorageClientSessionClosedV1, CreateStorageClientSessionShapeDataV1,
    OriginalCreateStorageClientSessionV1,
};
use crate::recovery::{RetainedStorageClientOwnerPostV1, RetainedStorageClientTerminalOriginalV1};

#[derive(Debug, thiserror::Error)]
#[error("the actual Storage Client transition remains closed with custody retained")]
pub(crate) struct ClientTransitionClosedV1;

// Only the same positive transition constructs this nonauthorizing lineage.
// No transport cookie or completed transcript can be supplied by a caller.
pub(crate) struct CompletedStorageClientRolloverV1 {
    originating_transport: std::num::NonZeroU64,
    previous_transport: std::num::NonZeroU64,
    transport: std::num::NonZeroU64,
    transcript: [u8; 32],
}

impl CompletedStorageClientRolloverV1 {
    pub(crate) fn matches_initial_v1(&self, cookie: std::num::NonZeroU64) -> bool {
        self.originating_transport == cookie
    }

    pub(crate) fn matches_session_v1(&self, session: &DormantAuthenticatedBrokerSessionV1) -> bool {
        self.matches_values_v1(session.socket.peer().socket_cookie(),
            session.transcript.session_binding())
    }

    fn matches_values_v1(&self, cookie: std::num::NonZeroU64, transcript: [u8; 32]) -> bool {
        self.transport == cookie && self.transcript == transcript
    }
}

/// Owns the actual Session across the consuming retirement frontier.
pub(crate) struct RetainedStorageClientTransitionV1 {
    session: Option<DormantAuthenticatedBrokerSessionV1>,
    previous_transport: std::num::NonZeroU64,
    originating_transport: std::num::NonZeroU64,
    completed_rollover: Option<CompletedStorageClientRolloverV1>,
    retired_owner: Option<ProtectedBrokerSessionOwnerV1>,
    terminal: Option<RetainedStorageClientTerminalOriginalV1>,
    fixed: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    capture: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    arm: Option<Result<(), BrokerSessionSecurityError>>,
    floor_arm: Option<Result<(), BrokerSessionSecurityError>>,
    idle: Option<Result<(), ClientTransitionClosedV1>>,
    old_witness_before: Option<Result<(), ClientTransitionClosedV1>>,
    old_witness_after_terminal: Option<Result<(), ClientTransitionClosedV1>>,
    old_witness_after_end: Option<Result<(), ClientTransitionClosedV1>>,
    terminal_result: Option<Result<(), BrokerSessionSecurityError>>,
    terminal_post: Option<RetainedStorageClientOwnerPostV1>,
    native_post: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    disposal: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    disposal_post: Option<RetainedStorageClientOwnerPostV1>,
    cutoff: Option<Result<u64, CreateStorageClientSessionClosedV1>>,
    node: Option<Result<aos_sandbox_model::NodeId, CreateStorageClientSessionClosedV1>>,
    hello_admission: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    deadline: Option<OriginalBrokerColdDeadlineV1>,
    deadline_result: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    connected: Option<Result<SeqpacketSocket, aos_sandbox_linux::seqpacket::RetainedSeqpacketAdmissionErrorV1>>,
    connected_peer: Option<Result<ProcessEvidence, HandshakeError>>,
    socket_join: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    hello: Option<Result<BrokerClientHello, aos_sandbox_broker_session_protocol::BrokerSessionNegotiationError>>,
    handshake: Option<DormantControllerClientHandshakeV1>,
    handshake_error: Option<DormantBrokerSessionHandshakeErrorV1>,
    cold_error: Option<crate::DormantBrokerSessionHandshakeErrorV1>,
    failed_entry_native_post: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    failed_entry_security_post: Option<RetainedStorageClientOwnerPostV1>,
    failed_hello_native_post: Option<Result<(), CreateStorageClientSessionClosedV1>>,
    failed_hello_security_post: Option<RetainedStorageClientOwnerPostV1>,
    cold: Option<RetainedStorageColdOpenV1>,
    completed: Option<DormantAuthenticatedBrokerSessionV1>,
    closed: Option<ClientTransitionClosedV1>,
}

impl RetainedStorageClientTransitionV1 {
    pub(crate) fn new(session: DormantAuthenticatedBrokerSessionV1) -> Self {
        Self {
            previous_transport: session.socket.peer().socket_cookie(),
            originating_transport: session.socket.peer().socket_cookie(),
            completed_rollover: None,
            session: Some(session), retired_owner: None, terminal: None,
            fixed: None, capture: None, arm: None, floor_arm: None, idle: None,
            old_witness_before: None, old_witness_after_terminal: None,
            old_witness_after_end: None, terminal_result: None, terminal_post: None, native_post: None, disposal: None,
            disposal_post: None, cutoff: None, node: None, hello_admission: None,
            deadline: None, deadline_result: None, connected: None, connected_peer: None,
            socket_join: None, hello: None, handshake: None, handshake_error: None,
            cold_error: None, failed_entry_native_post: None, failed_entry_security_post: None,
            failed_hello_native_post: None, failed_hello_security_post: None,
            cold: None, completed: None, closed: None,
        }
    }

    pub(crate) fn new_from_completed_predecessor_v1(
        session: DormantAuthenticatedBrokerSessionV1,
        predecessor: &CompletedStorageClientRolloverV1,
    ) -> Self {
        // Only the closed consumer calls this after it rejoined this exact
        // predecessor and Session. Propagate the original root identity;
        // neither the original capture nor either transport is replaced.
        let matches = predecessor.matches_session_v1(&session);
        let mut original = Self::new(session);
        if matches {
            original.originating_transport = predecessor.originating_transport;
        } else {
            // A defensive mismatch retains the whole Session and refuses
            // before the shared kernel can enter any native work.
            original.closed = Some(ClientTransitionClosedV1);
        }
        original
    }

    fn close(&mut self) -> Result<(), ClientTransitionClosedV1> {
        self.closed.get_or_insert(ClientTransitionClosedV1);
        Err(ClientTransitionClosedV1)
    }

    // The upper Runtime size describes its actual co-resident idle owner.
    // Every other layout comes from these concrete Security types. Amounts
    // are DATA only; the genuine Native borrower derives/adopts the vector.
    pub(super) fn actual_shape(&self, runtime_idle_owner: usize)
        -> Option<CreateStorageClientSessionShapeDataV1>
    {
        let (failure_bytes, failure_cells) = storage_preparation_handshake_failure_obligations_v1()?;
        let (terminal_bytes, terminal_cells) = RetainedStorageClientTerminalOriginalV1::receiving_partial_footprint_v1()?;
        let failure_bytes = failure_bytes.checked_add(terminal_bytes)?;
        // Every outer transition destination is a retained metadata/control
        // cell independently of its inline bytes and nested helper census.
        let failure_cells = failure_cells.checked_add(terminal_cells)?.checked_add(35)?;
        let (peer_bytes, peer_cells) = RetainedStorageClientOwnerPostV1::receiving_peer_footprint_v1()?;
        // Terminal's two typed peer owners are priced above. Four independent
        // OwnerPost destinations share that same complete retained helper.
        let failure_bytes = failure_bytes.checked_add(peer_bytes.checked_mul(4)?)?;
        let failure_cells = failure_cells.checked_add(peer_cells.checked_mul(4)?)?;
        Some(CreateStorageClientSessionShapeDataV1 {
            runtime_idle_owner,
            old_security_session: std::mem::size_of::<DormantAuthenticatedBrokerSessionV1>(),
            retirement_original: std::mem::size_of::<Self>(),
            hello_original: std::mem::size_of::<DormantControllerClientHandshakeV1>()
                .checked_add(std::mem::size_of::<RetainedStorageColdOpenV1>())?,
            narrow_security_session: std::mem::size_of::<DormantAuthenticatedBrokerSessionV1>(),
            send_original: std::mem::size_of::<aos_sandbox_linux::seqpacket::StorageSeqpacketSendAttemptV1>(),
            receive_original: std::mem::size_of::<aos_sandbox_linux::seqpacket::ReceivedRecord>()
                .checked_add(std::mem::size_of::<aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>())?,
            retained_handshake_failure_bytes: failure_bytes,
            retained_handshake_failure_cells: failure_cells,
            retained_checkpoint_hello_bytes: self.session.as_ref()?.checkpoint.encoded_hello_bytes_v1()?,
            process_evidence: super::storage_process_evidence_footprint_v1()?,
            endpoint_revalidation: crate::endpoint::endpoint_revalidation_footprint_v1()?,
            floor_revalidation: crate::recovery::floor_revalidation_footprint_v1()?,
        })
    }

    pub(crate) fn retire_once(
        &mut self,
        original: &mut OriginalCreateStorageClientSessionV1<'_, '_, '_>,
        runtime_idle_owner: usize,
    ) -> Result<(), ClientTransitionClosedV1> {
        if self.fixed.is_some() || self.retired_owner.is_some() || self.closed.is_some() {
            return self.close();
        }
        let Some(shape) = self.actual_shape(runtime_idle_owner) else { return self.close(); };
        self.fixed = Some(original.admit_fixed_once(shape));
        if !matches!(self.fixed, Some(Ok(()))) { return self.close(); }

        let session = match self.session.as_mut() {
            Some(session) => session,
            None => return self.close(),
        };
        self.idle = Some(if session.terminal_witness_failure
            || session.terminal_witness_debt.is_some()
            || session.client_witnesses.as_ref().is_err()
            || session.client_witnesses.as_ref().ok().and_then(|value| value.as_ref())
                .is_some_and(|witnesses| witnesses.first_failure.is_some())
        {
            Err(ClientTransitionClosedV1)
        } else { Ok(()) });
        if !matches!(self.idle, Some(Ok(()))) { return self.close(); }
        let journal = match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => journal,
            Err(_) => return self.close(),
        };
        self.capture = Some(original.capture_held_history_once(journal, &session.socket));
        if !matches!(self.capture, Some(Ok(()))) { return self.close(); }
        self.arm = Some(session.owner.retained_storage_client_endpoint_mut_v1()
            .arm_original_storage_revalidation_once(original));
        if !matches!(self.arm, Some(Ok(()))) { return self.close(); }
        self.floor_arm = Some(session.owner.arm_original_storage_floor_revalidation_once(original));
        if !matches!(self.floor_arm, Some(Ok(()))) { return self.close(); }

        // The actual signed HELLO record subjects, distinct from the listener
        // peer, must remain current through this positive disposal. The same
        // J paid the shared retained process observations before this entry.
        self.old_witness_before = Some(observe_old_client_witnesses(session));
        if matches!(self.old_witness_before, Some(Ok(()))) {
            self.terminal = Some(RetainedStorageClientTerminalOriginalV1::default());
            let terminal = match self.terminal.as_mut() {
                Some(terminal) => terminal,
                None => std::process::abort(),
            };
            self.terminal_result = Some(terminal.observe_once(
                &mut session.owner, &session.transcript, &session.checkpoint, session.socket.peer(),
            ));
        }
        // Both independent observers run even after canonical terminal refusal.
        self.terminal_post = Some(session.owner.observe_retained_storage_client_owner_v1(
            &session.transcript, session.socket.peer(),
        ));
        let journal = match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => journal,
            Err(_) => return self.close(),
        };
        self.native_post = Some(original.observe_retirement_post_once(journal, &session.socket));
        self.old_witness_after_terminal = Some(observe_old_client_witnesses(session));
        if !matches!(self.old_witness_before, Some(Ok(())))
            || !matches!(self.old_witness_after_terminal, Some(Ok(())))
            || !matches!(self.terminal_result, Some(Ok(())))
            || self.terminal_post.as_ref().is_some_and(|post| post.failure().is_some())
            || !matches!(self.native_post, Some(Ok(())))
        {
            return self.close();
        }

        let journal = match session.owner.retained_storage_client_journal_v1() {
            Ok(journal) => journal,
            Err(_) => return self.close(),
        };
        let disposal = match original.prepare_transport_disposal_once(journal, &mut session.socket) {
            Ok(disposal) => {
                self.disposal = Some(Ok(()));
                disposal
            }
            Err(error) => {
                self.disposal = Some(Err(error));
                return self.close();
            }
        };
        self.disposal_post = Some(session.owner.observe_retained_storage_client_owner_v1(
            &session.transcript, session.socket.peer(),
        ));
        self.old_witness_after_end = Some(observe_old_client_witnesses(session));
        if self.disposal_post.as_ref().is_some_and(|post| post.failure().is_some())
            || !matches!(self.old_witness_after_end, Some(Ok(())))
        {
            // Dropping an incomplete Native phase retains/poisons the SAME
            // original. The Session, socket and all Security posts remain here.
            drop(disposal);
            return self.close();
        }

        // All fallible native, terminal, End, floor, endpoint and peer posts are
        // complete. These final moves perform no IO and manufacture no owner.
        let session = match self.session.take() { Some(session) => session, None => std::process::abort() };
        let DormantAuthenticatedBrokerSessionV1 {
            mut owner, socket, transcript, checkpoint, client_witnesses,
            terminal_witness_failure: _, terminal_witness_debt: _,
            execution_cold_native, recovery_session_native, stop_cleanup_source_native,
        } = session;
        // A fresh Source/C18 Host graph can never enter Storage rollover.
        if execution_cold_native.is_some() || recovery_session_native.is_some() || stop_cleanup_source_native.is_some() { std::process::abort(); }
        let terminal = match self.terminal.take() { Some(terminal) => terminal, None => std::process::abort() };
        owner.park_retired_storage_client_transcript_v1(terminal, checkpoint, &transcript);
        drop(socket);
        drop(client_witnesses);
        self.retired_owner = Some(owner);
        disposal.complete_after_transport_disposal();
        Ok(())
    }

    pub(crate) fn begin_hello_once(
        &mut self,
        original: &mut OriginalCreateStorageClientSessionV1<'_, '_, '_>,
    ) -> Result<(), ClientTransitionClosedV1> {
        if self.closed.is_some() || self.retired_owner.is_none() || self.hello_admission.is_some() {
            return self.close();
        }
        self.cutoff = Some(original.create_storage_original_cutoff_data_v1());
        self.node = Some(original.create_storage_node_data_v1());
        let cutoff = match self.cutoff.as_ref() { Some(Ok(cutoff)) => *cutoff, _ => return self.close() };
        if !matches!(self.node, Some(Ok(_))) { return self.close(); }
        self.deadline = Some(OriginalBrokerColdDeadlineV1::storage_accept(cutoff));
        let deadline = match self.deadline { Some(deadline) => deadline, None => std::process::abort() };
        self.deadline_result = Some(deadline.check());
        if !matches!(self.deadline_result, Some(Ok(()))) { return self.close(); }
        self.hello_admission = Some(original.admit_narrow_hello_once());
        if !matches!(self.hello_admission, Some(Ok(()))) { return self.close(); }
        self.connected = Some(SeqpacketSocket::connect_retaining(std::path::Path::new(
            crate::recovery::ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient
                .production_socket_path(),
        )));
        if !matches!(self.connected, Some(Ok(_))) {
            let owner = match self.retired_owner.as_mut() { Some(owner) => owner, None => std::process::abort() };
            let journal = match owner.retained_storage_client_journal_v1() {
                Ok(journal) => journal,
                Err(_) => return self.close(),
            };
            self.failed_entry_native_post = Some(original.observe_failed_hello_entry_post_once(journal));
            self.failed_entry_security_post = Some(owner.observe_retained_storage_client_failed_entry_v1());
            return self.close();
        }
        let socket = match self.connected.as_ref() {
            Some(Ok(socket)) => socket,
            _ => return self.close(),
        };
        self.connected_peer = Some(ProcessEvidence::capture_peer_retaining(socket.peer()));
        let owner = match self.retired_owner.as_ref() { Some(owner) => owner, None => std::process::abort() };
        let journal = match owner.retained_storage_client_journal_v1() {
            Ok(journal) => journal,
            Err(_) => return self.close(),
        };
        self.socket_join = Some(original.capture_narrow_socket_once(journal, socket));
        if !matches!(self.connected_peer, Some(Ok(_))) || !matches!(self.socket_join, Some(Ok(()))) {
            return self.close();
        }
        self.hello = Some(original.storage_client_hello_v1());
        if !matches!(self.hello, Some(Ok(_))) { return self.close(); }
        let owner = match self.retired_owner.take() { Some(owner) => owner, None => std::process::abort() };
        let socket = match self.connected.take() { Some(Ok(socket)) => socket, _ => std::process::abort() };
        let hello = match self.hello.take() { Some(Ok(hello)) => hello, _ => std::process::abort() };
        let peer = match self.connected_peer.as_ref() { Some(Ok(peer)) => *peer, _ => std::process::abort() };
        self.handshake = Some(DormantControllerClientHandshakeV1::begin_retained_storage(owner, socket, hello, peer));
        Ok(())
    }

    pub(crate) fn advance_hello_once(
        &mut self,
        original: &mut OriginalCreateStorageClientSessionV1<'_, '_, '_>,
    ) -> Result<bool, ClientTransitionClosedV1> {
        if self.closed.is_some() || self.handshake_error.is_some() || self.completed.is_some() {
            return self.close().map(|()| false);
        }
        let deadline = match self.deadline { Some(deadline) => deadline, None => return self.close().map(|()| false) };
        self.deadline_result = Some(deadline.check());
        if !matches!(self.deadline_result, Some(Ok(()))) { return self.close().map(|()| false); }
        let handshake = match self.handshake.take() {
            Some(handshake) => handshake,
            None => return self.close().map(|()| false),
        };
        match handshake.advance_retaining_storage() {
            Ok(ColdClientHandshakeProgressV1::Pending(handshake)) => {
                self.handshake = Some(handshake);
                Ok(false)
            }
            Ok(ColdClientHandshakeProgressV1::Verified(verified)) => {
                self.cold = Some(RetainedStorageColdOpenV1::retain_output(verified, deadline));
                let node = match self.node.as_ref() { Some(Ok(node)) => node.into_bytes(), _ => std::process::abort() };
                let cold = match self.cold.as_mut() { Some(cold) => cold, None => std::process::abort() };
                match cold.finish_retained_storage_client_v1(original, node) {
                    Ok(session) => {
                        self.completed = Some(session);
                        // Same native final association and all Security/D posts
                        // completed. Dispose actual positive raw controls now.
                        drop(self.cold.take());
                        Ok(true)
                    }
                    Err(error) => {
                        self.cold_error = Some(error);
                        self.close().map(|()| false)
                    }
                }
            }
            Ok(ColdClientHandshakeProgressV1::Complete(session)) => {
                // The selected completion mode cannot produce a legacy opened
                // Session. Keep any defensive value resident and refuse.
                self.completed = Some(session);
                self.close().map(|()| false)
            }
            Err(error) => {
                self.handshake_error = Some(error);
                self.close().map(|()| false)
            }
        }
    }

    pub(crate) fn pending_readiness(&self)
        -> Result<(BorrowedFd<'_>, bool, u64), ClientTransitionClosedV1>
    {
        if self.closed.is_some() { return Err(ClientTransitionClosedV1); }
        let handshake = self.handshake.as_ref().ok_or(ClientTransitionClosedV1)?;
        let descriptor = handshake.as_fd().map_err(|_| ClientTransitionClosedV1)?;
        let deadline = self.deadline.ok_or(ClientTransitionClosedV1)?;
        Ok((descriptor, handshake.wants_write(), deadline.value()))
    }

    pub(crate) fn observe_failed_hello_posts_once(
        &mut self,
        original: &mut OriginalCreateStorageClientSessionV1<'_, '_, '_>,
    ) {
        if self.failed_hello_native_post.is_some() { return; }
        let parts = if let Some(cold) = self.cold.as_mut() {
            cold.retained_client_parts_mut_v1().map(|(owner, socket, transcript)| (owner, socket, Some(transcript)))
        } else if let Some(handshake) = self.handshake.as_mut() {
            handshake.retained_client_parts_mut_v1().map(|(owner, socket)| (owner, socket, None))
        } else if let Some(DormantBrokerSessionHandshakeErrorV1::StoragePreparation(failure)) = self.handshake_error.as_mut() {
            failure._owner.retained_client_parts_mut_v1().map(|(owner, socket)| (owner, socket, None))
        } else if let Some(session) = self.completed.as_mut() {
            Some((&mut session.owner, &session.socket, Some(&session.transcript)))
        } else if let (Some(owner), Some(Ok(socket))) = (self.retired_owner.as_mut(), self.connected.as_ref()) {
            Some((owner, socket, None))
        } else { None };
        if let Some((owner, socket, transcript)) = parts {
            if let Ok(journal) = owner.retained_storage_client_journal_v1() {
                self.failed_hello_native_post = Some(original.observe_failed_narrow_hello_post_once(journal, socket));
            }
            // Actual endpoint/floor/peer posts are independent of sticky
            // Native debt and do not invoke a positive-only funding getter.
            self.failed_hello_security_post = Some(match transcript {
                Some(transcript) => owner.observe_retained_storage_client_owner_v1(transcript, socket.peer()),
                None => owner.observe_retained_storage_client_failed_entry_v1(),
            });
        }
    }

    pub(crate) fn take_completed_once(&mut self)
        -> Result<DormantAuthenticatedBrokerSessionV1, ClientTransitionClosedV1>
    {
        if self.failure().is_some() || self.handshake.is_some() || self.cold.is_some() {
            self.closed.get_or_insert(ClientTransitionClosedV1);
            return Err(ClientTransitionClosedV1);
        }
        match self.completed.take() {
            Some(session) => {
                self.completed_rollover = Some(CompletedStorageClientRolloverV1 {
                    originating_transport: self.originating_transport,
                    previous_transport: self.previous_transport,
                    transport: session.socket.peer().socket_cookie(),
                    transcript: session.transcript.session_binding(),
                });
                Ok(session)
            },
            None => {
                self.closed.get_or_insert(ClientTransitionClosedV1);
                Err(ClientTransitionClosedV1)
            }
        }
    }

    pub(crate) fn completed_rollover_v1(&self) -> Option<&CompletedStorageClientRolloverV1> {
        if self.failure().is_some() || self.completed.is_some() { return None; }
        self.completed_rollover.as_ref()
    }

    // This is a borrowed chronological view over actual resident owners. A
    // later Native Closed marker or endpoint post never replaces the earlier
    // Security/body failure which caused that closure.
    pub(crate) fn failure_with_native_cause<'cause>(
        &'cause self,
        native_failure: Option<&'cause (dyn std::error::Error + 'static)>,
    ) -> Option<&'cause (dyn std::error::Error + 'static)> {
        let native = |status: &'cause Option<Result<(), CreateStorageClientSessionClosedV1>>| {
            error(status).map(|marker| native_failure.unwrap_or(marker))
        };
        let witness = |status: &'cause Option<Result<(), ClientTransitionClosedV1>>| {
            error(status).map(|marker| {
                self.session.as_ref().and_then(|session| session.client_witnesses.as_ref().ok())
                    .and_then(Option::as_ref).and_then(|witnesses| witnesses.first_failure.as_ref())
                    .map(|failure| failure.cause()).unwrap_or(marker)
            })
        };
        let owner = self.session.as_ref().map(|session| &session.owner)
            .or(self.retired_owner.as_ref())
            .or_else(|| self.cold.as_ref().and_then(|cold| cold.owner.as_ref()
                .or(cold.verified.retained_owner.as_ref())))
            .or_else(|| self.completed.as_ref().map(|session| &session.owner));
        let resolve = |cause: &'cause (dyn std::error::Error + 'static)| {
            let protected = cause.downcast_ref::<BrokerSessionSecurityError>()
                .or_else(|| match cause.downcast_ref::<crate::DormantBrokerSessionHandshakeErrorV1>() {
                    Some(crate::DormantBrokerSessionHandshakeErrorV1::Protected(error)) => Some(error),
                    _ => None,
                });
            match (owner, protected) {
                (Some(owner), Some(error)) => owner.retained_storage_client_failure_for_v1(error),
                _ => cause,
            }
        };
        native(&self.fixed).or_else(|| error(&self.idle))
            .or_else(|| native(&self.capture))
            .or_else(|| error(&self.arm).map(|marker| native_failure.unwrap_or(marker)))
            .or_else(|| error(&self.floor_arm).map(|marker| native_failure.unwrap_or(marker)))
            .or_else(|| witness(&self.old_witness_before))
            .or_else(|| self.terminal.as_ref().and_then(|terminal| terminal.failure()).map(resolve))
            .or_else(|| error(&self.terminal_result).map(resolve))
            .or_else(|| self.terminal_post.as_ref().and_then(|post| post.failure()).map(resolve))
            .or_else(|| native(&self.native_post))
            .or_else(|| witness(&self.old_witness_after_terminal))
            .or_else(|| native(&self.disposal))
            .or_else(|| self.disposal_post.as_ref().and_then(|post| post.failure()).map(resolve))
            .or_else(|| witness(&self.old_witness_after_end))
            .or_else(|| error(&self.cutoff)).or_else(|| error(&self.node))
            .or_else(|| error(&self.deadline_result)).or_else(|| native(&self.hello_admission))
            .or_else(|| error(&self.connected)).or_else(|| error(&self.connected_peer))
            .or_else(|| native(&self.socket_join)).or_else(|| error(&self.hello))
            .or_else(|| self.handshake_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.cold.as_ref().and_then(|cold| {
                if matches!(cold.output_failure_site, Some(OutputColdFailureSiteV1::ClientNative)) {
                    native_failure
                } else { cold.output_failure().map(resolve) }
            }))
            .or_else(|| self.cold_error.as_ref().map(|cause| resolve(cause as _)))
            .or_else(|| native(&self.failed_entry_native_post))
            .or_else(|| self.failed_entry_security_post.as_ref().and_then(|post| post.failure()).map(resolve))
            .or_else(|| native(&self.failed_hello_native_post))
            .or_else(|| self.failed_hello_security_post.as_ref().and_then(|post| post.failure()).map(resolve))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        error(&self.fixed).or_else(|| error(&self.idle)).or_else(|| error(&self.capture))
            .or_else(|| error(&self.arm)).or_else(|| error(&self.floor_arm))
            .or_else(|| error(&self.old_witness_before))
            .or_else(|| self.terminal.as_ref().and_then(|terminal| terminal.failure()))
            .or_else(|| error(&self.terminal_result))
            .or_else(|| self.terminal_post.as_ref().and_then(|post| post.failure()))
            .or_else(|| error(&self.native_post))
            .or_else(|| error(&self.old_witness_after_terminal)).or_else(|| error(&self.disposal))
            .or_else(|| self.disposal_post.as_ref().and_then(|post| post.failure()))
            .or_else(|| error(&self.old_witness_after_end))
            .or_else(|| error(&self.cutoff)).or_else(|| error(&self.node))
            .or_else(|| error(&self.deadline_result)).or_else(|| error(&self.hello_admission))
            .or_else(|| error(&self.connected)).or_else(|| error(&self.connected_peer))
            .or_else(|| error(&self.socket_join)).or_else(|| error(&self.hello))
            .or_else(|| self.handshake_error.as_ref().map(|cause| cause as _))
            .or_else(|| self.cold.as_ref().and_then(RetainedStorageColdOpenV1::output_failure))
            .or_else(|| self.cold_error.as_ref().map(|cause| cause as _))
            .or_else(|| error(&self.failed_entry_native_post))
            .or_else(|| self.failed_entry_security_post.as_ref().and_then(|post| post.failure()))
            .or_else(|| error(&self.failed_hello_native_post))
            .or_else(|| self.failed_hello_security_post.as_ref().and_then(|post| post.failure()))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn error<T, E: std::error::Error + 'static>(result: &Option<Result<T, E>>)
    -> Option<&(dyn std::error::Error + 'static)>
{
    result.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}


fn observe_old_client_witnesses(
    session: &mut DormantAuthenticatedBrokerSessionV1,
) -> Result<(), ClientTransitionClosedV1> {
    let Some(witnesses) = session.client_witnesses.as_mut().ok().and_then(Option::as_mut) else {
        return Err(ClientTransitionClosedV1);
    };
    // Only the fixed-paid, held-history-qualified turn calls this helper.
    // Existing failures remain sticky; changing the observation disposition
    // neither clears a failure nor admits another operation.
    witnesses.storage_preparation = true;
    if witnesses.revalidate(session.socket.peer()) {
        Ok(())
    } else {
        Err(ClientTransitionClosedV1)
    }
}

#[cfg(test)]
mod rollover_tests {
    use super::*;
    use std::num::NonZeroU64;

    #[test]
    fn completed_rollover_distinguishes_initial_and_current_transports() {
        let initial = NonZeroU64::new(11).unwrap();
        let current = NonZeroU64::new(12).unwrap();
        let lineage = CompletedStorageClientRolloverV1 {
            originating_transport: initial,
            previous_transport: initial, transport: current, transcript: [3; 32],
        };

        assert!(lineage.matches_initial_v1(initial));
        assert!(!lineage.matches_initial_v1(current));
        assert!(lineage.matches_values_v1(current, [3; 32]));
        assert!(!lineage.matches_values_v1(initial, [3; 32]));
        assert!(!lineage.matches_values_v1(current, [4; 32]));
        let next = NonZeroU64::new(13).unwrap();
        let successor = CompletedStorageClientRolloverV1 {
            originating_transport: lineage.originating_transport,
            previous_transport: lineage.transport,
            transport: next,
            transcript: [5; 32],
        };
        assert!(successor.matches_initial_v1(initial));
        assert!(!successor.matches_initial_v1(current));
        assert_eq!(successor.previous_transport, current);
        assert!(successor.matches_values_v1(next, [5; 32]));
    }
}
