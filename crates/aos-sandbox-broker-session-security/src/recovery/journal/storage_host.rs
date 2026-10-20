//! Selects only Storage's genuine same-F Host client native admission.
//!
//! Endpoint and main use the existing native engines. The loan continuously
//! borrows the actual Storage Server Session and lifecycle original; numeric
//! demand, an authenticated packet or a journal receipt cannot construct it.

use super::*;
use aos_sandbox_linux::seqpacket::SeqpacketSocket;

pub(crate) struct StorageHostClientReceivingV1<'loan, 'cut, 'original> {
    pub(crate) lifecycle: &'loan mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
    pub(crate) session: &'loan aos_sandbox::Journal,
    pub(crate) socket: &'loan SeqpacketSocket,
    node: [u8; 16],
}

impl StorageHostClientReceivingV1<'_, '_, '_> {
    pub(crate) fn require_current_v1(&mut self) -> Result<(), BrokerSessionSecurityError> {
        self.lifecycle.receiving_domain_v1(self.session, self.socket)
            .map(|_| ()).map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn reserve_upper_v1(&mut self, demand: aos_sandbox_core::ResourceVector)
        -> Result<(), BrokerSessionSecurityError>
    {
        // The genuine enclosing Host original has already armed the one
        // independent service post across this whole same-F native interval.
        self.lifecycle.reserve_domain_additional_v1(self.session, self.socket, demand)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    pub(crate) const fn node_v1(&self) -> [u8; 16] { self.node }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn borrow_storage_host_client_receiving_v1<'loan, 'cut, 'original>(
        &'loan mut self,
        socket: &'loan SeqpacketSocket,
        request: &AuthenticatedBrokerMethodRequestV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        lifecycle: &'loan mut aos_sandbox::StorageLifecycleSessionLoanV1<'cut, 'original>,
    ) -> Result<StorageHostClientReceivingV1<'loan, 'cut, 'original>, BrokerSessionSecurityError> {
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || !matches!(request.method(), BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                | BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1)
        { return Err(BrokerSessionSecurityError::Currentness); }
        // This current exact pending writer is checked before any Host native
        // allocation. Its transport comparison is not domain/effect admission.
        { let _pending = self.hold_output_registration_request(request, transcript, socket.peer())?; }
        let node = self.journal.endpoint.protected_protocol_and_node().1;
        let session = self.retained_storage_journal_v1()?;
        lifecycle.receiving_domain_v1(session, socket)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(StorageHostClientReceivingV1 { lifecycle, session, socket, node })
    }
}

impl ProtectedBrokerSessionFixedCustodyV1 {
    pub(crate) fn open_storage_host_retaining_v1(
        opening: &mut crate::endpoint::ProtectedBrokerSessionStorageHostClientOpeningV1,
        receiving: &mut StorageHostClientReceivingV1<'_, '_, '_>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        receiving.require_current_v1()?;
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageHostClient);
        opening.load_once(Path::new(fixed.custody_root), receiving.lifecycle, receiving.session, receiving.socket);
        let custody = opening.take_completed_matching_v1(fixed.protocol, receiving.node)
            .ok_or_else(|| opening.classified_failure())?;
        Ok(Self { journal_root: fixed.journal_root, protocol: fixed.protocol,
            audience: fixed.audience, socket_path: fixed.socket_path,
            custody: FixedEndpointCustodyV1::Client(custody) })
    }
}

impl BrokerMainOpenV1 {
    pub(crate) fn prepare_storage_host_v1(
        root: &'static str,
        custody: &mut Option<FixedEndpointCustodyV1>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
        receiving: &mut StorageHostClientReceivingV1<'_, '_, '_>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        receiving.require_current_v1()?;
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageHostClient);
        let Some(FixedEndpointCustodyV1::Client(endpoint)) = custody.as_ref() else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        if root != fixed.journal_root || endpoint.protected_protocol_and_node() != (fixed.protocol, receiving.node) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let memory = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(16 * (fixed.journal_root.len() + PROTECTED_SESSION_JOURNAL.len())))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        receiving.reserve_upper_v1(aos_sandbox_core::ResourceVector::ZERO
            .with(aos_sandbox_core::ResourceDimension::MemoryBytes, memory))?;
        // Names allocate only after this actual purpose's same-F fixed gate.
        let directory = PathBuf::from(fixed.journal_root);
        let name = PROTECTED_SESSION_JOURNAL.to_owned();
        let Some(FixedEndpointCustodyV1::Client(endpoint)) = custody.take() else { std::process::abort(); };
        Ok(Self { authority: None, floor: None, floor_preparation: None,
            endpoint: Some(ProtectedEndpointV1::Client(endpoint)), directory, name,
            limits: protected_session_journal_limits(), phase: BrokerMainOpenPhaseV1::Fresh,
            first_failure: None, cold_deadline: Some(deadline),
            #[cfg(feature = "online-nix")]
            online_schema: None,
        })
    }

    pub(crate) fn open_storage_host_v1(&mut self, receiving: &mut StorageHostClientReceivingV1<'_, '_, '_>)
        -> Result<(), BrokerSessionSecurityError>
    { self.open_with_original_receiving_v1(None, None, Some(receiving)) }
    pub(crate) fn storage_host_native_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.floor_preparation.as_ref().and_then(|original| original.failure())
            .or_else(|| self.authority.as_ref()?.storage_host_open.as_ref()?.failure())
    }

}

impl BrokerFloorOperationV1<'_> {
    pub(super) fn open_storage_host_main_v1(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        receiving: &mut StorageHostClientReceivingV1<'_, '_, '_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        receiving.require_current_v1()?;
        self.check_cold_deadline()?;
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageHostClient);
        if protocol != fixed.protocol || self.owner.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.owner.endpoint.protected_protocol_and_node() != (fixed.protocol, receiving.node)
            || self.owner.directory != Path::new(fixed.journal_root) || self.owner.name != PROTECTED_SESSION_JOURNAL
            || self.owner.journal.is_some() || self.owner.storage_host_open.is_some()
        { return Err(BrokerSessionSecurityError::Currentness); }
        self.owner.storage_host_open = Some(aos_sandbox::journal::StorageHostSessionCapturedJournalOpenV1::new());
        let staged = self.owner.storage_host_open.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        // Same ordinary Host create/repair behavior, now retaining its whole
        // native prefix; no Storage floor or Controller B slot is adopted.
        staged.prepare_once(self.owner.limits, aos_sandbox::journal::CapturedJournalOpenModeV1::CreateAndRepair,
            receiving.lifecycle, receiving.session, receiving.socket);
        if staged.failure().is_some() { return Err(BrokerSessionSecurityError::Currentness); }
        staged.replay_once(receiving.lifecycle, receiving.session, receiving.socket);
        if staged.failure().is_some() { return Err(BrokerSessionSecurityError::Currentness); }
        let Some((journal, _)) = staged.take_opened(receiving.lifecycle, receiving.session, receiving.socket) else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        self.owner.journal = Some(journal);
        self.check_cold_deadline()?;
        self.owner.endpoint.revalidate()?;
        self.owner.validate_schema_only()?;
        self.attach()
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn retained_storage_host_journal_v1(&self) -> Result<&aos_sandbox::Journal, BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::StorageHostClient);
        if self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.journal.endpoint.protected_protocol_and_node().0 != fixed.protocol
            || self.journal.directory != Path::new(fixed.journal_root) || self.journal.name != PROTECTED_SESSION_JOURNAL
            || !self.journal.storage_host_open.as_ref().is_some_and(|original| original.was_taken_positive_v1())
        { return Err(BrokerSessionSecurityError::Currentness); }
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn storage_host_unmodified_prefix_bound_v1(&self)
        -> Result<aos_sandbox::journal::ProtectedJournalPreopenReplayExtentV1, BrokerSessionSecurityError>
    {
        let journal = self.retained_storage_host_journal_v1()?;
        self.journal.storage_host_open.as_ref()
            .and_then(|original| original.unmodified_opened_prefix_bound_v1(journal)).copied()
            .ok_or(BrokerSessionSecurityError::Currentness)
    }
}
