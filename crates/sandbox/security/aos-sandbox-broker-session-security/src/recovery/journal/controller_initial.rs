//! Owns the closed initial Controller Client main Journal and its first causes.
//!
//! This purpose adapter uses the shared Native captured writer, exact original
//! prefix, upper schema and floor engines. It retains the actual main before
//! later typed/floor checks; no path, UID, account or signer factory is exposed.

use super::*;

#[derive(Clone, Copy)]
enum ControllerInitialMainFailureV1 {
    Existing,
    Native,
    Prefix,
    Deadline(usize),
}

pub(super) struct ControllerInitialSessionMainOpenV1 {
    existing: Option<Result<std::fs::Metadata, std::io::Error>>,
    native: aos_sandbox_controller_domain::journal::ControllerBrokerSessionCapturedJournalOpenV1,
    prefix: Option<Result<(), aos_sandbox_controller_domain::ControllerInitialBrokerSessionClosedV1>>,
    deadlines: [Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>; 5],
    first: Option<ControllerInitialMainFailureV1>,
}

impl ControllerInitialSessionMainOpenV1 {
    const fn new() -> Self {
        Self {
            existing: None,
            native: aos_sandbox_controller_domain::journal::ControllerBrokerSessionCapturedJournalOpenV1::new(),
            prefix: None,
            deadlines: [const { None }; 5],
            first: None,
        }
    }

    fn check_deadline_v1(
        &mut self,
        index: usize,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.deadlines[index] = Some(deadline.check());
        match self.deadlines[index] {
            Some(Ok(())) => Ok(()),
            _ => {
                self.first.get_or_insert(ControllerInitialMainFailureV1::Deadline(index));
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            ControllerInitialMainFailureV1::Existing => self.existing.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            ControllerInitialMainFailureV1::Native => self.native.failure(),
            ControllerInitialMainFailureV1::Prefix => self.prefix.as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
            ControllerInitialMainFailureV1::Deadline(index) => self.deadlines[index].as_ref()?.as_ref().err()
                .map(|cause| cause as &dyn std::error::Error),
        }
    }
}

pub(crate) const fn controller_initial_fixed_endpoint_v1(
    role: aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1,
) -> ProtectedBrokerSessionFixedEndpointV1 {
    use aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1 as Role;
    match role {
        Role::Host => ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient,
        Role::Mount => ProtectedBrokerSessionFixedEndpointV1::ControllerMountClient,
        Role::Storage => ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient,
        Role::Network => ProtectedBrokerSessionFixedEndpointV1::ControllerNetworkClient,
    }
}

impl BrokerMainOpenV1 {
    pub(crate) fn prepare_controller_initial_v1(
        root: &'static str,
        custody: &mut Option<FixedEndpointCustodyV1>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
        receiving: &aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let role = receiving.role_v1();
        receiving.require_fixed_capture_current_v1(role)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let fixed = fixed_endpoint(controller_initial_fixed_endpoint_v1(role));
        let node = receiving.expected_node_v1()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let Some(FixedEndpointCustodyV1::Client(endpoint)) = custody.as_ref() else {
            return Err(BrokerSessionSecurityError::Currentness);
        };
        if root != fixed.journal_root
            || endpoint.protected_protocol_and_node() != (fixed.protocol, node)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let directory = PathBuf::from(fixed.journal_root);
        let name = PROTECTED_SESSION_JOURNAL.to_owned();
        let Some(FixedEndpointCustodyV1::Client(endpoint)) = custody.take() else {
            std::process::abort()
        };
        Ok(Self {
            authority: None,
            floor: None,
            floor_preparation: None,
            endpoint: Some(ProtectedEndpointV1::Client(endpoint)),
            directory,
            name,
            limits: protected_session_journal_limits(),
            phase: BrokerMainOpenPhaseV1::Fresh,
            first_failure: None,
            cold_deadline: Some(deadline),
            #[cfg(feature = "online-nix")]
            online_schema: None,
        })
    }

    pub(crate) fn open_controller_initial_v1(
        &mut self,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.open_with_original_receiving_v1(None, Some(receiving), None)
    }

    pub(crate) fn observe_controller_initial_failure_post_v1(&mut self)
        -> Result<(), BrokerSessionSecurityError>
    {
        let owner = self.authority.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        let mut operation = BrokerFloorOperationV1::begin(owner);
        let result = operation.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .observe_controller_initial_failure_post_v1(operation.owner)
            .map_err(floor_revalidation::security_error);
        operation.finish(result)
    }

    pub(crate) fn controller_initial_property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    {
        if !matches!(self.first_failure,
            Some(BrokerMainOpenFailureV1::Endpoint(BrokerSessionSecurityError::ControllerPhysicalFloor)))
        { return None; }
        self.authority.as_ref()?.floor.controller_property_failure_view_v1()
    }

    pub(crate) fn controller_initial_native_failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if matches!(self.first_failure,
            Some(BrokerMainOpenFailureV1::Endpoint(BrokerSessionSecurityError::ControllerPhysicalFloor)))
        {
            return self.authority.as_ref()?.floor.controller_physical_failure_v1();
        }
        self.floor_preparation.as_ref().and_then(|original| original.failure())
            .or_else(|| self.authority.as_ref().and_then(|owner| {
                owner.floor_preparation.as_ref().and_then(|original| original.failure())
            }))
            .or_else(|| self.authority.as_ref()?.controller_initial_open.as_ref()?.failure())
    }
}

impl BrokerFloorOperationV1<'_> {
    pub(super) fn open_controller_initial_main_v1(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
        deadline: crate::handshake::OriginalBrokerColdDeadlineV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        use aos_sandbox_controller_domain::journal::CapturedJournalOpenModeV1;

        self.check_cold_deadline()?;
        let role = receiving.role_v1();
        let fixed = fixed_endpoint(controller_initial_fixed_endpoint_v1(role));
        let node = receiving.expected_node_v1()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if protocol != fixed.protocol
            || self.owner.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.owner.endpoint.protected_protocol_and_node() != (protocol, node)
            || self.owner.directory != Path::new(fixed.journal_root)
            || self.owner.name != PROTECTED_SESSION_JOURNAL
            || self.owner.journal.is_some() || self.owner.controller_initial_open.is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.owner.controller_initial_open = Some(ControllerInitialSessionMainOpenV1::new());
        let staged = self.owner.controller_initial_open.as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        staged.check_deadline_v1(0, deadline)?;
        staged.existing = Some(std::fs::symlink_metadata(
            self.owner.directory.join(&self.owner.name),
        ));
        let existing = match staged.existing.as_ref() {
            Some(Ok(_)) => true,
            Some(Err(cause)) if cause.kind() == std::io::ErrorKind::NotFound => false,
            _ => {
                staged.first = Some(ControllerInitialMainFailureV1::Existing);
                return Err(BrokerSessionSecurityError::Currentness);
            }
        };
        staged.check_deadline_v1(1, deadline)?;
        let mode = if protocol == BrokerSessionProtocolV1::Storage && existing {
            CapturedJournalOpenModeV1::ExistingOnly
        } else {
            CapturedJournalOpenModeV1::CreateAndRepair
        };
        staged.native.prepare_once(self.owner.limits, mode, receiving);
        if staged.native.failure().is_some() {
            staged.first = Some(ControllerInitialMainFailureV1::Native);
        }
        staged.check_deadline_v1(2, deadline)?;
        if staged.first.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        staged.prefix = Some(receiving.admit_captured_prefix_once_v1(&staged.native));
        if !matches!(staged.prefix, Some(Ok(()))) {
            staged.first = Some(ControllerInitialMainFailureV1::Prefix);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        staged.native.replay_once(receiving);
        if staged.native.failure().is_some() {
            staged.first = Some(ControllerInitialMainFailureV1::Native);
        }
        staged.check_deadline_v1(3, deadline)?;
        if staged.first.is_some() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let Some((journal, _)) = staged.native.take_opened(receiving) else {
            staged.first = Some(ControllerInitialMainFailureV1::Native);
            return Err(BrokerSessionSecurityError::Currentness);
        };
        self.owner.journal = Some(journal);
        staged.check_deadline_v1(4, deadline)?;

        // Reuse the existing typed Session validation and floor attachment.
        // Their original Journal is already resident across any upper refusal.
        self.check_cold_deadline()?;
        self.owner.endpoint.revalidate()?;
        let floor = self.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
        if role == aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1::Storage {
            self.owner.arm_initial_storage_floor_revalidation_once_v1(floor, receiving)?;
        }
        floor.bind_controller_initial_cold_v1(receiving, deadline)
            .map_err(floor_revalidation::security_error)?;
        self.owner.validate_schema_only()?;
        self.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .attach_controller_initial_v1(self.owner, receiving)
            .map_err(floor_revalidation::security_error)
    }
}

impl ProtectedBrokerSessionFixedCustodyV1 {
    pub(crate) fn open_controller_initial_retaining_v1(
        opening: &mut crate::endpoint::ProtectedBrokerSessionControllerClientOpeningV1,
        receiving: &mut aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<Self, BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(controller_initial_fixed_endpoint_v1(receiving.role_v1()));
        opening.load_controller_once(receiving);
        let Some(client) = opening.completed_ref_v1() else {
            return Err(opening.classified_failure().unwrap_or(BrokerSessionSecurityError::Currentness));
        };
        let node = receiving.expected_node_v1()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if client.protected_protocol_and_node() != (fixed.protocol, node) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let custody = opening.take_completed().ok_or(BrokerSessionSecurityError::Currentness)?;
        Ok(Self {
            journal_root: fixed.journal_root,
            protocol: fixed.protocol,
            audience: fixed.audience,
            socket_path: fixed.socket_path,
            custody: FixedEndpointCustodyV1::Client(custody),
        })
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn require_controller_initial_journal_v1(
        &self,
        receiving: &aos_sandbox_controller_domain::ControllerInitialBrokerSessionReceivingLoanV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(controller_initial_fixed_endpoint_v1(receiving.role_v1()));
        let node = receiving.expected_node_v1()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.journal.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.journal.endpoint.protected_protocol_and_node() != (fixed.protocol, node)
            || self.journal.directory != Path::new(fixed.journal_root)
            || self.journal.name != PROTECTED_SESSION_JOURNAL
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let journal = self.journal.journal.as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        receiving.require_opened_journal_v1(journal)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn observe_controller_initial_failure_post_v1(&mut self)
        -> Result<(), BrokerSessionSecurityError>
    {
        let mut operation = BrokerFloorOperationV1::begin(&mut self.journal);
        let result = operation.floor.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?
            .observe_controller_initial_failure_post_v1(operation.owner)
            .map_err(floor_revalidation::security_error);
        operation.finish(result)
    }
}
