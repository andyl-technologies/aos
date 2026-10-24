//! Selects the actual fixed Controller Client behind a closed D query.
//!
//! These borrowed projections open nothing and mint no query or financial
//! original. The caller must already hold the genuine C17 pending fence and
//! continuously retain this same Session through its whole independent post.

use super::*;

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn delete_inventory_client_method_v1(
        &self,
    ) -> Result<BrokerMethod, BrokerSessionSecurityError> {
        self.journal.delete_inventory_client_method_v1()
    }

    pub(crate) fn delete_inventory_client_journal_v1(
        &self,
    ) -> Result<&Journal, BrokerSessionSecurityError> {
        self.delete_inventory_client_method_v1()?;
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn delete_inventory_client_journal_mut_v1(
        &mut self,
    ) -> Result<&mut Journal, BrokerSessionSecurityError> {
        self.delete_inventory_client_method_v1()?;
        self.journal.journal.as_mut().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn delete_inventory_client_stored_v1(
        &self,
    ) -> Result<&[u8], BrokerSessionSecurityError> {
        let journal = self.delete_inventory_client_journal_v1()?;
        let protocol = self.journal.endpoint.protected_protocol_and_node().0;
        journal.get(RecordNamespace::BrokerSessionTraffic, &protocol_key(protocol))
            .ok_or(BrokerSessionSecurityError::Currentness)
    }
}

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    // The opaque answer constructor already validated this exact terminal
    // against its same Session. This borrows historical DATA only; no current
    // native owner, Session grant or predecessor comparison is projected.
    pub(crate) fn delete_inventory_completed_outcome_data_v1(&self)
        -> &AuthenticatedBrokerMethodOutcomeV1
    {
        &self.currentness_owner.outcome
    }

    // These are the actual confirmed-CAS generation/head retained by this
    // exact completed advancement, never a caller-selected historical floor.
    pub(crate) fn delete_inventory_negotiated_context_data_v2(&self) -> Option<(
        &ProtectedBrokerSessionVerificationContextV1, &VerifiedBrokerSessionTranscriptV1,
        &'static str, &'static str,
    )> {
        use aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1 as Role;
        let role = match self.currentness_owner.transcript.protocol() {
            BrokerSessionProtocolV1::Host => Role::Host,
            BrokerSessionProtocolV1::Mount => Role::Mount,
            BrokerSessionProtocolV1::Storage => Role::Storage,
            BrokerSessionProtocolV1::Network => Role::Network,
            _ => return None,
        };
        let fixed = fixed_endpoint(controller_initial_fixed_endpoint_v1(role));
        Some((&self.currentness_owner.context, &self.currentness_owner.transcript,
            fixed.journal_root, PROTECTED_SESSION_JOURNAL))
    }

    pub(crate) fn delete_inventory_kernel_boot_data_v2(&self) -> [u8; 16] {
        self.currentness_owner.context.boot_id()
    }

    pub(crate) fn delete_inventory_protected_cut_data_v2(&self) -> (u64, [u8; 32]) {
        (self.currentness_owner.protected_generation, self.currentness_owner.protected_head)
    }

    pub(crate) fn delete_inventory_client_originals_v1(
        &self,
        actual: &ProtectedBrokerSessionOwnerV1,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        let owner = &self.currentness_owner;
        actual.journal.require_delete_inventory_predecessor_v1(owner)?;
        Ok((&owner.outcome, owner))
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(in crate::recovery) fn delete_inventory_client_method_v1(&self) -> Result<BrokerMethod, BrokerSessionSecurityError> {
        use aos_sandbox_controller_domain::ControllerInitialBrokerSessionRoleV1 as Role;
        let (role, method) = match self.endpoint.protected_protocol_and_node().0 {
            BrokerSessionProtocolV1::Host => (Role::Host, BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME),
            BrokerSessionProtocolV1::Mount => (Role::Mount, BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS),
            BrokerSessionProtocolV1::Storage => (Role::Storage, BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES),
            BrokerSessionProtocolV1::Network => (Role::Network, BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES),
            _ => return Err(BrokerSessionSecurityError::Currentness),
        };
        let fixed = fixed_endpoint(controller_initial_fixed_endpoint_v1(role));
        if !matches!(self.owner, JournalOwnerV1::ServiceClient(_))
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.directory != Path::new(fixed.journal_root)
            || self.name != PROTECTED_SESSION_JOURNAL
            || self.limits != protected_session_journal_limits()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(method)
    }


    pub(in crate::recovery) fn require_delete_inventory_predecessor_v1(
        &self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let method = self.delete_inventory_client_method_v1()?;
        self.require_controller_inventory_predecessor_method_v2(owner, method)
    }

    pub(in crate::recovery) fn require_controller_inventory_predecessor_method_v2(
        &self, owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        if !owner.transcript.negotiated_methods().contains(&method)
            || owner.transcript.protocol() != self.endpoint.protected_protocol_and_node().0
            || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || owner.request.method() != method
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.method() != method
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(())
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn compare_delete_inventory_predecessor_retaining_v1(
        &mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        originals.observe_delete_inventory_once(&mut self.journal, owner, peer)
    }
}

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    pub(crate) fn delete_storage_preparation_originals_v3(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.delete_storage_originals_v3(DeleteStorageOutcomePurposeV3::Preparation)
    }

    pub(crate) fn delete_storage_apply_originals_v3(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.delete_storage_originals_v3(DeleteStorageOutcomePurposeV3::Apply)
    }

    pub(crate) fn delete_network_originals_v4(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.delete_storage_originals_v3(DeleteStorageOutcomePurposeV3::Network)
    }

    pub(crate) fn delete_mount_originals_v4(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        self.delete_storage_originals_v3(DeleteStorageOutcomePurposeV3::Mount)
    }

    fn delete_storage_originals_v3(&self, purpose: DeleteStorageOutcomePurposeV3)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError>
    {
        let owner = &self.currentness_owner;
        if owner.transcript.protocol() != match purpose {
            DeleteStorageOutcomePurposeV3::Preparation | DeleteStorageOutcomePurposeV3::Apply => BrokerSessionProtocolV1::Storage,
            DeleteStorageOutcomePurposeV3::Network => BrokerSessionProtocolV1::Network,
            DeleteStorageOutcomePurposeV3::Mount => BrokerSessionProtocolV1::Mount,
        }
            || owner.transcript.audience() != aos_sandbox_api::aos::sandbox::local::v1::Audience::AUDIENCE_NODE_CONTROLLER
            || !owner.transcript.negotiated_methods().contains(&purpose.method_v3())
            || owner.request.method() != purpose.method_v3()
            || owner.request.direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || owner.outcome.method() != owner.request.method()
            || owner.outcome.direction() != aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok((&owner.outcome, owner))
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn compare_delete_preparation_retaining_v3(&mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        originals.observe_delete_preparation_once_v3(&mut self.journal, owner, peer)
    }
}

#[derive(Clone, Copy)]
enum DeleteStorageOutcomePurposeV3 { Preparation, Apply, Network, Mount }

impl DeleteStorageOutcomePurposeV3 {
    fn method_v3(self) -> BrokerMethod {
        match self {
            Self::Preparation => BrokerMethod::BROKER_METHOD_STORAGE_PREPARE_CATALOG,
            Self::Apply => BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            Self::Network => BrokerMethod::BROKER_METHOD_NETWORK_APPLY,
            Self::Mount => BrokerMethod::BROKER_METHOD_MOUNT_APPLY_ATTACHMENT_ANCHOR_V1,
        }
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn compare_delete_network_retaining_v4(&mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        originals.observe_delete_network_once_v4(&mut self.journal, owner, peer)
    }

    pub(crate) fn compare_delete_mount_retaining_v4(&mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        originals.observe_delete_mount_once_v4(&mut self.journal, owner, peer)
    }

    pub(crate) fn compare_delete_apply_retaining_v3(&mut self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        originals.observe_delete_apply_once_v3(&mut self.journal, owner, peer)
    }
}
