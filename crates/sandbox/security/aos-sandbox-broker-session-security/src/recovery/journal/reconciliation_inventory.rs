//! Rejoins only finite reconciliation requests to the same fixed role history.
//!
//! The genuine residual native loan selects the method. This private adapter
//! opens nothing, overwrites no head and neither adopts nor retires a request.

use super::*;

impl ProtectedBrokerSessionJournalV1 {
    fn require_reconciliation_inventory_method_v2(&self, method: BrokerMethod)
        -> Result<(), BrokerSessionSecurityError> {
        if !matches!(self.purpose, SessionPurpose::Ordinary | SessionPurpose::HostStopCleanup)
            || (self.purpose == SessionPurpose::HostStopCleanup
                && (self.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Host
                    || method != BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME))
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        // The existing fixed location check proves actual Client ownership,
        // role, main name and limits. Its ordinary head/replay stays untouched.
        self.delete_inventory_client_method_v1()?;
        let allowed = match self.endpoint.protected_protocol_and_node().0 {
            BrokerSessionProtocolV1::Host => method == BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            BrokerSessionProtocolV1::Network => method == BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            BrokerSessionProtocolV1::Mount => method == BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            BrokerSessionProtocolV1::Storage => method == BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            _ => false,
        };
        if allowed { Ok(()) } else { Err(BrokerSessionSecurityError::Currentness) }
    }

    pub(in crate::recovery) fn require_reconciliation_inventory_predecessor_v2(&self,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1, method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.require_reconciliation_inventory_method_v2(method)?;
        self.require_controller_inventory_predecessor_method_v2(owner, method)
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn reconciliation_inventory_client_journal_v2(&self, method: BrokerMethod)
        -> Result<&Journal, BrokerSessionSecurityError> {
        self.journal.require_reconciliation_inventory_method_v2(method)?;
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn reconciliation_inventory_client_journal_mut_v2(&mut self, method: BrokerMethod)
        -> Result<&mut Journal, BrokerSessionSecurityError> {
        self.journal.require_reconciliation_inventory_method_v2(method)?;
        self.journal.journal.as_mut().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn reconciliation_inventory_client_stored_v2(&self, method: BrokerMethod)
        -> Result<&[u8], BrokerSessionSecurityError> {
        let journal = self.reconciliation_inventory_client_journal_v2(method)?;
        journal.get(RecordNamespace::BrokerSessionTraffic,
            &session_protocol_key_v2(self.journal.endpoint.protected_protocol_and_node().0,
                self.journal.purpose)?)
            .ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn compare_reconciliation_inventory_predecessor_retaining_v2(&mut self,
        currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        peer: &ConnectionPeerIdentity, originals: &mut OutcomeCurrentOriginalsV1,
        method: BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        originals.observe_reconciliation_inventory_once_v2(&mut self.journal, currentness, peer, method)
    }
}

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    pub(crate) fn reconciliation_inventory_client_originals_v2(&self,
        actual: &ProtectedBrokerSessionOwnerV1, method: BrokerMethod,
    ) -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        actual.journal.require_reconciliation_inventory_predecessor_v2(&self.currentness_owner, method)?;
        Ok((&self.currentness_owner.outcome, &self.currentness_owner))
    }
}
