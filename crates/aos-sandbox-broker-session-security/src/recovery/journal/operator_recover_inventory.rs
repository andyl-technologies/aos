//! Borrows only the actual signed Recover Inventory18 logical Session head.
//!
//! No constructor, native reader, writer, floor, deadline or financial original
//! is exposed. The same protected endpoint/currentness engines remain active.

use super::*;

impl ProtectedBrokerSessionOwnerV1 {
    pub(crate) fn operator_recover_inventory_journal_v1(&self) -> Result<&Journal, BrokerSessionSecurityError> {
        self.journal.require_operator_recover_inventory_v1()?;
        self.journal.journal.as_ref().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn operator_recover_inventory_journal_mut_v1(&mut self) -> Result<&mut Journal, BrokerSessionSecurityError> {
        self.journal.require_operator_recover_inventory_v1()?;
        self.journal.journal.as_mut().ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn operator_recover_inventory_stored_v1(&self) -> Result<&[u8], BrokerSessionSecurityError> {
        self.operator_recover_inventory_journal_v1()?.get(RecordNamespace::BrokerSessionTraffic,
            &canonical_operator_recover_inventory_key_v1()).ok_or(BrokerSessionSecurityError::Currentness)
    }

    pub(crate) fn compare_operator_recover_inventory_retaining_v1(&mut self,
        currentness: &ProtectedBrokerOutcomeCurrentnessOwnerV1, peer: &ConnectionPeerIdentity,
        originals: &mut OutcomeCurrentOriginalsV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.journal.require_operator_recover_inventory_v1()?;
        if !aos_sandbox_broker_session_protocol::profile::is_storage_operator_recover_transcript_v1(&currentness.transcript)
            || currentness.request.authorization().is_some()
        { return Err(BrokerSessionSecurityError::Currentness); }
        // The existing Storage retained replay is already purpose-neutral:
        // read_current selects the actual owner slot and validates both rows.
        originals.observe_inventory_once(&mut self.journal, currentness, peer)
    }
}

impl ProtectedBrokerSessionJournalV1 {
    fn require_operator_recover_inventory_v1(&self) -> Result<(), BrokerSessionSecurityError> {
        let fixed = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerStorageClient);
        if self.purpose != SessionPurpose::OperatorRecoverInventory
            || !matches!(self.owner, JournalOwnerV1::ServiceClient(_))
            || self.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Storage
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.directory != Path::new(fixed.journal_root) || self.name != PROTECTED_SESSION_JOURNAL
            || self.limits != protected_session_journal_limits()
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok(())
    }
}

impl ProtectedBrokerOutcomeCommittedAdvancementV1 {
    pub(crate) fn operator_recover_inventory_transcript_data_v1(&self)
        -> Option<&VerifiedBrokerSessionTranscriptV1> {
        let transcript = &self.currentness_owner.transcript;
        aos_sandbox_broker_session_protocol::profile::is_storage_operator_recover_transcript_v1(transcript)
            .then_some(transcript)
    }

    pub(crate) fn operator_recover_inventory_originals_v1(&self, actual: &ProtectedBrokerSessionOwnerV1)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ProtectedBrokerOutcomeCurrentnessOwnerV1), BrokerSessionSecurityError> {
        actual.journal.require_operator_recover_inventory_v1()?;
        let owner = &self.currentness_owner;
        actual.journal.require_storage_inventory_predecessor_v1(owner)?;
        if !aos_sandbox_broker_session_protocol::profile::is_storage_operator_recover_transcript_v1(&owner.transcript)
            || owner.request.authorization().is_some()
        { return Err(BrokerSessionSecurityError::Currentness); }
        Ok((&owner.outcome, owner))
    }
}
