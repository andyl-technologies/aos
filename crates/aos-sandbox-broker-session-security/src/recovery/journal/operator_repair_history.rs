//! Retains original Repair Inventory traffic as non-authorizing cold evidence.
//!
//! Archives share the existing journal's aggregate byte and record budgets.
//! They are immutable, survive compaction, and are never retired on age, EOF,
//! or an uncertain effect. Reauthentication cannot restore a live Storage hold.
//!
//! ```text
//! AOSBSR01 | actual Inventory request-id[16] ->
//! AOSRSH01 | version:u16be | request-id[16] | history-length:u32be
//! original protected history/checkpoint | domain-separated digest[32]
//! ```

use super::*;

pub(super) const KEY_MAGIC: &[u8; 8] = b"AOSBSR01";
const MAGIC: &[u8; 8] = b"AOSRSH01";
const DOMAIN: &[u8] = b"aos.sandbox.operator-repair.inventory-history.v1\0";
const MAXIMUM_ARCHIVES: usize = 16;

fn archive_key(request_id: [u8; 16]) -> Vec<u8> {
    [KEY_MAGIC.as_slice(), request_id.as_slice()].concat()
}

impl ProtectedBrokerSessionOwnerV1 {
    /// Retains or reauthenticates one exact original signed Repair Inventory.
    ///
    /// This returns historical evidence only. Both the current endpoint and
    /// protected journal are bracketed; no old packet becomes a send grant or
    /// a fresh inventory/currentness owner.
    ///
    /// An absent expected packet recovers only the selected request's complete
    /// protected terminal history, for loss before the Controller packet write.
    /// It does not infer absence, accept caller bytes, or issue another request.
    ///
    /// # Errors
    ///
    /// Rejects missing, mismatched or ambiguous original history, exhausted
    /// unchanged journal bounds, unavailable floor/checkpoint/pins, and changed
    /// actual current endpoint or socket peer.
    pub(crate) fn operator_repair_inventory_history(
        &mut self,
        request_id: [u8; 16],
        packet: Option<&[u8]>,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
        self.revalidate_transport(transcript, connection_peer)?;
        let before = self.journal.read_current(BrokerSessionProtocolV1::Storage)?;
        let outcome = self
            .journal
            .retain_operator_repair_inventory(request_id, packet)?;

        if self.journal.read_current(BrokerSessionProtocolV1::Storage)? != before {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let repeated = self
            .journal
            .read_operator_repair_inventory(request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if repeated.canonical_packet() != outcome.canonical_packet()
            || repeated.request().canonical_packet() != outcome.request().canonical_packet()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.revalidate_transport(transcript, connection_peer)?;
        Ok(outcome)
    }
}

impl ProtectedBrokerSessionJournalV1 {
    fn retain_operator_repair_inventory(
        &mut self,
        request_id: [u8; 16],
        packet: Option<&[u8]>,
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
        if let Some(outcome) = self.read_operator_repair_inventory(request_id)? {
            if packet.is_some_and(|packet| outcome.canonical_packet() != packet) {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            return Ok(outcome);
        }
        if self.validate_operator_repair_inventory_archives()? == MAXIMUM_ARCHIVES {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let stored = self
            .read_optional(BrokerSessionProtocolV1::Storage)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let outcome = self.verify_operator_repair_inventory(&stored, request_id)?;
        if packet.is_some_and(|packet| outcome.canonical_packet() != packet) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let value = encode_history_archive_frame(request_id, &stored.encode()?, MAGIC, DOMAIN)?;

        // The unchanged owner limits reject an oversized complete frame or an
        // exhausted aggregate budget. No truncation or archive eviction occurs.
        let mut digest = Sha256::new();
        digest.update(DOMAIN);
        digest.update(request_id);
        digest.update(&value);
        let transaction_id: [u8; 16] = digest.finalize()[..16]
            .try_into()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![JournalRecord::put(
                RecordNamespace::BrokerSessionTraffic,
                archive_key(request_id),
                value,
            )],
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.commit_floor_checked_transaction(&transaction)?;

        let retained = self
            .read_operator_repair_inventory(request_id)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if retained.canonical_packet() != outcome.canonical_packet() {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        Ok(retained)
    }

    fn read_operator_repair_inventory(
        &mut self,
        request_id: [u8; 16],
    ) -> Result<Option<AuthenticatedBrokerMethodOutcomeV1>, BrokerSessionSecurityError> {
        let value = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            authority
                .get(&archive_key(request_id))
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        let Some(value) = value else {
            return Ok(None);
        };
        let frame = open_history_archive_frame(request_id, &value, MAGIC, DOMAIN)?;
        let stored = StoredProtocolHistoryV1::decode(
            &protocol_key(BrokerSessionProtocolV1::Storage),
            frame,
        )?;
        self.verify_operator_repair_inventory(&stored, request_id)
            .map(Some)
    }

    fn verify_operator_repair_inventory(
        &mut self,
        stored: &StoredProtocolHistoryV1,
        request_id: [u8; 16],
    ) -> Result<AuthenticatedBrokerMethodOutcomeV1, BrokerSessionSecurityError> {
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        if request_id == [0; 16]
            || stored.protocol != BrokerSessionProtocolV1::Storage
            || stored.endpoint != BrokerSessionDurableEndpointV1::Client
            || stored.stable_endpoint_identity
                != self.stable_endpoint_identity(BrokerSessionProtocolV1::Storage)?
            || self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
            || stored.endpoint_publication
                != self.historical_endpoint_publication(
                    BrokerSessionProtocolV1::Storage,
                    &transcript,
                )?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let history = stored.history_model()?;
        reconstruct_traffic(&history, &transcript, checkpoint.context())?;
        let records = history.records();

        // Output-prefix traffic has its own explicitly scoped floor/archive
        // closure. This Repair archive must not become its alternate producer.
        if records.iter().any(|record| {
            matches!(
                record.method(),
                BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_OUTPUT
                    | BrokerMethod::BROKER_METHOD_HOST_OBSERVE_STORAGE_OUTPUT
            )
        }) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let index = records
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let head = records
            .get(index)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
            || head.request_id() != request_id
            || records
                .iter()
                .filter(|record| {
                    record.phase() == BrokerSessionDurablePhaseV1::Terminal
                        && record.request_id() == request_id
                })
                .count() != 1
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let outcome = historical_terminal_outcome(records, index, checkpoint, &transcript)?;
        aos_sandbox::lifecycle::LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(
            &outcome,
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        Ok(outcome)
    }

    pub(super) fn validate_operator_repair_inventory_archives(
        &mut self,
    ) -> Result<usize, BrokerSessionSecurityError> {
        let ids = self.bounded_host_archive_request_ids(
            BrokerSessionJournalKeyKind::OperatorRepairInventoryArchive,
            MAXIMUM_ARCHIVES,
        )?;
        for id in &ids {
            self.read_operator_repair_inventory(*id)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
        }
        Ok(ids.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_archive_key_and_frame_are_distinct_and_exact() {
        let id = [7; 16];
        let key = archive_key(id);

        assert_eq!(key.len(), 24);
        assert_eq!(
            classified_broker_session_key(&key).unwrap().0,
            BrokerSessionJournalKeyKind::OperatorRepairInventoryArchive,
        );

        let frame = encode_history_archive_frame(id, b"history", MAGIC, DOMAIN).unwrap();

        assert_eq!(open_history_archive_frame(id, &frame, MAGIC, DOMAIN).unwrap(), b"history");
        assert!(open_history_archive_frame([8; 16], &frame, MAGIC, DOMAIN).is_err());
        assert!(
            open_history_archive_frame(
                id,
                &frame,
                HOST_ARGUMENT_ARCHIVE_MAGIC,
                HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
            )
            .is_err(),
        );
    }
}
