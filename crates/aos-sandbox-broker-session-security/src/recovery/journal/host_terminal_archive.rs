//! Retained signed Host no-Apply terminal history across session rollover.
//!
//! ```text
//! AOSHTA01 | original-method-37-request-id:16 | history-length:u32be |
//! exact signed method-39 session history | SHA256(domain || preceding):32
//! ```
//!
//! The archive preserves historical evidence only. It neither proves that the
//! Host marker is still current nor acknowledges Controller FAILED settlement.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, ObserveHostExecutionArgumentRequestV1,
    TerminalHostExecutionArgumentNoApplyRequestV1,
};
use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox::{JournalRecord, RecordNamespace};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionDurablePhaseV1, BrokerSessionProtocolV1,
};
use buffa::Message as _;

use super::{
    AuthenticatedOriginalHostArgumentArchiveV1, AuthenticatedOriginalHostNoApplyJoinV1,
    BrokerSessionJournalKeyKind, BrokerSessionSecurityError, HOST_TERMINAL_SESSION_KEY_MAGIC,
    MAXIMUM_HOST_TERMINAL_ARCHIVES, ProtectedBrokerSessionJournalV1, StoredProtocolHistoryV1,
    classified_broker_session_key, encode_history_archive_frame, historical_client_request,
    historical_terminal_outcome, host_terminal_archive_key, open_history_archive_frame,
    protocol_key, successful_terminal,
};

const MAGIC: &[u8; 8] = b"AOSHTA01";
const DOMAIN: &[u8] = b"aos.sandbox.broker-session.host-terminal-archive.v1\0";

#[cfg(test)]
mod signed_tests;

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn read_host_terminal_archive(
        &mut self,
        original_request_id: [u8; 16],
    ) -> Result<Option<AuthenticatedOriginalHostNoApplyJoinV1>, BrokerSessionSecurityError> {
        let value = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            authority
                .get(&host_terminal_archive_key(original_request_id))
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .map(<[u8]>::to_vec)
        };
        let Some(value) = value else {
            return Ok(None);
        };
        let bytes = open_history_archive_frame(original_request_id, &value, MAGIC, DOMAIN)?;
        let stored =
            StoredProtocolHistoryV1::decode(&protocol_key(BrokerSessionProtocolV1::Host), bytes)?;
        self.verify_host_terminal_archive(&stored, Some(original_request_id))
            .map(Some)
    }

    pub(super) fn validate_host_terminal_archives(
        &mut self,
    ) -> Result<usize, BrokerSessionSecurityError> {
        let keys = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let mut keys = Vec::new();
            for (key, _) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                let (kind, logical_key) = classified_broker_session_key(key)?;
                if kind == BrokerSessionJournalKeyKind::HostTerminalSessionArchive {
                    if keys.len() == MAXIMUM_HOST_TERMINAL_ARCHIVES {
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                    keys.push(
                        logical_key
                            .try_into()
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?,
                    );
                }
            }
            keys
        };
        for request_id in &keys {
            self.read_host_terminal_archive(*request_id)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
        }
        Ok(keys.len())
    }

    pub(super) fn prepare_host_terminal_archive(
        &mut self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<JournalRecord>, BrokerSessionSecurityError> {
        if stored.protocol != BrokerSessionProtocolV1::Host
            || stored.endpoint != BrokerSessionDurableEndpointV1::Client
        {
            return Ok(None);
        }
        let history = stored.history_model()?;
        let head = history
            .head()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.method() != BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
            || !successful_terminal(head)?
        {
            return Ok(None);
        }
        let outcome = self.verify_host_terminal_archive(stored, None)?;
        let original_request_id = outcome.original().source().request_id();
        if self.validate_host_terminal_archives()? == MAXIMUM_HOST_TERMINAL_ARCHIVES
            || self
                .read_host_terminal_archive(original_request_id)?
                .is_some()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let frame =
            encode_history_archive_frame(original_request_id, &stored.encode()?, MAGIC, DOMAIN)?;
        Ok(Some(JournalRecord::put(
            RecordNamespace::BrokerSessionTraffic,
            host_terminal_archive_key(original_request_id),
            frame,
        )))
    }

    fn verify_host_terminal_archive(
        &mut self,
        stored: &StoredProtocolHistoryV1,
        expected_original_request_id: Option<[u8; 16]>,
    ) -> Result<AuthenticatedOriginalHostNoApplyJoinV1, BrokerSessionSecurityError> {
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        if stored.protocol != BrokerSessionProtocolV1::Host
            || stored.endpoint != BrokerSessionDurableEndpointV1::Client
            || stored.stable_endpoint_identity
                != self.stable_endpoint_identity(BrokerSessionProtocolV1::Host)?
            || self.endpoint.historical_context(checkpoint.context())? != *checkpoint.context()
            || stored.endpoint_publication
                != self
                    .historical_endpoint_publication(BrokerSessionProtocolV1::Host, &transcript)?
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let history = stored.history_model()?;
        let records = history.records();
        let terminal_index = records
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let head = records
            .get(terminal_index)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if head.phase() != BrokerSessionDurablePhaseV1::Terminal
            || head.method() != BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let outcome =
            historical_terminal_outcome(records, terminal_index, checkpoint, &transcript)?;
        let body = TerminalHostExecutionArgumentNoApplyRequestV1::decode_from_slice(
            outcome.request().exact_body(),
        )
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let source =
            ControllerExecutionArgumentAttemptV1::decode_canonical(&body.canonical_attempt)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if expected_original_request_id.is_some_and(|expected| source.request_id() != expected) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let original = self
            .read_host_argument_archive(source.request_id())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let original_checkpoint = original
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let original_transcript = original_checkpoint.verify()?;
        let original_history = original.history_model()?;
        let original_request_index = original_history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (original_request, _) = historical_client_request(
            original_history.records(),
            original_request_index,
            original_checkpoint,
            &original_transcript,
        )?;
        let original_body =
            ObserveHostExecutionArgumentRequestV1::decode_from_slice(original_request.exact_body())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if original_body.canonical_attempt != source.canonical_bytes()
            || original_request.request_id() != source.request_id()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let archive = AuthenticatedOriginalHostArgumentArchiveV1 {
            source,
            request: original_request,
            archive_head: original.current_head,
        };
        let readback = outcome
            .recorded_host_no_apply()
            .map_err(|_| BrokerSessionSecurityError::Currentness)?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        archive.join_no_apply(&readback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_archive_has_distinct_exact_key_and_frame() {
        let original_request_id = [37; 16];
        let key = host_terminal_archive_key(original_request_id);
        assert_eq!(key.len(), 24);
        assert!(key.starts_with(HOST_TERMINAL_SESSION_KEY_MAGIC));
        assert_eq!(
            classified_broker_session_key(&key).unwrap().0,
            BrokerSessionJournalKeyKind::HostTerminalSessionArchive
        );
        assert_ne!(
            key,
            super::super::host_argument_archive_key(original_request_id)
        );

        let frame = encode_history_archive_frame(
            original_request_id,
            b"signed-terminal-transcript",
            MAGIC,
            DOMAIN,
        )
        .unwrap();
        assert_eq!(
            open_history_archive_frame(original_request_id, &frame, MAGIC, DOMAIN).unwrap(),
            b"signed-terminal-transcript"
        );
        assert!(open_history_archive_frame([38; 16], &frame, MAGIC, DOMAIN).is_err());
        let mut changed = frame.clone();
        let final_byte = changed.len() - 1;
        changed[final_byte] ^= 1;
        assert!(open_history_archive_frame(original_request_id, &changed, MAGIC, DOMAIN).is_err());
        assert!(
            open_history_archive_frame(
                original_request_id,
                &frame,
                super::super::HOST_ARGUMENT_ARCHIVE_MAGIC,
                super::super::HOST_ARGUMENT_ARCHIVE_VALUE_DOMAIN,
            )
            .is_err()
        );
    }
}
