//! Bounded complete original Host history capture before failed-Create quarantine.
//!
//! Only the actual fixed ControllerHostClient writer can produce this private
//! snapshot. It retains both complete native archive wrappers, not digest-only
//! claims. The result is historical DATA: it cannot authorize a Root step,
//! Controller CAS, Host effect, release, request resend or currentness.

use std::path::Path;

use aos_proto::aos::sandbox::local::v1::ObserveHostExecutionArgumentRequestV1;
use aos_sandbox::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use aos_sandbox::tpm_nv_custody::{
    encode_failed_create_original_histories_v4, failed_create_original_histories_encoded_len_v4,
};
use aos_sandbox::RecordNamespace;
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1,
};
use buffa::Message as _;

use super::{
    AuthenticatedOriginalHostNoApplyJoinV1, BrokerSessionSecurityError,
    ProtectedBrokerSessionFixedEndpointV1, ProtectedBrokerSessionJournalAuthorityV1,
    ProtectedBrokerSessionJournalV1, ProtectedBrokerSessionOwnerV1,
    PROTECTED_SESSION_JOURNAL, fixed_endpoint, historical_client_request,
    host_argument_archive_key, host_terminal_archive_key,
};

/// Retains complete selected history bytes without a live continuation permit.
pub(crate) struct RetainedFailedCreateOriginalsDataV3 {
    bundle: Vec<u8>,
    historical_join: AuthenticatedOriginalHostNoApplyJoinV1,
}

impl RetainedFailedCreateOriginalsDataV3 {
    /// Borrows the exact bounded AOSCFH04 encoding for immutable Root archival.
    pub(crate) fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    /// Borrows the genuine historical H/T identity join, never current authority.
    pub(crate) const fn historical_join(&self) -> &AuthenticatedOriginalHostNoApplyJoinV1 {
        &self.historical_join
    }
}

impl ProtectedBrokerSessionOwnerV1 {
    /// Captures full original histories while the actual fixed writer is retained.
    ///
    /// The existing-session wrapper independently rechecks its actual socket and
    /// transcript around this call. Its Controller caller must recheck the
    /// accepted operation, current RuntimeScope and output source on both sides,
    /// before any gate, quarantine or method53 Prepare.
    pub(crate) fn capture_failed_create_originals_v3(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<RetainedFailedCreateOriginalsDataV3, BrokerSessionSecurityError> {
        self.journal.capture_failed_create_originals_v3(source)
    }
}

impl ProtectedBrokerSessionJournalV1 {
    /// Captures the selected complete archives before allocating their copies.
    ///
    /// Missing or oversized history is indeterminate, not absence, a new
    /// original operation, or permission to quarantine the existing one.
    pub(crate) fn capture_failed_create_originals_v3(
        &mut self,
        source: &ControllerExecutionArgumentAttemptV1,
    ) -> Result<RetainedFailedCreateOriginalsDataV3, BrokerSessionSecurityError> {
        self.require_fixed_failed_create_client()?;
        let original_key = host_argument_archive_key(source.request_id());
        let terminal_key = host_terminal_archive_key(source.request_id());

        // Inspect actual borrowed row lengths before the old archive readers
        // can clone/decode a wrapper. Unrelated current-history limits remain
        // unchanged; the selected pair alone has the new closed aggregate cap.
        let (snapshot, original, terminal) = {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let snapshot = authority
                .snapshot()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let original = authority
                .get(&original_key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            let terminal = authority
                .get(&terminal_key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .ok_or(BrokerSessionSecurityError::Currentness)?;
            failed_create_original_histories_encoded_len_v4(original.len(), terminal.len())
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            authority
                .validate_snapshot_for_effect(&snapshot)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            (snapshot, original.to_vec(), terminal.to_vec())
        };

        let before = self.read_current(BrokerSessionProtocolV1::Host)?;
        let stored = self
            .read_host_argument_archive(source.request_id())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let checkpoint = stored
            .checkpoint
            .as_ref()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let transcript = checkpoint.verify()?;
        let history = stored.history_model()?;
        let original_index = history
            .records()
            .len()
            .checked_sub(1)
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let (request, _) = historical_client_request(
            history.records(),
            original_index,
            checkpoint,
            &transcript,
        )?;
        let body = ObserveHostExecutionArgumentRequestV1::decode_from_slice(request.exact_body())
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if body.encode_to_vec() != request.exact_body()
            || body.canonical_attempt != source.canonical_bytes()
            || request.request_id() != source.request_id()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let joined = self
            .read_host_terminal_archive(source.request_id())?
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        if joined.original().source().canonical_bytes() != source.canonical_bytes()
            || joined.original().archive_head() != stored.current_head
            || joined.original().request().canonical_packet() != request.canonical_packet()
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let bundle = encode_failed_create_original_histories_v4(&original, &terminal)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.require_fixed_failed_create_client()?;
        if self.read_current(BrokerSessionProtocolV1::Host)? != before {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        {
            let authority = self
                .journal_mut()?
                .claim_protected_authority(RecordNamespace::BrokerSessionTraffic)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let current_original = authority
                .get(&original_key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let current_terminal = authority
                .get(&terminal_key)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            if current_original != Some(original.as_slice())
                || current_terminal != Some(terminal.as_slice())
            {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            authority
                .validate_snapshot_for_effect(&snapshot)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        }
        self.require_fixed_failed_create_client()?;

        Ok(RetainedFailedCreateOriginalsDataV3 {
            bundle,
            historical_join: joined,
        })
    }

    fn require_fixed_failed_create_client(&mut self) -> Result<(), BrokerSessionSecurityError> {
        let selected = fixed_endpoint(ProtectedBrokerSessionFixedEndpointV1::ControllerHostClient);
        if self.directory != Path::new(selected.journal_root)
            || self.name != PROTECTED_SESSION_JOURNAL
            || self.endpoint.role() != BrokerSessionDurableEndpointV1::Client
            || self.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Host
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.endpoint.revalidate()?;
        let owner = self.owner;
        owner
            .validate_held(
                self.journal_mut()?,
                Path::new(selected.journal_root),
                PROTECTED_SESSION_JOURNAL,
            )
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        self.require_floor_current()?;
        self.endpoint.revalidate()
    }
}
