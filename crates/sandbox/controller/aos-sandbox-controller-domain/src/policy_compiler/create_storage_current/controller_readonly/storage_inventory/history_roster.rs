//! Verifies both fixed Storage history slots without selecting either as a grant.
//!
//! Ordinary and Recover Inventory histories share the canonical codec and
//! historical signature/traffic verifier. Every Traffic row is checked; the
//! ordinary caller still selects only AOSBSJ01 for its own exact operation.
//! Recover's AOSBRI01 can never substitute for an interrupted Apply head.

use super::*;
use aos_sandbox_protocol::authenticated_session::stored_history::{
    classify_protocol_key_v2, StoredBrokerSessionPurposeDataV2,
};

pub(super) fn receiving_demand_v2(prefix: usize) -> Result<ResourceVector, JournalError> {
    use aos_sandbox_protocol::authenticated_session::all_methods::{
        request_capture::AuthenticatedBrokerMethodRequestCaptureV1,
        outcome_capture::AuthenticatedBrokerMethodOutcomeCaptureV1,
    };
    // The loop releases pure verification scratch after each row. The total
    // reached prefix bounds each row; request/outcome model recipes and sixteen
    // raw planes dominate its decode, context, transcript and traffic copies.
    let request = AuthenticatedBrokerMethodRequestCaptureV1::dynamic_receiving_demand_v1(prefix)
        .ok_or(JournalError::JournalTooLarge)?;
    let outcome = AuthenticatedBrokerMethodOutcomeCaptureV1::dynamic_receiving_demand_v1(prefix)
        .ok_or(JournalError::JournalTooLarge)?;
    let bytes = u64::try_from(prefix).ok().and_then(|bytes| bytes.checked_mul(16))
        .and_then(|bytes| bytes.checked_add(256 * 1024)).ok_or(JournalError::JournalTooLarge)?;
    request.checked_add(outcome)
        .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
        .map_err(JournalError::ReceivingAccounting)
}

pub(in crate::policy_compiler) fn verify_storage_history_roster_v2(
    state: &std::collections::BTreeMap<(crate::journal::RecordNamespace, Vec<u8>), Vec<u8>>,
    manifest: &BrokerSessionManifestV1, node: [u8; 16], boot: [u8; 16],
) -> Result<(), Error> {
    let mut ordinary = false;
    let mut recover = false;
    for ((namespace, key), encoded) in state {
        if *namespace != crate::journal::RecordNamespace::BrokerSessionTraffic { continue; }
        let (purpose, protocol) = classify_protocol_key_v2(key)?;
        if protocol != BrokerSessionProtocolV1::Storage { return Err(Box::new(Changed)); }
        let selected = match purpose {
            StoredBrokerSessionPurposeDataV2::Ordinary => &mut ordinary,
            StoredBrokerSessionPurposeDataV2::OperatorRecoverInventory => &mut recover,
            StoredBrokerSessionPurposeDataV2::HostStopCleanup
            | StoredBrokerSessionPurposeDataV2::HostNoApplyCleanup => return Err(Box::new(Changed)),
        };
        // Two fixed keys exhaust this endpoint's admissible Traffic roster.
        // No map or vector is grown before this closed cardinality check.
        if std::mem::replace(selected, true) { return Err(Box::new(Changed)); }
        let stored = StoredBrokerSessionHistoryV1::decode(key, encoded)?;
        if stored.endpoint != BrokerSessionDurableEndpointV1::Client { return Err(Box::new(Changed)); }
        let checkpoint = stored.checkpoint.as_ref().ok_or(Changed)?;
        let context = local_context_for_protocol_v2(manifest, checkpoint.context(), node, boot, protocol)?;
        let transcript = checkpoint.verify()?;
        let history = stored.history_model()?;
        // A pending head stays pending. Verification of the full signed prefix
        // neither completes it nor requires it to be terminal for the other slot.
        verify_historical_traffic_records_v1(history.records(), &transcript, &context)?;
    }
    Ok(())
}
