//! Rechecks actual deployment admission at the final native genesis frontier.
//!
//! A saved packet is historical DATA. New admission additionally checks its
//! independently pinned generation and the real wall clock at this crossing.
//! No caller supplies a timestamp or renews the original signed expiry.

use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::replay::root_genesis_pins::decode_policy_signer_pins_v1;

use crate::journal_keys::{HEAD_KEY, SIGNER_PINS_KEY};
use crate::native::authority::RootAuthorityErrorV1;
use crate::native::journal::RootPolicyJournalV1;
use crate::signed_inputs::verify_historical_policy_deployment_packet_v1;

pub(super) fn require_current_deployment(
    journal: &RootPolicyJournalV1,
) -> Result<i64, RootAuthorityErrorV1> {
    let namespace = RecordNamespace::DesiredState;
    let (generation, key, _, _) = decode_policy_signer_pins_v1(
        journal
            .get(namespace, SIGNER_PINS_KEY)
            .ok_or(RootAuthorityErrorV1::AdmissionClosed)?,
    )
    .map_err(|_| RootAuthorityErrorV1::AdmissionClosed)?;
    let packet = journal
        .get(namespace, HEAD_KEY)
        .ok_or(RootAuthorityErrorV1::AdmissionClosed)?;
    verify_historical_policy_deployment_packet_v1(packet, &key)
        .map_err(|_| RootAuthorityErrorV1::AdmissionClosed)?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RootAuthorityErrorV1::AdmissionClosed)?
            .as_secs(),
    )
    .map_err(|_| RootAuthorityErrorV1::AdmissionClosed)?;
    let read = |offset| aos_sandbox_ledger_replay::data::take::<8>(packet, offset);
    let expires = i64::from_be_bytes(read(24)?);
    if u64::from_be_bytes(read(8)?) != generation
        || i64::from_be_bytes(read(16)?) > now
        || now >= expires
    {
        return Err(RootAuthorityErrorV1::AdmissionClosed);
    }
    Ok(expires)
}
