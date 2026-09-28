//! Capacity-backed denial of an actual historical Controller dispatch.
//!
//! This path is available with independently retained role pins after positive
//! credentials expire. It admits no policy input and never creates a stage.

use crate::journal::{Journal, RecordNamespace};
use crate::policy_compiler::controller_project_dispatch_readback::verify_controller_project_dispatch_readback_v1;
use crate::policy_compiler::{PinnedControllerHoldSignerV1, PinnedSourceHoldReadbackSignerV1};

use super::super::super::binding_v2::ensure_root_binding_unheld;
use super::super::super::controller_hold_pin::CONTROLLER_HOLD_PIN_KEY;
use super::super::super::source_hold_pin::SOURCE_HOLD_PIN_KEY;
use super::{
    KEY, PolicyDeploymentHeadErrorV1, RootProjectAdmissionIntentV1, STAGE_KEY, SUFFIX_BYTES,
    SUFFIX_RECORDS, commit_intent, current_project_head_digests, open_fixed_root_project_journal,
    require_intent_capacity, reservation_cancellation_key, zero_digest,
};

/// Reports whether protected historical owner pins can support denial only.
///
/// This permits the existing recovery listener to bind with no Root artifact;
/// it grants neither current credentials nor fresh positive admission.
///
/// # Errors
///
/// Rejects unsafe Root custody, malformed role pins, or key-role reuse.
pub fn fixed_root_project_negative_recovery_available_v1()
-> Result<bool, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    historical_role_pins(&mut journal).map(|pins| pins.is_some())
}

fn historical_role_pins(
    journal: &mut Journal,
) -> Result<Option<PinnedControllerHoldSignerV1>, PolicyDeploymentHeadErrorV1> {
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    let (Some(controller), Some(source)) = (
        authority.get(CONTROLLER_HOLD_PIN_KEY)?,
        authority.get(SOURCE_HOLD_PIN_KEY)?,
    ) else {
        return Ok(None);
    };
    let controller = PinnedControllerHoldSignerV1::decode(controller)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let source = PinnedSourceHoldReadbackSignerV1::decode(source)
        .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    if controller.verifying_key().as_bytes() == source.verifying_key().as_bytes() {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    Ok(Some(controller))
}

/// Reserves only permanent cancellation and historical retirement headroom.
///
/// Root obtains the Controller pin independently from its protected journal,
/// not from the request. The authenticated fixed Controller peer must retain
/// Controller then Source writers, rejoin this actual Source preview, and append
/// that real reservation only after this durable intent is read back.
///
/// # Errors
///
/// Rejects changed historical pins, owner claims, Source issue, current Root
/// predecessor, foreign/pending artifacts, or insufficient reserved capacity.
pub fn prepare_fixed_root_project_negative_intent_v1(
    controller_dispatch: &[u8],
    controller_uid: u32,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let mut journal = open_fixed_root_project_journal()?;
    prepare_with_journal(&mut journal, controller_dispatch, controller_uid)
}

pub(in crate::policy_compiler::project_admission_root) fn prepare_with_journal(
    journal: &mut Journal,
    controller_dispatch: &[u8],
    controller_uid: u32,
) -> Result<RootProjectAdmissionIntentV1, PolicyDeploymentHeadErrorV1> {
    let pin = historical_role_pins(journal)?.ok_or(PolicyDeploymentHeadErrorV1::StaleHead)?;
    let claims =
        verify_controller_project_dispatch_readback_v1(controller_dispatch, &pin, controller_uid)
            .map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    let source = claims.reservation;
    let authority = journal.claim_protected_authority(RecordNamespace::DesiredState)?;
    ensure_root_binding_unheld(&authority).map_err(|_| PolicyDeploymentHeadErrorV1::StaleHead)?;
    super::super::history::require_successor_source_issue(&authority, source)?;
    let (prior_packet, prior_input) = current_project_head_digests(&authority)?;
    if (prior_packet == zero_digest()) != (prior_input == zero_digest()) {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    let intent = RootProjectAdmissionIntentV1 {
        client_nonce: source.client_nonce(),
        project: source.project(),
        source_reservation: source.record_digest(),
        project_packet: zero_digest(),
        project_input: zero_digest(),
        deployment_packet: zero_digest(),
        prior_packet,
        prior_input,
        capacity_id: [0; 32],
        history_retirement: true,
        remaining_records: SUFFIX_RECORDS,
        remaining_bytes: SUFFIX_BYTES,
        decision: zero_digest(),
        negative_dispatch: Some(claims.metadata),
    };
    let prior = authority
        .get(KEY)?
        .map(RootProjectAdmissionIntentV1::decode)
        .transpose()?;
    if authority.get(STAGE_KEY)?.is_some()
        || authority
            .get(&reservation_cancellation_key(source.record_digest()))?
            .is_some()
    {
        return Err(PolicyDeploymentHeadErrorV1::StaleHead);
    }
    if let Some(prior) = prior {
        if !prior.is_retirement_only()
            || prior.decision != zero_digest()
            || prior.binding_digest() != intent.binding_digest()
        {
            return Err(PolicyDeploymentHeadErrorV1::StaleHead);
        }
        drop(authority);
        require_intent_capacity(journal, prior)?;
        return Ok(prior);
    }
    drop(authority);
    commit_intent(journal, intent)
}
