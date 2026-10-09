//! Verifies that downstream controllers can name destination-slot effect tokens.

#![cfg(target_os = "linux")]

use aos_sandbox::{
    BrokerDispatchAttemptV1, BrokerDispatchSemanticIdentityV1, BrokerDispatchTemplateV1,
    CompletedCurrentDestinationSlotAttemptV1, DestinationSlotAttemptAdmissionOutcomeV1,
    DestinationSlotCompletionOutcomeV1, DestinationSlotReconciliationActionV1,
    DurableCurrentDestinationSlotAttemptV1, PreparedCurrentDestinationSlotDispatchV1,
    PreparedCurrentDestinationSlotResumeDispatchV1, PreparedCurrentDestinationSlotResumeV1,
    PreparedCurrentDestinationSlotV1,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::ValidatedDestinationSlotInventoryRecord;

#[test]
fn downstream_code_can_inspect_destination_slot_effect_tokens() {
    fn accept_opaque_results(
        _: Option<PreparedCurrentDestinationSlotV1>,
        _: Option<PreparedCurrentDestinationSlotResumeV1>,
        _: Option<PreparedCurrentDestinationSlotDispatchV1>,
        _: Option<PreparedCurrentDestinationSlotResumeDispatchV1>,
        _: Option<DurableCurrentDestinationSlotAttemptV1>,
        _: Option<CompletedCurrentDestinationSlotAttemptV1>,
    ) {
    }

    let prepared_action: fn(
        &PreparedCurrentDestinationSlotV1,
    ) -> DestinationSlotReconciliationActionV1 = PreparedCurrentDestinationSlotV1::action;
    let semantics: fn(&PreparedCurrentDestinationSlotV1) -> BrokerDispatchSemanticIdentityV1 =
        PreparedCurrentDestinationSlotV1::semantics;
    let body: for<'a> fn(&'a PreparedCurrentDestinationSlotV1) -> &'a [u8] =
        PreparedCurrentDestinationSlotV1::body_without_deadline;
    let valid_until: fn(&PreparedCurrentDestinationSlotV1) -> u64 =
        PreparedCurrentDestinationSlotV1::valid_until_boottime_nanoseconds;
    let resume_request: fn(&PreparedCurrentDestinationSlotResumeV1) -> [u8; 16] =
        PreparedCurrentDestinationSlotResumeV1::request_id;
    let required_plan: fn(&PreparedCurrentDestinationSlotResumeV1) -> ObjectDigest =
        PreparedCurrentDestinationSlotResumeV1::required_plan_digest;
    let template: for<'a> fn(
        &'a PreparedCurrentDestinationSlotDispatchV1,
    ) -> &'a BrokerDispatchTemplateV1 = PreparedCurrentDestinationSlotDispatchV1::template;
    let attempt_outcome: fn(
        &DurableCurrentDestinationSlotAttemptV1,
    ) -> DestinationSlotAttemptAdmissionOutcomeV1 = DurableCurrentDestinationSlotAttemptV1::outcome;
    let dispatch: for<'a> fn(
        &'a DurableCurrentDestinationSlotAttemptV1,
    ) -> &'a BrokerDispatchAttemptV1 = DurableCurrentDestinationSlotAttemptV1::dispatch_attempt;
    let completion_outcome: fn(
        &CompletedCurrentDestinationSlotAttemptV1,
    ) -> DestinationSlotCompletionOutcomeV1 = CompletedCurrentDestinationSlotAttemptV1::outcome;
    let result: for<'a> fn(
        &'a CompletedCurrentDestinationSlotAttemptV1,
    ) -> &'a ValidatedDestinationSlotInventoryRecord =
        CompletedCurrentDestinationSlotAttemptV1::result;

    assert_eq!(
        DestinationSlotAttemptAdmissionOutcomeV1::Admitted,
        DestinationSlotAttemptAdmissionOutcomeV1::Admitted
    );
    assert_eq!(
        DestinationSlotCompletionOutcomeV1::Recorded,
        DestinationSlotCompletionOutcomeV1::Recorded
    );
    let _ = (
        accept_opaque_results,
        prepared_action,
        semantics,
        body,
        valid_until,
        resume_request,
        required_plan,
        template,
        attempt_outcome,
        dispatch,
        completion_outcome,
        result,
    );
}
