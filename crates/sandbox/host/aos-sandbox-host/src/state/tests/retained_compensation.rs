//! Checks the closed negative grammar and immutable original replay boundary.

use aos_sandbox_broker::BrokerEffectStatusV1;

use super::*;
use crate::state::transition::GuardianLaunchPhase;

fn retained_state() -> (AdmissionFixture, HostAuthorityV1, HostState, Vec<u8>) {
    let fixture = AdmissionFixture::new();
    let authority = fixture.authority();
    let bytes = runtime_request();
    let mut state = authenticated_guardian_state(&fixture, &authority, &bytes);
    let effect = state.effect(&[103; 16]).unwrap().to_vec();
    let fence = state.request_authorization(&[103; 16]).unwrap().to_vec();
    state
        .set_guardian_phase(
            &[103; 16],
            GuardianLaunchPhase::CompensatedRetainedV1 {
                observation_sequence: 7,
            },
            &authority,
        )
        .unwrap();
    assert_eq!(state.effect(&[103; 16]), Some(effect.as_slice()));
    assert_eq!(
        state.request_authorization(&[103; 16]),
        Some(fence.as_slice())
    );
    (fixture, authority, state, bytes)
}

#[test]
fn retained_negative_roundtrips_with_original_pending_effect_and_no_receipt() {
    let (_, authority, state, bytes) = retained_state();
    let id = [103; 16];
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let sealed_effect = state.effect(&id).unwrap().to_vec();
    let sealed_fence = state.request_authorization(&id).unwrap().to_vec();

    state.validate_authenticated(&authority).unwrap();
    let reopened = HostState::decode(&state.encode().unwrap()).unwrap();
    reopened.validate_authenticated(&authority).unwrap();

    assert_eq!(reopened.effect(&id), Some(sealed_effect.as_slice()));
    assert_eq!(
        reopened.request_authorization(&id),
        Some(sealed_fence.as_slice())
    );
    assert!(reopened.requests[&id].receipt.is_none());
    assert_eq!(
        authority.open_effect(&id, &sealed_effect).unwrap().status(),
        BrokerEffectStatusV1::Pending
    );
    assert_eq!(
        reopened.query_effect(&id, digest).unwrap(),
        RuntimeEffectQuery::Pending
    );
    assert!(reopened.query_effect(&id, [99; 32]).is_err());
    assert!(reopened.original_canary_baseline_debt().is_err());
    assert!(!reopened.canary_cleanup_is_complete([id, [0; 16]]));
    assert!(reopened.canary_reservation_is_issued([id, [0; 16]]));
    let execution = reopened.guardian_execution(&id).unwrap();
    assert!(execution.canary_remaining_guardian().is_none());
    assert!(execution.guardian_completed_invocations().is_none());
}

#[test]
fn retained_negative_is_mac_bound_and_cannot_have_a_positive_receipt() {
    let (_, authority, state, _) = retained_state();
    let id = [103; 16];
    let mut changed = state.clone();
    assert!(
        changed
            .requests
            .get_mut(&id)
            .unwrap()
            .execution
            .set_guardian_phase(GuardianLaunchPhase::CompensatedRetainedV1 {
                observation_sequence: 8
            })
    );
    assert!(changed.validate_authenticated(&authority).is_err());

    let mut with_receipt = state;
    let completed = authority
        .open_effect(&id, with_receipt.effect(&id).unwrap())
        .unwrap()
        .complete(vec![42])
        .unwrap();
    let record = with_receipt.requests.get_mut(&id).unwrap();
    record.effect = authority.seal_effect(&id, &completed).unwrap();
    record.receipt = Some(vec![42]);
    assert!(with_receipt.validate_authenticated(&authority).is_err());
    assert!(HostState::decode(&with_receipt.encode().unwrap()).is_err());
}

#[test]
fn retained_negative_refuses_refresh_before_any_original_bytes_change() {
    let (fixture, authority, mut state, bytes) = retained_state();
    let id = [103; 16];
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let request = decode_runtime_request(
        &bytes,
        test_peer(),
        test_policy(),
        TEST_BOOTTIME_NANOSECONDS,
    )
    .unwrap();
    let prior = state.request_authorization(&id).unwrap().to_vec();
    let renewed = admitted_records(&fixture, &authority, &bytes, 2, 300, Some(&prior));
    let fence = authority
        .seal_fence(request.fence().sandbox_id(), &renewed.fence)
        .unwrap();
    let effect = authority.seal_effect(&id, &renewed.effect).unwrap();
    let original = state.encode().unwrap();
    let execution = state.guardian_execution(&id).unwrap();
    assert_ne!(state.effect(&id).unwrap(), effect.as_slice());

    assert!(
        state
            .admit(
                request.fence(),
                id,
                digest,
                HostAction::Launch.code(),
                fence.clone(),
                &renewed,
                effect.clone(),
                &authority
            )
            .is_err()
    );
    assert_eq!(state.encode().unwrap(), original);
    assert!(
        state
            .admit_guardian(
                request.fence(),
                id,
                digest,
                execution,
                fence,
                &renewed,
                effect,
                &authority
            )
            .is_err()
    );
    assert_eq!(state.encode().unwrap(), original);
    state.validate_authenticated(&authority).unwrap();
}

#[test]
fn old_compensated_still_requires_receipt_and_negative_zero_never_installs() {
    let (_, authority, mut state, bytes) = retained_state();
    let id = [103; 16];
    let original = state.encode().unwrap();
    assert!(
        state
            .set_guardian_phase(
                &id,
                GuardianLaunchPhase::CompensatedRetainedV1 {
                    observation_sequence: 0
                },
                &authority
            )
            .is_err()
    );
    assert_eq!(state.encode().unwrap(), original);

    state
        .set_guardian_phase(
            &id,
            GuardianLaunchPhase::Compensated {
                observation_sequence: 7,
            },
            &authority,
        )
        .unwrap();
    assert!(state.validate_authenticated(&authority).is_err());
    assert!(HostState::decode(&state.encode().unwrap()).is_err());

    // The original positive grammar and its MAC remain valid once the same
    // pending effect is completed with its matching receipt.
    let authentication = state.requests[&id].execution_authentication.clone();
    let receipt = vec![42];
    let completed = authority
        .open_effect(&id, state.effect(&id).unwrap())
        .unwrap()
        .complete(receipt.clone())
        .unwrap();
    let sealed = authority.seal_effect(&id, &completed).unwrap();
    let digest = Sha256::digest(&bytes).into();
    state.complete(id, digest, sealed, receipt.clone()).unwrap();

    state.validate_authenticated(&authority).unwrap();
    assert_eq!(state.requests[&id].execution_authentication, authentication);
    let encoded = state.encode().unwrap();
    let reopened = HostState::decode(&encoded).unwrap();
    reopened.validate_authenticated(&authority).unwrap();
    assert_eq!(reopened.encode().unwrap(), encoded);
    assert_eq!(
        reopened.query_effect(&id, digest).unwrap(),
        RuntimeEffectQuery::Complete(receipt)
    );
}
