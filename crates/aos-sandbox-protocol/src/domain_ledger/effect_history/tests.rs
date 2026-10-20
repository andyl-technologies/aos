//! Original pure Effect codec regressions against the canonical historical DATA owner.

use super::*;
use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_core::{BrokerAudience, ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

#[test]
fn nix_audience_cannot_enter_or_encode_the_generic_broker_effect_path() {
    assert!(matches!(
        EffectDomain::from_audience(BrokerAudience::Nix),
        Err(EffectHistoryDataError::InvalidPlan(
            "Nix authority cannot use the generic broker effect path"
        ))
    ));
    assert!(matches!(
        audience_code(BrokerAudience::Nix),
        Err(EffectHistoryDataError::InvalidPlan(
            "Nix authority cannot use the generic broker effect path"
        ))
    ));

    for reserved in [0, 5, 6, u8::MAX] {
        assert!(matches!(
            audience_from_code(reserved),
            Err(EffectHistoryDataError::CorruptLedger(
                "unknown authority effect audience"
            ))
        ));
    }
}

#[test]
fn generic_v1_effect_is_rejected_in_every_state() {
    let cases = [
        (
            "planned",
            vec![
                1, 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c',
            ],
        ),
        (
            "applying",
            vec![
                1, 1, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, b'a', b'b', b'c', b't', b'r',
                b'y',
            ],
        ),
        (
            "applied",
            vec![
                1, 1, 3, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, b'a', b'b', b'c', 9, 8,
            ],
        ),
        (
            "permanently blocked",
            vec![
                1, 1, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, b'a', b'b', b'c', b'n', b'o',
            ],
        ),
    ];
    for (state, bytes) in cases {
        assert!(
            matches!(
                decode_effect(&bytes),
                Err(EffectHistoryDataError::CorruptLedger(
                    "invalid effect record header"
                ))
            ),
            "{state}",
        );
    }
}

#[test]
fn opaque_effect_plan_is_rejected_by_the_encoder() {
    let record = EffectLedgerRecord {
        plan: EffectPlan {
            domain: EffectDomain::Host,
            method: None,
            controller_method: None,
            request: b"abc".to_vec(),
            authority: None,
        },
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    };

    assert!(matches!(
        encode_effect(&record),
        Err(EffectHistoryDataError::InvalidPlan(
            "broker effect has no method"
        ))
    ));
}

#[test]
fn generic_v2_effect_bytes_remain_exact_in_every_state() {
    let cases = [
        (
            EffectState::Planned,
            vec![
                2, 2, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b', b'c',
            ],
        ),
        (
            EffectState::Applying {
                attempt: 2,
                diagnostic: "try".to_owned(),
            },
            vec![
                2, 2, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 7, b'a', b'b', b'c',
                b't', b'r', b'y',
            ],
        ),
        (
            EffectState::Applied {
                attempt: 3,
                receipt: EffectReceipt::new(vec![9, 8]).unwrap(),
            },
            vec![
                2, 2, 3, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b', b'c',
                9, 8,
            ],
        ),
        (
            EffectState::PermanentlyBlocked {
                attempt: 4,
                diagnostic: "no".to_owned(),
            },
            vec![
                2, 2, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 7, b'a', b'b', b'c',
                b'n', b'o',
            ],
        ),
    ];
    for (state, expected) in cases {
        let record = EffectLedgerRecord {
            plan: EffectPlan::new(
                EffectDomain::Storage,
                BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
                b"abc".to_vec(),
            )
            .unwrap(),
            state,
            dispatch: None,
            project_admission: None,
        };
        assert_eq!(encode_effect(&record).unwrap(), expected);
        assert_eq!(decode_effect(&expected).unwrap(), record);
    }
}

#[test]
fn generic_v2_effect_binds_the_exact_broker_method() {
    let record = EffectLedgerRecord {
        plan: EffectPlan::new(
            EffectDomain::Storage,
            BrokerMethod::BROKER_METHOD_STORAGE_APPLY,
            b"abc".to_vec(),
        )
        .unwrap(),
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    };
    let expected = vec![
        2, 2, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b', b'c',
    ];
    assert_eq!(encode_effect(&record).unwrap(), expected);
    assert_eq!(decode_effect(&expected).unwrap(), record);

    let mut unknown_method = expected.clone();
    unknown_method[18..22].copy_from_slice(&5_i32.to_be_bytes());
    assert!(matches!(
        decode_effect(&unknown_method),
        Err(EffectHistoryDataError::CorruptLedger(
            "unknown broker effect method"
        ))
    ));

    let mut cross_domain = expected;
    cross_domain[18..22]
        .copy_from_slice(&(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME as i32).to_be_bytes());
    assert!(matches!(
        decode_effect(&cross_domain),
        Err(EffectHistoryDataError::CorruptLedger(
            "broker effect method/domain mismatch"
        ))
    ));
}

#[test]
fn new_effect_rejects_unspecified_and_cross_domain_methods() {
    assert!(matches!(
        EffectPlan::new(
            EffectDomain::Host,
            BrokerMethod::BROKER_METHOD_UNSPECIFIED,
            b"body".to_vec(),
        ),
        Err(EffectHistoryDataError::InvalidPlan(
            "unknown broker effect method"
        ))
    ));
    assert!(matches!(
        EffectPlan::new(
            EffectDomain::Storage,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            b"body".to_vec(),
        ),
        Err(EffectHistoryDataError::InvalidPlan(
            "broker effect method crosses its fixed domain"
        ))
    ));
}

#[test]
fn authority_bound_v2_effect_has_fixed_binding_and_record_digests() {
    let record = EffectLedgerRecord {
        plan: authority_bound_plan(),
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    };
    let binding = record.plan.authority().unwrap();
    assert_eq!(
        binding.digest.as_bytes(),
        &[
            0x93, 0xa5, 0xb9, 0xa6, 0x43, 0x87, 0xa8, 0x85, 0xf7, 0xe6, 0xd2, 0x06, 0x3e, 0x82,
            0x98, 0xaf, 0xd2, 0xbe, 0x2e, 0xf1, 0xbc, 0x51, 0x38, 0xfc, 0x29, 0x71, 0x70, 0xda,
            0xcd, 0x5a, 0xfb, 0x92,
        ]
    );

    let bytes = encode_effect(&record).unwrap();
    assert_eq!(bytes.len(), 400);
    assert_eq!(bytes[0], EFFECT_VERSION);
    assert_eq!(bytes[3], AUTHORITY_BOUND_FLAG);
    assert_eq!(decode_effect(&bytes).unwrap(), record);
    let record_digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(
        record_digest,
        [
            0x08, 0x44, 0x42, 0xef, 0x5f, 0x24, 0xfc, 0x96, 0xf3, 0xa3, 0xd4, 0x30, 0x65, 0x84,
            0x33, 0xae, 0xbb, 0x49, 0x72, 0xb3, 0x66, 0xfd, 0x2f, 0x89, 0x89, 0xfc, 0xc4, 0xf5,
            0x7a, 0xd4, 0x6c, 0xd7,
        ]
    );
}

#[test]
fn authority_bound_v1_record_is_rejected_before_binding_recovery() {
    let record = EffectLedgerRecord {
        plan: authority_bound_plan(),
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    };
    let mut legacy = encode_effect(&record).unwrap();
    legacy[0] = 1;
    legacy.drain(18..22);

    assert!(matches!(
        decode_effect(&legacy),
        Err(EffectHistoryDataError::CorruptLedger(
            "invalid effect record header"
        ))
    ));
}

#[test]
fn effect_decoder_accepts_only_known_versions_and_closed_flags() {
    let generic = encode_effect(&EffectLedgerRecord {
        plan: EffectPlan::new(
            EffectDomain::Host,
            BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            b"generic".to_vec(),
        )
        .unwrap(),
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    })
    .unwrap();
    let authority = encode_effect(&EffectLedgerRecord {
        plan: authority_bound_plan(),
        state: EffectState::Planned,
        dispatch: None,
        project_admission: None,
    })
    .unwrap();

    for version in [0, super::observe_completion::COMPLETED_OBSERVE_EFFECT_VERSION + 1, u8::MAX] {
        for canonical in [&generic, &authority] {
            let mut unknown_version = canonical.clone();
            unknown_version[0] = version;
            assert!(matches!(
                decode_effect(&unknown_version),
                Err(EffectHistoryDataError::CorruptLedger(
                    "invalid effect record header"
                ))
            ));
        }
    }
    for flags in [2, 3, u8::MAX] {
        for canonical in [&generic, &authority] {
            let mut unknown_flags = canonical.clone();
            unknown_flags[3] = flags;
            assert!(matches!(
                decode_effect(&unknown_flags),
                Err(EffectHistoryDataError::CorruptLedger(
                    "invalid effect record header"
                ))
            ));
        }
    }
}

#[test]
fn authority_dispatch_requires_a_nonzero_preparation_host_boot() {
    const HOST_BOOT_OFFSET: usize = 373;
    const HOST_BOOT_BYTES: usize = 16;

    let plan = authority_bound_plan();
    let binding = plan.authority().unwrap();
    let dispatch = PreparedAuthorityEffectHistoryV1::from_durable_parts(
        binding.digest,
        ObjectDigest::from_bytes([7; 32]),
        10,
        20,
        [8; 16],
        BrokerDispatchAttemptHistoryV1::from_durable_parts(
            binding.template_digest,
            ObjectDigest::from_bytes([6; 32]),
            1,
            30,
            b"attempt".to_vec(),
            b"packet".to_vec(),
        ),
    );
    let record = EffectLedgerRecord {
        plan,
        state: EffectState::Applying {
            attempt: 1,
            diagnostic: String::new(),
        },
        dispatch: Some(dispatch),
        project_admission: None,
    };

    let bytes = encode_effect(&record).unwrap();
    assert_eq!(decode_effect(&bytes).unwrap(), record);

    let mut zero_boot_record = record.clone();
    zero_boot_record
        .dispatch
        .as_mut()
        .unwrap()
        .preparation_host_boot_id = [0; 16];
    assert!(matches!(
        encode_effect(&zero_boot_record),
        Err(EffectHistoryDataError::InvalidPlan(
            "authority effect dispatch has a sentinel host boot"
        ))
    ));

    let mut zero_boot_bytes = bytes;
    zero_boot_bytes[HOST_BOOT_OFFSET..HOST_BOOT_OFFSET + HOST_BOOT_BYTES].fill(0);
    assert!(matches!(
        decode_effect(&zero_boot_bytes),
        Err(EffectHistoryDataError::CorruptLedger(
            "invalid authority effect dispatch"
        ))
    ));
}

fn authority_bound_plan() -> EffectPlan {
    let operation_id = OperationId::from_bytes([3; 16]);
    let source_draft_digest = ObjectDigest::from_bytes([1; 32]);
    let template_digest = ObjectDigest::from_bytes([2; 32]);
    let body_digest = effect_body_digest(b"abc");
    let semantic_digest = ObjectDigest::from_bytes([5; 32]);
    let digest = effect_binding_digest(
        operation_id,
        7,
        source_draft_digest,
        BrokerAudience::Host,
        BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
        template_digest,
        body_digest,
        semantic_digest,
    )
    .unwrap();

    EffectPlan {
        domain: EffectDomain::Host,
        method: Some(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME),
        controller_method: None,
        request: b"abc".to_vec(),
        authority: Some(AuthorityEffectBindingV1 {
            operation_id,
            step: 7,
            source_draft_digest,
            audience: BrokerAudience::Host,
            method: BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME,
            template_digest,
            body_digest,
            semantic_digest,
            descriptor_free: true,
            digest,
        }),
    }
}

#[cfg(target_os = "linux")]
pub(super) fn completed_q04_fixture_v1() -> (EffectLedgerRecord,
    crate::domain_ledger::create_q04_history::Q04EffectSubgateV1,
) {
    use aos_proto::aos::sandbox::v1::{CreateSandboxRequest, Duration, ObjectDescriptor};
    use aos_sandbox_core::{PrincipalId, ProjectId};
    use buffa::Message as _;
    use crate::domain_ledger::create_q04_history::{GATE_BYTES, Q04EffectSubgateV1};
    use crate::public_api::PublicOperationMethodV1;
    use crate::public_api::method::PublicApiAuditMethodV1;
    use crate::public_api::mutation::PublicMutationRequestV1;
    use crate::public_api::public_mutation_context::PublicMutationContextV1;

    let project = ProjectId::from_bytes([1; 16]);
    let descriptor = |media_type: &str| ObjectDescriptor {
        media_type: media_type.to_owned(),
        sha256: vec![2; 32],
        encoded_size: 1,
        ..Default::default()
    };
    let request = CreateSandboxRequest {
        project_id: project.as_bytes().to_vec(),
        expected_project_resource_version: vec![3; 32],
        specification: Some(descriptor("application/vnd.aos.sandbox.spec.v1+cbor")).into(),
        requested_policy: Some(descriptor("application/vnd.aos.sandbox.policy.v1+cbor")).into(),
        idempotency_key: b"create-terminal".to_vec(),
        operation_timeout: Some(Duration { nanoseconds: 1, ..Default::default() }).into(),
        ..Default::default()
    };
    let envelope = PublicMutationRequestV1::new(
        PublicApiAuditMethodV1::CreateSandbox, &request.encode_to_vec(),
    ).unwrap().encode();
    let context = PublicMutationContextV1::new(
        PrincipalId::from_bytes([4; 16]), project, 100, envelope,
    ).unwrap();
    let plan = EffectPlan::from_public_mutation_bytes(
        PublicOperationMethodV1::CreateSandbox, context.encode().unwrap(),
    ).unwrap();
    let receipt = EffectReceipt::new([
        b"AOSLIF01".as_slice(), &[5; 16], &[6; 32],
    ].concat()).unwrap();
    let record = EffectLedgerRecord::from_parts((
        plan, EffectState::Applied { attempt: 1, receipt }, None, None,
    ));
    let mut body = [0; GATE_BYTES];
    body[16..176].fill(7);
    body[176..184].copy_from_slice(&1_u64.to_be_bytes());
    body[184] = 4;
    body[192..256].fill(8);
    let final_gate = Q04EffectSubgateV1::from_body(body).unwrap();

    (record, final_gate)
}

#[cfg(target_os = "linux")]
#[test]
fn completed_q04_preserves_its_final_companion_and_refuses_earlier_status() {
    use crate::domain_ledger::create_q04_history::{GATE_BYTES, Q04EffectSubgateV1};

    let (record, final_gate) = completed_q04_fixture_v1();
    let mut body = *final_gate.bytes();
    let encoded = encode_q04_effect(&record, &final_gate).unwrap();
    let (decoded, gate) = decode_effect_with_q04(&encoded).unwrap();

    assert_eq!(decoded, record);
    assert_eq!(gate.unwrap().bytes(), final_gate.bytes());
    assert_eq!(encoded[0], CONTROLLER_Q04_EFFECT_VERSION);

    body[184] = 3;
    let earlier = Q04EffectSubgateV1::from_body(body).unwrap();
    assert!(encode_q04_effect(&record, &earlier).is_err());
    let mut substituted = encoded;
    let offset = substituted.len() - GATE_BYTES;
    substituted[offset..].copy_from_slice(earlier.bytes());
    assert!(decode_effect_with_q04(&substituted).is_err());
}

#[test]
fn authority_effect_forecast_covers_real_encoder_at_request_limit_and_refuses_the_next_byte() {
    for request_bytes in [1, MAXIMUM_REQUEST_BYTES] {
        let mut plan = authority_bound_plan();
        plan.request = vec![7; request_bytes];
        let bound = authority_effect_record_bound_v1(&plan).unwrap();
        let record = EffectLedgerRecord {
            plan,
            state: EffectState::Planned,
            dispatch: None,
            project_admission: None,
        };

        let encoded = encode_effect(&record).unwrap();

        assert!(bound >= encoded.len());
    }

    let mut oversized = authority_bound_plan();
    oversized.request = vec![7; MAXIMUM_REQUEST_BYTES + 1];

    assert!(authority_effect_record_bound_v1(&oversized).is_err());
}
