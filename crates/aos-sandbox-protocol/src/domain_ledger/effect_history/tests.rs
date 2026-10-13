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
                    1, 1, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, b'a', b'b', b'c', b't',
                    b'r', b'y',
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
                    1, 1, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, b'a', b'b', b'c', b'n',
                    b'o',
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
            Err(EffectHistoryDataError::InvalidPlan("broker effect has no method"))
        ));
    }

    #[test]
    fn generic_v2_effect_bytes_remain_exact_in_every_state() {
        let cases = [
            (
                EffectState::Planned,
                vec![
                    2, 2, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c',
                ],
            ),
            (
                EffectState::Applying {
                    attempt: 2,
                    diagnostic: "try".to_owned(),
                },
                vec![
                    2, 2, 2, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c', b't', b'r', b'y',
                ],
            ),
            (
                EffectState::Applied {
                    attempt: 3,
                    receipt: EffectReceipt::new(vec![9, 8]).unwrap(),
                },
                vec![
                    2, 2, 3, 0, 3, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c', 9, 8,
                ],
            ),
            (
                EffectState::PermanentlyBlocked {
                    attempt: 4,
                    diagnostic: "no".to_owned(),
                },
                vec![
                    2, 2, 4, 0, 4, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 7, b'a', b'b',
                    b'c', b'n', b'o',
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
        cross_domain[18..22].copy_from_slice(
            &(BrokerMethod::BROKER_METHOD_HOST_APPLY_RUNTIME as i32).to_be_bytes(),
        );
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
            Err(EffectHistoryDataError::InvalidPlan("unknown broker effect method"))
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

        for version in [0, CONTROLLER_Q04_EFFECT_VERSION + 1, u8::MAX] {
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
