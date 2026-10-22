//! Canonical block-fault continuation codec tests.

use super::*;
use crate::block::codec::{BLOCK_ABI_VERSION, BlockCodecError};

fn state() -> BlockFaultState {
    BlockFaultState::new(BlockDurabilityConfig {
        length_bytes: 32,
        atomic_write_bytes: 1,
        maximum_request_bytes: 32,
        discard_granularity_bytes: 0,
        discard_semantics: BlockDiscardSemantics::DeterministicZero,
        volatile_cache_bytes: 64,
        cache_entries: 64,
        controller_buffer_bytes: 64,
        controller_entries: 64,
        persistence_dependencies: 1024,
        retained_versions: 8,
        completion_durability: BlockCompletionDurability::VolatileCacheAccepted,
    })
    .unwrap_or_else(|error| panic!("valid test state: {error}"))
}

#[test]
fn block_fault_checkpoint_codec_is_bounded_versioned_and_canonical() {
    let state = state();
    let bytes = state
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode checkpoint: {error}"));
    let restored = BlockFaultState::from_canonical_bytes(&bytes, 32)
        .unwrap_or_else(|error| panic!("decode checkpoint: {error}"));
    assert_eq!(restored, state);

    let mut unsupported_version = bytes.clone();
    let version_index = b"crucible.block-fault-state.v".len();
    assert_eq!(unsupported_version[version_index], b'4');
    unsupported_version[version_index] = b'?';
    assert_eq!(
        BlockFaultState::from_canonical_bytes(&unsupported_version, 32),
        Err(BlockFaultStateCodecError::Version)
    );

    let configured = u64::try_from(bytes.len() - 1)
        .unwrap_or_else(|error| panic!("fixture length is representable: {error}"));
    assert_eq!(
        BlockFaultState::from_canonical_bytes_with_limit(&bytes, 32, configured),
        Err(BlockFaultStateCodecError::ResourceLimit {
            field: "block fault-state bytes",
            current: 0,
            requested: bytes.len() as u64,
            configured,
            hard: MAX_BLOCK_FAULT_STATE_BYTES,
        })
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        BlockFaultState::from_canonical_bytes(&trailing, 32),
        Err(BlockFaultStateCodecError::Noncanonical)
    );
}

#[test]
fn supplied_fault_parser_preserves_canonical_state_and_input_admission() {
    let expected = state();
    let bytes = expected.to_canonical_bytes().unwrap();
    let mut calls = 0;

    let actual = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        32,
        MAX_BLOCK_FAULT_STATE_BYTES,
        &mut |_| Ok(()),
        &mut |_| Ok(()),
        |payload| {
            calls += 1;
            ciborium::de::from_reader(payload)
        },
    )
    .unwrap();

    assert_eq!(actual, expected);
    assert_eq!(calls, 1);

    let maximum = u64::try_from(bytes.len() - 1).unwrap();
    let result = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        32,
        maximum,
        &mut |_| Ok(()),
        &mut |_| Ok(()),
        |payload| {
            calls += 1;
            ciborium::de::from_reader(payload)
        },
    );

    assert!(matches!(
        result,
        Err(BlockFaultStateCodecError::ResourceLimit { .. })
    ));
    assert_eq!(calls, 1);
}

#[test]
fn supplied_fault_parser_error_precedes_restore_validation() {
    let bytes = state().to_canonical_bytes().unwrap();
    let mut calls = 0;

    let result = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        0,
        MAX_BLOCK_FAULT_STATE_BYTES,
        &mut |_| Ok(()),
        &mut |_| Ok(()),
        |_| {
            calls += 1;
            Err(ciborium::de::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "actual supplied fault parser failure",
            )))
        },
    );

    assert_eq!(result, Err(BlockFaultStateCodecError::Malformed));
    assert_eq!(calls, 1);
}

#[test]
fn fault_validation_output_is_admitted_before_buffer_reservation() {
    let expected = state();
    let bytes = expected.to_canonical_bytes().unwrap();
    let mut requested = Vec::new();

    let result = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        32,
        MAX_BLOCK_FAULT_STATE_BYTES,
        &mut |count| {
            requested.push(count);
            Err("original fault output refused")
        },
        &mut |_| Ok(()),
        |payload| ciborium::de::from_reader(payload),
    );

    assert_eq!(result, Err(BlockFaultStateCodecError::Malformed));
    assert_eq!(requested, [bytes.len() as u64]);
}

#[test]
fn restore_validation_flags_admit_before_later_outcome_validation() {
    let mut checkpoint = state();
    checkpoint.service_outcomes.push(BlockServiceCompletion {
        contributor: [1; 32],
        sequence: 0,
        started_ticks: 0,
        finished_ticks: 0,
        busy_epoch_bytes: 0,
        busy_epoch_operations: 0,
    });
    // The invalid index is reached only after both actual flag arrays are born.
    checkpoint
        .storage_outcome_order
        .push(BlockStorageOutcomeRef::Service(7));
    let mut requests = Vec::new();
    let refusal = checkpoint.validate_restore_with_admission(32, &mut |purpose| {
        requests.push(purpose);
        Err("outcome flags refused")
    });
    assert!(matches!(
        refusal,
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "outcome flags refused"
        })
    ));
    assert_eq!(
        requests,
        [crate::DeviceSnapshotAllocation::ValidationFlags { entries: 1 }]
    );

    requests.clear();
    let invalid = checkpoint.validate_restore_with_admission(32, &mut |purpose| {
        requests.push(purpose);
        Ok(())
    });
    assert!(matches!(
        invalid,
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "restored storage outcome order contains an invalid index"
        })
    ));
    assert_eq!(
        requests,
        [
            crate::DeviceSnapshotAllocation::ValidationFlags { entries: 1 },
            crate::DeviceSnapshotAllocation::ValidationFlags { entries: 0 },
        ]
    );
}

#[test]
fn admitted_fault_restore_preserves_ordinary_state_and_all_temporary_requests() {
    let expected = state();
    let bytes = expected.to_canonical_bytes().unwrap();
    let mut purposes = Vec::new();
    let restored = BlockFaultState::from_canonical_bytes_with_decoder(
        &bytes,
        32,
        MAX_BLOCK_FAULT_STATE_BYTES,
        &mut |_| Ok(()),
        &mut |purpose| {
            purposes.push(purpose);
            Ok(())
        },
        |payload| ciborium::de::from_reader(payload),
    )
    .unwrap();
    assert_eq!(restored, expected);
    // Empty collections make no storage claim, but still cross the saved sticky cut.
    assert_eq!(
        purposes
            .iter()
            .filter(|purpose| matches!(
                purpose,
                crate::DeviceSnapshotAllocation::ValidationSequences { .. }
            ))
            .count(),
        9
    );
    assert_eq!(
        purposes
            .iter()
            .filter(|purpose| matches!(
                purpose,
                crate::DeviceSnapshotAllocation::ValidationJobs { .. }
            ))
            .count(),
        2
    );
    assert!(purposes.contains(&crate::DeviceSnapshotAllocation::ValidationJobArray { entries: 0 }));
}

#[test]
fn admitted_restore_reaches_optional_execution_media_set() {
    let base = BaseImage::new(vec![0; 32]);
    let mut durable = CowOverlay::new();
    let mut checkpoint = state();
    checkpoint.require_execution_opportunities(true).unwrap();
    let request = BlockRequest::write(61, 4, b"stage".to_vec());
    let mut admission = ResolvedBlockFaultDirective::fault_free(&request, 32);
    admission.request_sequence = 900;
    admission.execution_ticks = 17;
    checkpoint.install(request.identity(), admission).unwrap();
    checkpoint
        .execute(&base, &mut durable, &request, 3)
        .unwrap();
    let opportunity = checkpoint.next_execution_opportunity(17).unwrap();
    let mut execution = opportunity.admission.clone();
    execution.media_rules.push(ResolvedBlockMediaRule {
        contributor: [2; 32],
        start: 0,
        length: 32,
        state: crate::block::media::BlockMediaRangeState::Bad,
        operations: vec![BlockOp::Write],
        count_threshold: None,
        time_threshold_nanos: None,
    });
    checkpoint
        .install_execution_directive(ResolvedBlockExecutionDirective {
            opportunity,
            directive: execution,
        })
        .unwrap();
    checkpoint.validate_restore(32).unwrap();

    let mut contributor_requests = 0;
    let refusal = checkpoint.validate_restore_with_admission(32, &mut |purpose| {
        if purpose == crate::DeviceSnapshotAllocation::ValidationContributor {
            contributor_requests += 1;
            Err("optional execution contributor refused")
        } else {
            Ok(())
        }
    });
    assert!(matches!(
        refusal,
        Err(DeviceError::InvalidBlockFaultDirective {
            reason: "optional execution contributor refused"
        })
    ));
    assert_eq!(contributor_requests, 1);
}

#[test]
fn retained_completion_borrowed_validation_preserves_codec_before_envelope_errors() {
    let identity = BlockRequestIdentity::new(7, 13);
    let payload = BlockResponse::ok_for(identity, vec![1, 2, 3])
        .encode()
        .unwrap();
    let completion = BlockRetainedCompletion {
        identity,
        recovery_response: Response::new(identity.request_id, ResponseStatus::Ok, payload.clone()),
        timeout_response: Response::new(identity.request_id, ResponseStatus::Ok, payload),
        request_icount: 0,
        additional_latency_ticks: 0,
        timeout_ticks: 0,
        recovery_event: None,
        recovery_after_ticks: None,
        recovery_after_sequence: None,
        persist_through_on_recovery: None,
    };
    let mut healthy = state();
    healthy.retained_completions.insert(identity, completion);
    assert_eq!(healthy.validate_restore(32), Ok(()));
    let encoded = healthy.to_canonical_bytes().unwrap();
    assert_eq!(
        BlockFaultState::from_canonical_bytes(&encoded, 32).unwrap(),
        healthy
    );

    for recovery in [true, false] {
        let mut invalid = healthy.clone();
        {
            let completion = invalid.retained_completions.get_mut(&identity).unwrap();
            let response = if recovery {
                &mut completion.recovery_response
            } else {
                &mut completion.timeout_response
            };
            response.status = ResponseStatus::Error;
            response.payload[1] = 255;
        }
        assert_eq!(
            invalid.validate_restore(32),
            Err(DeviceError::Codec(BlockCodecError::VersionMismatch {
                expected: BLOCK_ABI_VERSION,
                found: 255
            },))
        );
        {
            let completion = invalid.retained_completions.get_mut(&identity).unwrap();
            let response = if recovery {
                &mut completion.recovery_response
            } else {
                &mut completion.timeout_response
            };
            response.payload[1] = BLOCK_ABI_VERSION;
        }
        assert!(matches!(
            invalid.validate_restore(32),
            Err(DeviceError::InvalidBlockFaultDirective {
                reason: "restored retained completion payload differs from its envelope",
            })
        ));
    }
}
