//! Checks real ordinary Sources and the exact production result-range helper.
//!
//! A codec frame is ordinary DATA here, never a fabricated sealed completion.
//! Installed same-job/cancel/drain positives require the actual supervised route.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;

fn original(reactive: bool) -> PacketCompleteSemanticSource {
    let coordinator = fixture::coordinator();
    if reactive {
        PacketCompleteSemanticSource::new_reactive_for_collecting_world(
            fixture::installation(&coordinator, 1),
            fixture::reactive(&coordinator, 1),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    } else {
        PacketCompleteSemanticSource::new_producer_for_collecting_world(
            fixture::installation(&coordinator, 0),
            fixture::producer(),
            coordinator,
            fixture::storage_selection(),
        )
        .unwrap()
    }
}

#[test]
fn ordinary_originals_refuse_new_banks_without_creating_a_job_or_spending_birth() {
    for reactive in [false, true] {
        let mut source = original(reactive);
        let mut incoming = None;
        assert!(
            source
                .retain_native_import18_derivation_result_into(&mut incoming)
                .is_err()
        );
        assert!(source.native_import18_derived_banks_data().is_err());
        source.cancel_native_import18_derivation().unwrap();
        assert!(incoming.is_none());
        assert!(source.native_import18_derivation.is_none());
        assert!(source.native_import18_derivation_mechanism.is_none());
        assert!(source.native_import18_birth_construction.is_none());
        assert!(!source.ack_birth_attempted);
        assert_eq!(source.isolated_derivation_known_backing_data(0), Ok(0));
    }
}

#[test]
fn expected_world_views_borrow_the_same_independent_original() {
    use crate::node_adapters::cnp::source_birth_derivation::derive::ExpectedCoordinator;
    for reactive in [false, true] {
        let source = original(reactive);
        let (first, second) = match &source.original {
            CompletePacketOriginal::Producer(source) => (
                source.isolated_expected_coordinator_data(),
                source.isolated_expected_coordinator_data(),
            ),
            CompletePacketOriginal::Reactive(source) => (
                source.isolated_expected_coordinator_data(),
                source.isolated_expected_coordinator_data(),
            ),
        };
        match (first, second) {
            (ExpectedCoordinator::Producer(first), ExpectedCoordinator::Producer(second))
            | (ExpectedCoordinator::Reactive(first), ExpectedCoordinator::Reactive(second)) => {
                assert!(std::ptr::eq(first, second))
            }
            _ => panic!("genuine complete original lost its independent coordinator"),
        }
    }
}

#[test]
fn production_ranges_borrow_exact_original_frame_and_closed_limits_refuse_one_short() {
    let identity = ResultIdentity {
        task_digest: [1; 32],
        input_digest: [2; 32],
    };
    let source = b"source candidate";
    let registration = b"registration candidate";
    let header = result_wire::ResultHeader::success(identity, source, registration).unwrap();
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(source);
    frame.extend_from_slice(registration);
    let limits = result_wire::WireLimits {
        maximum_frame_bytes: frame.len(),
        maximum_diagnostic_bytes: 64,
    };
    let verified = result_wire::verify_stdout(&frame, identity, limits).unwrap();
    let [source_range, registration_range] = verified_bank_ranges(&verified).unwrap();
    assert_eq!(
        frame[source_range.clone()].as_ptr(),
        verified.source_bytes().as_ptr()
    );
    assert_eq!(
        frame[registration_range.clone()].as_ptr(),
        verified.registration_bytes().as_ptr()
    );
    assert_eq!(&frame[source_range], source);
    assert_eq!(&frame[registration_range], registration);
    assert!(
        result_wire::verify_stdout(
            &frame,
            identity,
            result_wire::WireLimits {
                maximum_frame_bytes: frame.len() - 1,
                ..limits
            }
        )
        .is_err()
    );
    assert!(
        result_wire::verify_stdout(
            &frame,
            ResultIdentity {
                task_digest: [3; 32],
                ..identity
            },
            limits
        )
        .is_err()
    );
}

#[test]
fn valid_failed_result_is_not_a_success_bank_range() {
    let identity = ResultIdentity {
        task_digest: [4; 32],
        input_digest: [5; 32],
    };
    let diagnostic = "actual worker refusal";
    let header = result_wire::ResultHeader::failure(
        identity,
        result_wire::FailureInfo::operational(result_wire::OperationalReason::RequestLimit),
        diagnostic,
        64,
    )
    .unwrap();
    let mut frame = header.encode().to_vec();
    frame.extend_from_slice(diagnostic.as_bytes());
    let verified = result_wire::verify_stdout(
        &frame,
        identity,
        result_wire::WireLimits {
            maximum_frame_bytes: frame.len(),
            maximum_diagnostic_bytes: 64,
        },
    )
    .unwrap();

    assert_eq!(verified.header(), &header);
    assert_eq!(verified.diagnostic(), diagnostic);
    assert!(verified.source_bytes().is_empty() && verified.registration_bytes().is_empty());
    assert_eq!(
        verified_bank_ranges(&verified),
        Err(RuntimeError::OwnerUnavailable)
    );
}
