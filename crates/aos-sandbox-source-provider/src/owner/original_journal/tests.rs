//! UNRUN custody-parking vectors; genuine complete Source writer fixtures remain missing.

use super::*;
use aos_sandbox::JournalRecord;

fn input(id: u8) -> JournalTransaction {
    JournalTransaction::new([id; 16], vec![JournalRecord::put(
        RecordNamespace::SourceProviderAuthority, vec![id], vec![id + 1],
    )]).unwrap()
}

#[test]
fn input_and_observed_packet_are_parked_before_source_or_sandbox_checks() {
    let transaction = input(1);
    let mut owners = Some(transaction.clone());
    let mut controls = Some(OriginalSourceControlInputsV5::retain(None, None,
        Some(ObservedOriginalQueryV5 {
            packet: CurrentProviderOriginalCarrierPacketV1::Source(vec![9; 12]),
            session: None, failed: false,
        })));
    let mut slot = None;

    PreparedSourceOriginalV5::park(&mut owners, &mut controls, &mut slot).unwrap();
    let retained = slot.as_mut().unwrap();
    assert!(owners.is_none());
    assert!(controls.is_none());
    assert_eq!(retained.owners.as_ref(), Some(&transaction));
    assert_eq!(retained.controls.as_ref().unwrap().query.as_ref().unwrap().bytes().unwrap(), &[9; 12]);
    retained.failed = true;
    assert_eq!(retained.owners.as_ref(), Some(&transaction));
}

#[test]
fn occupied_slot_latches_failure_and_does_not_consume_incoming_input() {
    let mut owners = Some(input(1));
    let mut controls = None;
    let mut slot = None;
    PreparedSourceOriginalV5::park(&mut owners, &mut controls, &mut slot).unwrap();
    let incoming = input(2);
    owners = Some(incoming.clone());
    controls = Some(OriginalSourceControlInputsV5::retain(None, None, None));

    assert!(PreparedSourceOriginalV5::park(&mut owners, &mut controls, &mut slot).is_err());
    assert_eq!(owners.as_ref(), Some(&incoming));
    assert!(controls.is_some());
    assert!(slot.as_ref().unwrap().failed);
    assert_eq!(slot.as_ref().unwrap().owners.as_ref(), Some(&input(1)));
}

#[test]
fn stale_or_failed_query_retains_exact_packet_but_cannot_supply_context() {
    let session = ObjectDigest::from_bytes([1; 32]);
    let controls = OriginalSourceControlInputsV5::retain(None, None, Some(ObservedOriginalQueryV5 {
        packet: CurrentProviderOriginalCarrierPacketV1::Source(vec![2; 20]),
        session: Some(session), failed: true,
    }));

    assert!(observed_query_bytes(Some(&controls), session).is_err());
    assert_eq!(controls.query.as_ref().unwrap().bytes().unwrap(), &[2; 20]);
    assert!(observed_query_bytes(Some(&controls), ObjectDigest::from_bytes([3; 32])).is_err());
}

#[test]
fn first_birth_cannot_substitute_an_empty_ingress_or_later_control_inputs() {
    let ingress = super::super::original_ingress::OriginalIngressV1::default();
    let controls = OriginalSourceControlInputsV5::retain(None, None, None);

    assert!(original_pair_inputs(true, &ingress, Some(&controls)).is_err());
    assert!(original_pair_inputs(false, &ingress, Some(&controls)).is_err());
    assert!(ingress.borrowed_pair_v5().is_err());
    assert!(!OriginalJournalV5::default().history.baseline_pending);
}

// These vectors exercise the actual metadata latch used by owner cleanup.
// They do not construct a genuine Session, protected owner or parked runtime.
#[test]
fn pending_first_birth_failure_preserves_identity_for_repeated_cleanup() {
    for already_failed in [false, true] {
        let mut original = OriginalJournalHistoryV5 {
            baseline_pending: true,
            failed: already_failed,
            ..OriginalJournalHistoryV5::default()
        };

        assert!(original.fail_pending_baseline());

        assert!(original.failed);
        assert!(original.baseline_pending);
        assert!(original.fail_pending_baseline());
        assert!(original.baseline_pending);
    }
}

#[test]
fn completed_historical_baseline_is_not_failed_by_first_birth_cleanup() {
    let mut original = OriginalJournalHistoryV5::default();

    assert!(!original.fail_pending_baseline());

    assert!(!original.failed);
    assert!(!original.baseline_pending);

    original.failed = true;
    assert!(!original.fail_pending_baseline());
    assert!(original.failed);
}

#[test]
fn completed_baseline_preserves_retained_metadata_and_releases_failure_identity() {
    let acquisition = ObjectDigest::from_bytes([7; 32]);
    let mut original = OriginalJournalHistoryV5 {
        baseline_pending: true,
        projection_bytes: 123,
        ..OriginalJournalHistoryV5::default()
    };
    original.admissions.insert(acquisition, ([8; 16], 9));

    original.complete_baseline();

    assert!(!original.baseline_pending);
    assert!(!original.failed);
    assert_eq!(original.projection_bytes, 123);
    assert_eq!(original.admissions.get(&acquisition), Some(&([8; 16], 9)));
    assert!(!original.fail_pending_baseline());
    assert!(!original.failed);
}
