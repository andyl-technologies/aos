//! Selects native diagnostic types for canonical saved Source family work.

use super::*;

type H = crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1;
type R = crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
pub(super) type SourceFamilySinksV1<'a> = aos_sandbox_ledger_replay::replay::source_tree_successor::retained::SourceFamilySinksV1<'a, JournalError, H, R>;
pub(super) type SourceFamilyOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_successor::retained::SourceFamilyOriginalsV1<JournalError, H, R>;
pub(in crate::journal) type SourceReplayFamilyOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_successor::SourceReplayFamilyOriginalsV1<JournalError, H, R>;

#[cfg(test)]
mod tests {
    use super::*;

    fn ack(project: ProjectId) -> SourceFirstSuccessorAckV2 {
        SourceFirstSuccessorAckV2::new(aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorAckFieldsV2 {
            instance: [1; 32],
            project,
            receipt: ObjectDigest::from_bytes([3; 32]),
            root_floor: ObjectDigest::from_bytes([4; 32]),
            controller_anchored: ObjectDigest::from_bytes([5; 32]),
        }).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from).unwrap()
    }

    #[test]
    fn native_state_validator_keeps_orphan_successor_map_and_cause() {
        let project = ProjectId::from_bytes([2; 16]);
        let original = ack(project);
        let mut state = State::new();
        state.insert((RecordNamespace::DesiredState, ack_key(project)), original.as_bytes().to_vec());
        assert!(validate_replayed_state(&state, false).is_err());

        let mut destination = None;
        assert!(super::super::super::validate_replayed_source_state(
            &state, false, true, &mut destination,
        ).is_err());
        let retained = destination.as_ref().unwrap();
        assert_eq!(retained.family.rows.as_ref().unwrap().acks.get(&project), Some(&original));
        let cause = retained.failure().unwrap() as *const JournalError;

        assert!(super::super::super::validate_replayed_source_state(
            &State::new(), false, true, &mut destination,
        ).is_err());
        assert_eq!(destination.as_ref().unwrap().failure().unwrap() as *const JournalError, cause);
    }

    #[test]
    fn native_key_refusal_keeps_the_actual_decoded_successor() {
        let original = ack(ProjectId::from_bytes([2; 16]));
        let mut state = State::new();
        state.insert((RecordNamespace::DesiredState, ack_key(ProjectId::from_bytes([9; 16]))),
            original.as_bytes().to_vec());
        let mut retained = SourceReplayFamilyOriginalsV1::new();

        assert!(retained.observe_once(&state).is_err());
        assert_eq!(retained.family.ack.as_ref(), Some(&original));
        assert!(retained.family.rows.as_ref().unwrap().acks.is_empty());
        assert!(SourceReplayFamilyOriginalsV1::fixed_footprint_v1().is_some());
    }

    #[test]
    fn complete_native_state_disposes_only_its_positive_comparison_destination() {
        let mut destination = None;
        super::super::super::validate_replayed_source_state(
            &State::new(), false, true, &mut destination,
        ).unwrap();
        assert!(destination.is_none());

        // The ordinary branch neither creates a selected destination nor
        // changes acceptance of the same complete empty Source state.
        super::super::super::validate_replayed_source_state(
            &State::new(), false, false, &mut destination,
        ).unwrap();
        assert!(destination.is_none());
    }

    #[test]
    fn actual_pending_selector_keeps_the_returned_error_in_the_native_original() {
        let project = ProjectId::from_bytes([2; 16]);
        let mut state = State::new();
        state.insert((RecordNamespace::DesiredState, receipt_key(project)), vec![1]);
        state.insert((RecordNamespace::DesiredState, PENDING_KEY.to_vec()), vec![0]);
        let input = state.clone();
        assert!(replay_family(&state).is_err());
        let mut original = SourceReplayFamilyOriginalsV1::new();

        assert!(original.observe_once(&state).is_err());
        assert!(matches!(original.result, Some(Err(JournalError::ProtectedBoundary))));
        assert!(original.selected.is_none());
        assert!(original.family.rows.is_none());
        assert_eq!(state, input);
        let cause = original.failure().unwrap() as *const JournalError;

        assert!(original.observe_once(&State::new()).is_err());
        assert_eq!(original.failure().unwrap() as *const JournalError, cause);
    }

    #[test]
    fn actual_ack_map_transfer_remains_owned_on_later_family_refusal() {
        let project = ProjectId::from_bytes([2; 16]);
        let ack = ack(project);
        let mut state = State::new();
        state.insert((RecordNamespace::DesiredState, ack_key(project)), ack.as_bytes().to_vec());
        let mut original = SourceReplayFamilyOriginalsV1::new();

        assert!(original.observe_once(&state).is_err());
        assert_eq!(original.family.rows.as_ref().unwrap().acks.get(&project), Some(&ack));
        assert!(original.family.ack.is_none());
        assert!(original.failure().is_some());
    }

    #[test]
    fn lazy_source_diagnostics_keep_the_same_cause_and_reached_ack() {
        let project = ProjectId::from_bytes([2; 16]);
        let actual_ack = ack(project);
        let mut state = State::new();
        state.insert(
            (RecordNamespace::DesiredState, ack_key(ProjectId::from_bytes([9; 16]))),
            actual_ack.as_bytes().to_vec(),
        );
        let mut inline = SourceReplayFamilyOriginalsV1::new();
        let mut lazy = None;

        assert!(validate_replayed_state_with_originals(&state, false, Some(&mut inline)).is_err());
        assert!(super::super::super::validate_replayed_source_state(
            &state, false, true, &mut lazy,
        ).is_err());

        let retained = lazy.as_ref().unwrap();
        assert_eq!(retained.family.ack, inline.family.ack);
        assert_eq!(retained.family.ack.as_ref(), Some(&actual_ack));
        let expected = inline.cause().unwrap();
        let observed = retained.cause().unwrap();
        assert_eq!(observed.is::<JournalError>(), expected.is::<JournalError>());
        assert_eq!(observed.is::<H>(), expected.is::<H>());
        assert_eq!(observed.is::<R>(), expected.is::<R>());
        assert_eq!(format!("{observed:?}"), format!("{expected:?}"));
        let first = observed as *const dyn std::error::Error;

        // Moving the scratch destination and refusing reentry retain the same
        // original allocation, decoded prefix and first typed cause.
        let mut transferred = lazy.take();
        assert!(super::super::super::validate_replayed_source_state(
            &State::new(), false, true, &mut transferred,
        ).is_err());
        assert!(std::ptr::eq(first, transferred.as_ref().unwrap().cause().unwrap()));
        assert_eq!(transferred.as_ref().unwrap().family.ack.as_ref(), Some(&actual_ack));
    }

    #[test]
    fn ordinary_source_replay_keeps_diagnostic_destination_empty() {
        let mut destination = None;

        super::super::super::validate_replayed_source_state(
            &State::new(), false, false, &mut destination,
        ).unwrap();

        assert!(destination.is_none());
    }

    #[test]
    fn lazy_source_invoice_keeps_both_constructor_and_resident_planes() {
        let (family, family_cells) = SourceReplayFamilyOriginalsV1::fixed_footprint_v1().unwrap();
        let (boxed_family, boxed_family_cells) = SourceReplayFamilyOriginalsV1::boxed_footprint_v1().unwrap();
        let (transition, transition_cells) = SourceReplayTransactionOriginalsV1::fixed_footprint_v1().unwrap();
        let (boxed_transition, boxed_transition_cells) = SourceReplayTransactionOriginalsV1::boxed_footprint_v1().unwrap();
        let layout = std::mem::size_of::<std::alloc::Layout>();

        assert!(family >= 2 * std::mem::size_of::<SourceReplayFamilyOriginalsV1>());
        assert!(transition >= 2 * std::mem::size_of::<SourceReplayTransactionOriginalsV1>());
        assert_eq!(boxed_family, family + layout
            + std::mem::size_of::<SourceReplayFamilyOriginalsV1>()
            + std::mem::size_of::<Option<Box<SourceReplayFamilyOriginalsV1>>>());
        assert_eq!(boxed_transition, transition + layout
            + std::mem::size_of::<SourceReplayTransactionOriginalsV1>()
            + std::mem::size_of::<Option<Box<SourceReplayTransactionOriginalsV1>>>());
        assert_eq!(boxed_family_cells, family_cells);
        assert_eq!(boxed_transition_cells, transition_cells);
        assert_eq!(super::super::super::source_native_family_fixed_footprint_v1().unwrap().0,
            boxed_family + boxed_transition);
    }

}
