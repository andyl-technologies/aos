//! Checks the actual publisher-state decision after a collected cohort.
//!
//! These factual state controls create no Source, subscriber or Native
//! grant. The full authenticated publisher driver remains a separate gate.

use super::*;

pub(super) fn current() -> PendingAction {
    PendingAction::from_observation_for_test(ActionObservation {
        binding: ActionBinding {
            cap: [1; 32],
            reservation: [2; 32],
            account_generation: 1,
            process_generation: 1,
            loan_sequence: 2,
            token: 0,
            capture: Some(1),
            park_request: None,
            frontier: 7,
        },
        primary_count: 2,
        row_count: 2,
        borrowed_mask: 3,
        projected_mask: 3,
        cohort_current: true,
        parents: [ActionParent::default(); 4],
    })
}

#[test]
fn equal_fresh_cohort_skips_only_already_current_rows() {
    let mut state = current();
    let binding = state.observation.binding;
    let fresh = state.observation.parents;

    assert!(state.matches_current_cohort(binding, &fresh, 2));
    state.observation.cohort_current = false;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    state.observation.cohort_current = true;
    state.returning = true;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
}

#[test]
fn one_owner_change_never_reuses_a_previous_cohort() {
    let state = current();
    let binding = state.observation.binding;
    let mut fresh = state.observation.parents;

    fresh[1].policy_revision = 1;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    fresh = state.observation.parents;
    fresh[0].state = 3;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    fresh = state.observation.parents;
    fresh[0].total_end_ns = 1;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));

    let mut another = binding;
    another.loan_sequence = 4;
    assert!(!state.matches_current_cohort(another, &fresh, 2));
}

#[test]
fn dirty_or_refused_no_capture_keeps_the_existing_membership() {
    let mut state = current();
    state.observation.binding.capture = None;
    let binding = state.observation.binding;
    let fresh = state.observation.parents;
    let retained_mask = state.observation.borrowed_mask;
    let projected_mask = state.observation.projected_mask;

    state.observation.cohort_current = false;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    assert_eq!(state.observation.borrowed_mask, retained_mask);
    assert_eq!(state.observation.projected_mask, projected_mask);
    assert_eq!(state.observation.binding, binding);

    state.observation.cohort_current = true;
    state.refused = true;
    assert!(!state.matches_current_cohort(binding, &fresh, 2));
    assert_eq!(state.observation.borrowed_mask, retained_mask);
    assert_eq!(state.observation.binding.capture, None);
}

#[test]
fn local_closure_preserves_partial_birth_and_unprojected_row_facts() {
    let mut action = current();
    action.observation.row_count = 4;
    action.observation.borrowed_mask = 3;
    action.observation.projected_mask = 1;
    action.observation.cohort_current = false;
    action.refused = true;
    let before = action.observation;

    assert!(action.close_unpublished().unwrap());
    assert!(action.close_unpublished().unwrap());

    assert_eq!(action.publication, PublicationPhase::LocallyClosed);
    assert_eq!(action.observation, before);
    assert!(action.verified_return.is_none());
    assert!(action.verified_park_return.is_none());
    assert!(!action.returning);
    assert!(action.begin_publication().is_err());
}

#[test]
fn actual_request_refusal_keeps_the_producer_unpublished() {
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let mut action = current();
    action.observation.cohort_current = false;

    let result =
        slot.request_control_boundary_with_publication(7, Some(1), |_| action.begin_publication());

    assert!(matches!(
        result,
        Err(crucible_qemu_shmem::ControlBoundaryPublicationError::Producer(_))
    ));
    assert_eq!(slot.control_boundary_token(), 1);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 0);
    assert_eq!(slot.control_boundary_capture_request(), None);
    assert_eq!(action.publication, PublicationPhase::Unpublished);
    assert!(action.close_unpublished().unwrap());
}

#[test]
fn unwind_after_the_actual_producer_cut_never_restores_unpublished_custody() {
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let mut action = current();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = slot.request_control_boundary_with_publication(
            7,
            Some(1),
            |_| -> Result<(), HostSupervisionError> {
                action.begin_publication()?;
                panic!("after the original producer's irreversible cut");
            },
        );
    }));

    assert!(result.is_err());
    assert_eq!(slot.control_boundary_token(), 1);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 0);
    assert_eq!(slot.control_boundary_capture_request(), None);
    assert_eq!(action.publication, PublicationPhase::Publishing);
    assert!(!action.close_unpublished().unwrap());
    assert_eq!(action.observation.borrowed_mask, 3);
    assert!(action.verified_return.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn real_eventfd_wake_failure_and_ack_cannot_return_published_membership() {
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let mut action = current();
    let wake = rustix::event::eventfd(
        0,
        rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
    )
    .unwrap();
    rustix::io::write(&wake, &(u64::MAX - 1).to_ne_bytes()).unwrap();

    let token = slot
        .request_control_boundary_with_publication(7, Some(1), |_| action.begin_publication())
        .unwrap();
    assert_eq!(token, 2);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 7);
    assert_eq!(slot.control_boundary_capture_request(), Some(1));
    // The same irreversible phase applies whether the later transport knows
    // publication returned or remains uncertain after a fallible wake.
    assert!(!action.close_unpublished().unwrap());
    action.record_publication().unwrap();
    assert_eq!(action.publication, PublicationPhase::Published);
    let wake_error = rustix::io::write(&wake, &1_u64.to_ne_bytes()).unwrap_err();
    assert_eq!(wake_error, rustix::io::Errno::AGAIN);
    assert_eq!(slot.acknowledge_control_boundary(), 3);

    assert!(!action.close_unpublished().unwrap());
    assert_eq!(action.observation.borrowed_mask, 3);
    assert!(action.verified_return.is_none());
}

#[test]
fn sampler_mutation_without_a_control_token_keeps_attempted_publication_debt() {
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let sampler = crucible_qemu_shmem::FingerprintSampleSlot::new();
    let mut action = current();

    action.begin_publication().unwrap();
    assert_eq!(sampler.request_fresh_capture_from_v1(0), Ok(1));

    assert_eq!(slot.control_boundary_token(), 1);
    assert_eq!(sampler.capture_request_generation(), 1);
    assert_eq!(action.publication, PublicationPhase::Publishing);
    assert!(!action.close_unpublished().unwrap());
    assert_eq!(action.observation.borrowed_mask, 3);
    assert!(action.verified_return.is_none());
}

#[test]
fn park_remains_outside_local_unpublished_return() {
    let mut action = current();
    action.observation.binding.capture = None;
    action.observation.binding.park_request = Some(9);
    action.publication = PublicationPhase::Published;

    assert!(action.close_unpublished().is_err());
    assert_eq!(action.publication, PublicationPhase::Published);
    assert_eq!(action.observation.borrowed_mask, 3);
    assert!(action.verified_park_return.is_none());
}

#[test]
fn missing_retained_action_refuses_before_actual_request_or_capture_publication() {
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let sampler = crucible_qemu_shmem::FingerprintSampleSlot::new();
    let mut action = None;

    let request = slot.request_control_boundary_with_publication(7, Some(1), |_| {
        publication::retained_action(&mut action)?.begin_publication()
    });
    let capture = publication::retained_action(&mut action).and_then(|action| {
        action.begin_publication()?;
        sampler
            .request_fresh_capture_from_v1(0)
            .map_err(|_| HostSupervisionError::Unavailable)
    });
    let completion =
        publication::retained_action(&mut action).and_then(PendingAction::record_publication);

    assert!(matches!(
        request,
        Err(
            crucible_qemu_shmem::ControlBoundaryPublicationError::Producer(
                HostSupervisionError::Unavailable
            )
        )
    ));
    assert!(matches!(capture, Err(HostSupervisionError::Unavailable)));
    assert!(matches!(completion, Err(HostSupervisionError::Unavailable)));
    assert!(action.is_none());
    assert_eq!(slot.control_boundary_token(), 1);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 0);
    assert_eq!(slot.control_boundary_capture_request(), None);
    assert_eq!(sampler.capture_request_generation(), 0);
}

fn pause_action() -> PendingAction {
    let mut action = current();
    action.observation.binding.capture = None;
    for parent in &mut action.observation.parents[..2] {
        parent.class = 6;
    }
    action
}

fn pause_header() -> crucible_qemu_shmem::RegionHeader {
    let layout =
        crucible_qemu_shmem::RegionLayout::for_config(crucible_qemu_shmem::RegionConfig::new(1, 8))
            .unwrap();
    crucible_qemu_shmem::RegionHeader::new(layout)
}

#[test]
fn terminal_or_unprojected_cohort_cannot_begin_an_effect() {
    for index in 0..4 {
        for state in 1..=3 {
            let mut action = pause_action();
            action.observation.row_count = 4;
            action.observation.borrowed_mask = 15;
            action.observation.projected_mask = 15;
            let binding = action.observation.binding;
            action.observation.parents[index].state = state;

            assert!(action.begin_pause_publication(binding).is_err());
            assert_eq!(action.publication, PublicationPhase::Unpublished);
            assert!(action.close_unpublished().unwrap());
        }
    }
    for count in [0, 5] {
        let mut action = pause_action();
        action.observation.row_count = count;

        assert!(action.begin_publication().is_err());
        assert_eq!(action.publication, PublicationPhase::Unpublished);
    }
    let mut action = pause_action();
    action.observation.projected_mask = 1;

    assert!(action.begin_publication().is_err());
    assert!(action.close_unpublished().unwrap());
}

#[test]
fn changed_pause_selector_or_lender_class_cannot_begin_an_effect() {
    for change in 0..5 {
        let mut action = pause_action();
        let mut binding = action.observation.binding;
        match change {
            0 => binding.loan_sequence += 2,
            1 => binding.capture = Some(1),
            2 => binding.park_request = Some(9),
            3 => action.observation.primary_count = 1,
            4 => action.observation.parents[1].class = 5,
            _ => unreachable!(),
        }

        assert!(action.begin_pause_publication(binding).is_err());
        assert_eq!(action.publication, PublicationPhase::Unpublished);
        assert!(action.close_unpublished().unwrap());
    }
}

#[test]
fn pause_header_and_scheduler_writes_keep_debt_before_any_token() {
    let header = pause_header();
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let mut action = pause_action();
    let binding = action.observation.binding;

    action.begin_pause_publication(binding).unwrap();
    header.request_pause([&slot]).unwrap();
    let ceiling = crucible_qemu_shmem::authorize_advance_ceiling(0, 17, None).unwrap();
    slot.publish_scheduler_advance(ceiling, crucible_qemu_shmem::AdvanceStopCondition::Ceiling)
        .unwrap();

    assert!(header.pause_requested());
    assert_eq!(slot.load_scheduler_advance().unwrap().0, 17);
    assert_eq!(slot.control_boundary_token(), 1);
    action.observation.parents[1].state = 3;
    assert!(action.begin_publication().is_err());
    assert_eq!(action.publication, PublicationPhase::Publishing);
    assert!(!action.close_unpublished().unwrap());
    assert!(action.verified_return.is_none());
    assert_eq!(action.observation.borrowed_mask, 3);
}

#[test]
fn unwind_after_pause_flag_cannot_reopen_local_return() {
    let header = pause_header();
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let mut action = pause_action();
    let binding = action.observation.binding;
    let before = slot.load_scheduler_advance().unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        action.begin_pause_publication(binding).unwrap();
        header.request_pause([&slot]).unwrap();
        panic!("after Pause visibility, before scheduler or token publication");
    }));

    assert!(result.is_err());
    assert!(header.pause_requested());
    assert_eq!(slot.load_scheduler_advance().unwrap(), before);
    assert_eq!(slot.control_boundary_token(), 1);
    assert_eq!(action.publication, PublicationPhase::Publishing);
    assert!(!action.close_unpublished().unwrap());
    assert!(action.verified_return.is_none());
}

#[test]
fn actual_scheduler_refusal_after_pause_flag_keeps_peer_only_debt() {
    let header = pause_header();
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let stale = crucible_qemu_shmem::authorize_advance_ceiling(0, 0, None).unwrap();
    let preceding = crucible_qemu_shmem::authorize_advance_ceiling(0, 1, None).unwrap();
    slot.publish_scheduler_advance(
        preceding,
        crucible_qemu_shmem::AdvanceStopCondition::Ceiling,
    )
    .unwrap();
    slot.publish_reached_icount(1).unwrap();
    let mut action = pause_action();
    let binding = action.observation.binding;

    action.begin_pause_publication(binding).unwrap();
    header.request_pause([&slot]).unwrap();
    let result =
        slot.publish_scheduler_advance(stale, crucible_qemu_shmem::AdvanceStopCondition::Ceiling);

    assert!(matches!(
        result,
        Err(crucible_qemu_shmem::NodeSlotError::CeilingBeforePublishedCurrent { .. })
    ));
    assert!(header.pause_requested());
    assert_eq!(slot.control_boundary_token(), 1);
    assert_eq!(action.publication, PublicationPhase::Publishing);
    assert!(!action.close_unpublished().unwrap());
    assert!(action.verified_return.is_none());
}

#[test]
fn missing_pause_action_refuses_before_header_or_scheduler_mutation() {
    let header = pause_header();
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let binding = pause_action().observation.binding;
    let mut action = None;
    let before = slot.load_scheduler_advance().unwrap();

    let result = publication::retained_action(&mut action).and_then(|action| {
        action.begin_pause_publication(binding)?;
        header
            .request_pause([&slot])
            .map_err(|_| HostSupervisionError::Unavailable)?;
        let ceiling = crucible_qemu_shmem::authorize_advance_ceiling(0, 17, None)
            .map_err(|_| HostSupervisionError::Unavailable)?;
        slot.publish_scheduler_advance(ceiling, crucible_qemu_shmem::AdvanceStopCondition::Ceiling)
            .map_err(|_| HostSupervisionError::Unavailable)
    });

    assert!(matches!(result, Err(HostSupervisionError::Unavailable)));
    assert!(action.is_none());
    assert!(!header.pause_requested());
    assert_eq!(slot.snapshot().wake_signal, 0);
    assert_eq!(slot.load_scheduler_advance().unwrap(), before);
    assert_eq!(slot.control_boundary_token(), 1);
}

#[test]
fn matching_pending_untyped_request_cannot_acquire_producing_membership() {
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let token = slot.request_control_boundary(7, Some(1)).unwrap();
    let request = RequestIdentity::Control {
        token,
        capture: Some(1),
    };

    assert_eq!(slot.preview_action_token(7, Some(1)), Ok(token));
    assert!(matches!(
        request.require_unpublished_request(&slot),
        Err(HostSupervisionError::BorrowedOperation)
    ));
    assert_eq!(slot.control_boundary_token(), token);
    assert_eq!(slot.control_boundary_fault_command_frontier(), 7);
    assert_eq!(slot.control_boundary_capture_request(), Some(1));
    assert!(!slot.action_frontier_is_retained());
}

#[test]
fn action_birth_requires_next_unpublished_token_and_unoccupied_real_frontier() {
    let slot = crucible_qemu_shmem::NodeSlot::new(crucible_qemu_shmem::KIND_VM);
    let next = RequestIdentity::Control {
        token: 2,
        capture: None,
    };
    let stale = RequestIdentity::Control {
        token: 0,
        capture: None,
    };

    assert!(next.require_unpublished_request(&slot).is_ok());
    assert!(matches!(
        stale.require_unpublished_request(&slot),
        Err(HostSupervisionError::BorrowedOperation)
    ));
    slot.retain_action_frontier(12).unwrap();

    assert!(matches!(
        next.require_unpublished_request(&slot),
        Err(HostSupervisionError::BorrowedOperation)
    ));
    assert_eq!(slot.control_boundary_token(), 1);
    assert!(slot.action_frontier_is_retained());
    assert!(slot.release_action_frontier(14).is_err());
    slot.release_action_frontier(12).unwrap();
    assert!(next.require_unpublished_request(&slot).is_ok());
}

#[test]
fn exhausted_actual_control_token_cannot_authorize_a_wrapped_action_birth()
-> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::os::fd::AsFd;

    for (acknowledged, token, accepted) in
        [(u32::MAX - 2, u32::MAX - 1, true), (u32::MAX, 0, false)]
    {
        let allocation = crucible_qemu_shmem::RegionAllocation::new_model(
            crucible_qemu_shmem::RegionConfig::new(1, 2),
        )?;
        let layout = allocation.layout();
        let mut initial = allocation.setup_region_bytes()?;
        let offset = usize::try_from(layout.node_slots_off)?
            + crucible_qemu_shmem::NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET;
        initial[offset..offset + 4].copy_from_slice(&acknowledged.to_ne_bytes());
        let mut shmem = std::fs::File::from(crate::spawn::memfd_region(layout.region_size)?);
        shmem.write_all(&initial)?;
        let mapping = crucible_qemu_shmem::mmap_setup_region(shmem.as_fd(), layout.region_size)?;
        let slot = mapping.node_slot(0)?;
        let before = slot.snapshot();
        let request = RequestIdentity::Control {
            token,
            capture: None,
        };

        let result = request.require_unpublished_request(slot);

        if accepted {
            result?;
        } else {
            assert_eq!(result, Err(HostSupervisionError::BorrowedOperation));
        }
        assert_eq!(slot.snapshot(), before);
        assert!(!slot.action_frontier_is_retained());
    }
    Ok(())
}
