//! Original-bound, one-shot initial process issuance controls.

// crucible-lint: allow panic-shortcut -- fixed accounting fixtures panic only on invalid modeled setup or the deliberate caught-unwind control; they grant no native resources.

use super::*;
use crucible_linux_resource::host_supervision::HostOperationBudgets;
use std::time::Duration;

fn resources() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 512 * 1024 * 1024,
        backing_peak_bytes: 1024 * 1024 * 1024,
        metadata_bytes: 16 * 1024 * 1024,
        staging_bytes: 8 * 1024 * 1024,
        paging_io_slots: 2,
        cpu_slots: 1,
        task_slots: 64,
        file_descriptors: 128,
    }
}

fn target() -> HostRamTarget {
    HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    }
}

fn original() -> HostOperationSupervisor {
    HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(300)),
    )
    .unwrap_or_else(|error| panic!("modeled original supervisor: {error}"))
}

fn single(original: HostOperationSupervisor) -> ConfiguredProcessFamily {
    let partition = HostRamProcessFamilyPartition::single(resources())
        .unwrap_or_else(|error| panic!("modeled single partition: {error}"));
    ConfiguredProcessFamily::new(partition, original)
}

#[test]
fn a_second_generation_cannot_receive_the_complete_family_again() {
    let mut family = single(original());
    let initial = target();
    let admitted = family
        .prepare_initial(initial)
        .unwrap_or_else(|error| panic!("modeled initial issuance: {error}"));
    assert_eq!(admitted, resources());
    assert!(family.verify_initial(initial, admitted).is_ok());

    let mut replacement = initial;
    replacement.owner_generation += 1;
    replacement.arena_generation += 1;
    assert!(family.prepare_initial(replacement).is_err());
    assert!(family.prepare_initial(initial).is_err());
    assert!(family.verify_initial(replacement, admitted).is_err());
}

#[test]
fn stage_headroom_is_reserved_before_initial_issuance() {
    let floor = HostResourceVector {
        resident_peak_bytes: 128 * 1024 * 1024,
        backing_peak_bytes: 256 * 1024 * 1024,
        metadata_bytes: 4 * 1024 * 1024,
        staging_bytes: 2 * 1024 * 1024,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 8,
        file_descriptors: 32,
    };
    let partition = HostRamProcessFamilyPartition::with_staged(resources(), floor, floor)
        .unwrap_or_else(|error| panic!("modeled staged partition: {error}"));
    let mut family = ConfiguredProcessFamily::new(partition, original());
    let admitted = family
        .prepare_initial(target())
        .unwrap_or_else(|error| panic!("modeled initial issuance: {error}"));
    assert_eq!(
        admitted.resident_peak_bytes,
        resources().resident_peak_bytes - floor.resident_peak_bytes
    );
    assert_eq!(
        admitted.file_descriptors,
        resources().file_descriptors - floor.file_descriptors
    );
    assert!(family.verify_initial(target(), resources()).is_err());
    assert!(family.verify_initial(target(), admitted).is_ok());
}

#[test]
fn original_cancellation_refuses_issuance_and_later_verification() {
    let original = original();
    let mut family = single(original.clone());
    let admitted = family
        .prepare_initial(target())
        .unwrap_or_else(|error| panic!("modeled initial issuance: {error}"));
    original
        .cancel()
        .unwrap_or_else(|error| panic!("modeled cancellation: {error}"));
    assert!(family.verify_initial(target(), admitted).is_err());

    let mut unused = single(original);
    assert!(unused.prepare_initial(target()).is_err());
    assert!(!unused.is_issued());
}

#[test]
fn caught_unwind_after_issuance_does_not_reopen_the_assignment() {
    let mut family = single(original());
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(family.prepare_initial(target()).is_ok());
        panic!("modeled caller failed after issuance");
    }));
    assert!(caught.is_err());
    assert!(family.is_issued());
    assert!(family.prepare_initial(target()).is_err());
}

fn staged(original: HostOperationSupervisor) -> ConfiguredProcessFamily {
    let floor = HostResourceVector {
        resident_peak_bytes: 128 * 1024 * 1024,
        backing_peak_bytes: 256 * 1024 * 1024,
        metadata_bytes: 4 * 1024 * 1024,
        staging_bytes: 2 * 1024 * 1024,
        paging_io_slots: 1,
        cpu_slots: 1,
        task_slots: 8,
        file_descriptors: 32,
    };
    let partition = HostRamProcessFamilyPartition::with_staged(resources(), floor, floor)
        .unwrap_or_else(|error| panic!("modeled staged partition: {error}"));
    ConfiguredProcessFamily::new(partition, original)
}

#[test]
fn a_stage_requires_its_predeclared_subset_and_issued_parent() {
    let mut single = single(original());
    single.prepare_initial(target()).unwrap();
    assert!(
        single
            .prepare_staged(target(), 2, &stage_services(), &stage_contract())
            .is_err()
    );
    assert!(single.staged.is_none());

    let mut family = staged(original());
    assert!(
        family
            .prepare_staged(target(), 2, &stage_services(), &stage_contract())
            .is_err()
    );
    assert!(family.staged.is_none());
    family.prepare_initial(target()).unwrap();
    let operation = family
        .prepare_staged(target(), 2, &stage_services(), &stage_contract())
        .unwrap();
    assert!(family.verify_staged(&operation).is_ok());
    assert!(operation.verify_original().is_ok());
}

#[test]
fn a_foreign_parent_or_reused_arena_cannot_occupy_the_stage() {
    let mut family = staged(original());
    family.prepare_initial(target()).unwrap();
    let mut foreign = target();
    foreign.node_id = [4; 32];
    assert!(
        family
            .prepare_staged(foreign, 2, &stage_services(), &stage_contract())
            .is_err()
    );
    assert!(
        family
            .prepare_staged(target(), 0, &stage_services(), &stage_contract())
            .is_err()
    );
    assert!(
        family
            .prepare_staged(target(), 1, &stage_services(), &stage_contract())
            .is_err()
    );
    assert!(family.staged.is_none());
    assert!(
        family
            .prepare_staged(target(), 2, &stage_services(), &stage_contract())
            .is_ok()
    );
}

#[test]
fn dropping_or_unwinding_a_stage_coordinate_does_not_release_escrow() {
    let mut family = staged(original());
    family.prepare_initial(target()).unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let operation = family
            .prepare_staged(target(), 2, &stage_services(), &stage_contract())
            .unwrap();
        assert!(family.verify_staged(&operation).is_ok());
        drop(operation);
        panic!("modeled caller unwinds after obtaining its stage coordinate");
    }));
    assert!(caught.is_err());
    assert!(family.staged.is_some());
    assert!(
        family
            .prepare_staged(target(), 3, &stage_services(), &stage_contract())
            .is_err()
    );
}

#[test]
fn family_original_cancellation_refuses_a_stage_and_its_existing_coordinate() {
    let original = original();
    let mut issued = staged(original.clone());
    issued.prepare_initial(target()).unwrap();
    let operation = issued
        .prepare_staged(target(), 2, &stage_services(), &stage_contract())
        .unwrap();
    let mut unissued = staged(original.clone());
    unissued.prepare_initial(target()).unwrap();

    original.cancel().unwrap();
    assert!(issued.verify_staged(&operation).is_err());
    assert!(operation.verify_original().is_err());
    assert!(
        unissued
            .prepare_staged(target(), 2, &stage_services(), &stage_contract())
            .is_err()
    );
    assert!(unissued.staged.is_none());
    assert!(issued.staged.is_some());
}

#[test]
fn equal_target_scalars_do_not_substitute_another_original_family() {
    let mut first = staged(original());
    let mut second = staged(original());
    first.prepare_initial(target()).unwrap();
    second.prepare_initial(target()).unwrap();
    let first_operation = first
        .prepare_staged(target(), 2, &stage_services(), &stage_contract())
        .unwrap();
    let second_operation = second
        .prepare_staged(target(), 2, &stage_services(), &stage_contract())
        .unwrap();
    assert!(first.verify_staged(&first_operation).is_ok());
    assert!(second.verify_staged(&second_operation).is_ok());
    assert!(first.verify_staged(&second_operation).is_err());
    assert!(second.verify_staged(&first_operation).is_err());
}

fn stage_services() -> crucible_linux_resource::host_services::HostServiceAllocator {
    crucible_linux_resource::host_services::HostServiceAllocator::new(1, 1, 16 * 1024).unwrap()
}

#[test]
fn exhausted_stage_control_refuses_before_occupying_the_assignment() {
    let mut family = staged(original());
    family.prepare_initial(target()).unwrap();
    let services =
        crucible_linux_resource::host_services::HostServiceAllocator::new(1, 1, 1).unwrap();
    assert!(
        family
            .prepare_staged(target(), 2, &services, &stage_contract())
            .is_err()
    );
    assert!(family.staged.is_none());
    assert!(
        family
            .prepare_staged(target(), 2, &stage_services(), &stage_contract())
            .is_ok()
    );
}

// These descriptors model event custody only; they validate no cgroup or native
// process entitlement. Production assembly selects its actual admitted host.
fn stage_contract() -> crucible_qemu::QemuChildProcessContract {
    let event = || {
        rustix::event::eventfd(
            0,
            rustix::event::EventfdFlags::CLOEXEC | rustix::event::EventfdFlags::NONBLOCK,
        )
        .unwrap()
    };
    crucible_qemu::QemuChildProcessContract::from_unvalidated_test_descriptors(
        event(),
        event(),
        1,
        resources().resident_peak_bytes,
        resources().backing_peak_bytes,
    )
}

#[test]
fn issuer_keeps_the_actual_quiescence_after_coordinate_drop() {
    let original = original();
    let mut family = staged(original.clone());
    family.prepare_initial(target()).unwrap();
    let operation = family
        .prepare_staged(target(), 2, &stage_services(), &stage_contract())
        .unwrap();
    operation.verify_parent(&target()).unwrap();
    let first = stage_guard_observation(&operation, |guard| {
        guard.serialize_original_quiescence_basis()
    })
    .unwrap();
    assert_eq!(&first[..8], b"CRUCPAU1");
    assert_eq!(
        first,
        stage_guard_observation(&operation, |guard| guard
            .serialize_original_quiescence_basis())
        .unwrap()
    );
    assert!(
        stage_guard_observation(&operation, |guard| guard.wait_slice()).unwrap()
            <= Duration::from_secs(300)
    );
    assert_eq!(
        operation
            .with_quiescence(|guard| guard.status().unwrap().class)
            .unwrap(),
        (
            crucible_linux_resource::host_supervision::HostOperationClass::Quiescence,
            None
        )
    );
    let mut foreign = target();
    foreign.node_id = [9; 32];
    assert!(operation.verify_parent(&foreign).is_err());
    drop(operation);

    let entered = original.operation_statuses().unwrap();
    assert_eq!(entered.len(), 1);
    assert_eq!(
        entered[0].class,
        crucible_linux_resource::host_supervision::HostOperationClass::Quiescence
    );
    drop(family);
    assert!(original.operation_statuses().unwrap().is_empty());
}

#[test]
fn actual_process_event_cancellation_refuses_the_retained_stage() {
    let original = original();
    let mut family = staged(original);
    family.prepare_initial(target()).unwrap();
    let contract = stage_contract();
    let event = contract.try_clone_cancellation_event().unwrap();
    let operation = family
        .prepare_staged(target(), 2, &stage_services(), &contract)
        .unwrap();
    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();
    assert!(operation.verify_original().is_err());
    assert!(stage_guard_observation(&operation, |guard| guard.wait_slice()).is_err());
    assert!(
        stage_guard_observation(&operation, |guard| guard
            .serialize_original_quiescence_basis())
        .is_err()
    );
    assert!(family.verify_staged(&operation).is_err());
    assert!(family.staged.is_some());
}

#[test]
fn a_signalled_event_preserves_the_entered_first_cause_and_terminal_issuer() {
    let original = original();
    let mut family = staged(original.clone());
    family.prepare_initial(target()).unwrap();
    let contract = stage_contract();
    let event = contract.try_clone_cancellation_event().unwrap();
    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();
    let refusal = match family.prepare_staged(target(), 2, &stage_services(), &contract) {
        Ok(_) => panic!("signalled process event must refuse"),
        Err(refusal) => refusal,
    };
    assert!(matches!(refusal, StagePrepareError::Entered { .. }));
    assert!(std::error::Error::source(&refusal).is_some());
    assert!(family.staged.is_some());
    assert_eq!(original.operation_statuses().unwrap().len(), 1);
    assert!(
        family
            .prepare_staged(target(), 3, &stage_services(), &stage_contract())
            .is_err()
    );
    drop(refusal);
    assert_eq!(original.operation_statuses().unwrap().len(), 1);
}

#[test]
fn borrowed_stage_effect_keeps_its_outcome_and_independent_cancellation_post() {
    let original = original();
    let mut family = staged(original.clone());
    family.prepare_initial(target()).unwrap();
    let operation = family
        .prepare_staged(target(), 2, &stage_services(), &stage_contract())
        .unwrap();
    let (outcome, after) = operation
        .with_quiescence(|_guard| {
            original.cancel().unwrap();
            Err::<(), _>(std::io::Error::from_raw_os_error(5))
        })
        .unwrap();
    assert_eq!(outcome.unwrap_err().raw_os_error(), Some(5));
    assert!(after.is_some());
    assert!(stage_guard_observation(&operation, |guard| guard.wait_slice()).is_err());
    assert!(family.staged.is_some());
}

#[test]
fn terminal_entered_event_refuses_publication_while_family_cap_remains_live() {
    let original = original();
    let family = staged(original.clone());
    let contract = stage_contract();
    let event = contract.try_clone_cancellation_event().unwrap();
    let (mut record, operation) = StagedProcessAssignment::prepare(
        family.partition,
        target(),
        target(),
        2,
        &original,
        &stage_services(),
    )
    .unwrap();
    record.enter(&contract).unwrap();

    rustix::io::write(&event, &1_u64.to_ne_bytes()).unwrap();
    assert!(original.verify_original_live().is_ok());
    let refusal = match record.finish_entry(Ok(()), operation) {
        Ok(_) => panic!("terminal entered event must refuse final publication"),
        Err(refusal) => refusal,
    };
    assert!(matches!(refusal, StagePrepareError::Entered { .. }));
    assert!(std::error::Error::source(&refusal).is_some());
}

// Exercises the same fixed retained guard path used by the provider. The
// callback result remains primary while its independent original post is read.
fn stage_guard_observation<T>(
    operation: &ConfiguredStageOperation,
    observe: impl FnOnce(
        &crucible_linux_resource::host_supervision::HostOperationGuard,
    )
        -> Result<T, crucible_linux_resource::host_supervision::HostSupervisionError>,
) -> Result<T, crucible_linux_resource::host_supervision::HostSupervisionError> {
    let (outcome, after) = operation.with_quiescence(observe)?;
    let value = outcome?;
    match after {
        Some(source) => Err(source),
        None => Ok(value),
    }
}

#[test]
fn retained_stage_requires_the_actual_process_attempt_on_revalidation() {
    let mut family = staged(original());
    family.prepare_initial(target()).unwrap();
    let contract = stage_contract();
    let operation = family
        .prepare_staged(target(), 2, &stage_services(), &contract)
        .unwrap();
    let duplicate = contract.try_clone_for_attempt_generation().unwrap();
    let foreign = stage_contract();

    assert!(operation.verify_process_contract(&duplicate).is_ok());
    assert!(operation.verify_process_contract(&foreign).is_err());
    assert!(family.verify_staged(&operation).is_ok());
    drop(contract);
    assert!(operation.verify_process_contract(&duplicate).is_ok());
    assert!(
        family
            .prepare_staged(target(), 3, &stage_services(), &duplicate)
            .is_err()
    );
}
