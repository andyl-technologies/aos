//! Conservation tests for global operational and retained physical admission.

use super::*;
use crucible_linux_resource::ram_policy::{HostRamTarget, HostResourceVector};

fn owner_target(epoch: DaemonEpoch, execution: ExecutionId) -> HostRamTarget {
    HostRamTarget {
        daemon_epoch: crate::host_operational_registry::operational_identity(epoch.as_bytes()),
        owner_id: crate::host_operational_registry::operational_identity(execution.as_bytes()),
        node_id: [0x42; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    }
}

fn node_resources() -> HostResourceVector {
    HostResourceVector {
        resident_peak_bytes: 1024,
        backing_peak_bytes: 2048,
        metadata_bytes: 32,
        staging_bytes: 32,
        paging_io_slots: 2,
        cpu_slots: 1,
        task_slots: 8,
        file_descriptors: 64,
    }
}

fn supervisor() -> LocalExecutorSupervisor<MemoryAssignmentLedger, AllowAllAttemptAdmission> {
    LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        daemon_epoch(0x81),
        ExecutorCapacity::new(4, 8, 8 * 1024 * 1024, 16384, 64).expect("physical capacity"),
    )
    .with_host_operational_capacity(
        HostOperationalCapacity::new(2, 8, 64, 512, 512).expect("explicit operational capacity"),
    )
    .expect("install operational capacity")
}

#[test]
fn authored_assignment_peak_is_reserved_before_any_node_launch() {
    let epoch = daemon_epoch(0x81);
    let vector = HostResourceVector {
        resident_peak_bytes: 2 * 1024 * 1024,
        ..node_resources()
    };
    let mut actor = supervisor()
        .with_host_assignment_resources(vector, resources(1, 1024, 2048), 1024 * 1024)
        .expect("authored assignment entitlement");
    let small = request(0x91, 0xa1, epoch, resources(1, 512, 1024));
    let execution = accepted_execution(&actor.submit_attempt(&small).expect("first assignment"));
    let target = owner_target(epoch, execution);

    assert_eq!(actor.used.resident_bytes, vector.resident_peak_bytes);
    assert_eq!(actor.used.disk_bytes, vector.backing_peak_bytes);
    assert_eq!(
        actor.host_operational_used.paging_io_slots,
        vector.paging_io_slots
    );
    assert_eq!(
        actor
            .host_ram_owner_ceiling(target.daemon_epoch, target.owner_id)
            .expect("live bound"),
        HostResourceVector {
            resident_peak_bytes: vector.resident_peak_bytes - 1024 * 1024,
            task_slots: vector.task_slots - 1,
            ..vector
        }
    );
    let second = request(0x92, 0xa2, epoch, resources(1, 512, 1024));
    assert!(!matches!(
        actor
            .submit_attempt(&second)
            .expect("admission refusal")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));

    actor
        .release_active(execution)
        .expect("empty physical ledger permits release");
    assert_eq!(actor.used.resident_bytes, 0);
    assert_eq!(actor.host_operational_used.paging_io_slots, 0);
    assert_eq!(actor.host_operational_used.task_slots, 0);
    assert_eq!(actor.host_operational_used.file_descriptors, 0);
    let replacement = request(0x93, 0xa3, epoch, resources(1, 512, 1024));
    assert!(matches!(
        actor
            .submit_attempt(&replacement)
            .expect("replacement")
            .disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
}

#[test]
fn service_headroom_is_atomic_and_does_not_charge_the_future_assignment() {
    let mut actor = supervisor();
    let held = node_resources();
    let unavailable_assignment = held;
    assert!(
        actor
            .reserve_host_ram_service_with_assignment_headroom(
                [0x71; 32],
                held,
                unavailable_assignment
            )
            .is_err()
    );
    assert!(actor.host_service_resources.is_empty());
    assert_eq!(actor.used.resident_bytes, 0);

    let mut service = held;
    service.paging_io_slots = 1;
    service.task_slots = 4;
    service.file_descriptors = 32;
    let mut actor = actor
        .with_host_assignment_resources(
            HostResourceVector {
                resident_peak_bytes: 2 * 1024 * 1024,
                ..service
            },
            resources(1, 1024, 2048),
            1024 * 1024,
        )
        .expect("authored assignment headroom");
    let smaller_assignment = HostResourceVector {
        cpu_slots: 0,
        ..service
    };
    assert!(
        actor
            .reserve_host_ram_service_with_assignment_headroom(
                [0x71; 32],
                service,
                smaller_assignment,
            )
            .is_err()
    );
    assert!(actor.host_service_resources.is_empty());
    let assignment = actor.host_assignment_resources.expect("authored vector").0;
    actor
        .reserve_host_ram_service_with_assignment_headroom([0x71; 32], service, assignment)
        .expect("service and future assignment both fit");
    assert_eq!(actor.used.resident_bytes, service.resident_peak_bytes);
    assert_eq!(
        actor.host_operational_used.paging_io_slots,
        service.paging_io_slots
    );
}

#[test]
fn admitted_child_service_uses_existing_charge_without_speculative_assignment() {
    let epoch = daemon_epoch(0x81);
    let service = HostResourceVector {
        paging_io_slots: 1,
        task_slots: 4,
        file_descriptors: 32,
        ..node_resources()
    };
    let assignment = HostResourceVector {
        resident_peak_bytes: 2 * 1024 * 1024,
        ..service
    };
    let mut actor = supervisor()
        .with_host_assignment_resources(assignment, resources(1, 1024, 2048), 1024 * 1024)
        .expect("authored assignment");
    let request = request(0x91, 0xa1, epoch, resources(1, 512, 1024));
    let execution = accepted_execution(&actor.submit_attempt(&request).expect("child assignment"));
    let existing_owner = owner_target(epoch, execution).owner_id;

    assert!(
        actor
            .reserve_host_ram_service_with_admitted_assignment([0x71; 32], service, existing_owner)
            .is_err()
    );
    actor.next_queued().expect("actual active child worker");
    assert!(
        actor
            .reserve_host_ram_service_with_assignment_headroom([0x71; 32], service, assignment)
            .is_err()
    );
    actor
        .reserve_host_ram_service_with_admitted_assignment([0x71; 32], service, existing_owner)
        .expect("existing child and independent source fit");

    assert_eq!(
        actor.used.resident_bytes,
        assignment.resident_peak_bytes + service.resident_peak_bytes
    );
    assert_eq!(
        actor.used.disk_bytes,
        assignment.backing_peak_bytes + service.backing_peak_bytes
    );
    assert_eq!(actor.host_operational_used.paging_io_slots, 2);
    assert_eq!(actor.host_service_resources.len(), 1);
}

#[test]
fn admitted_child_service_refuses_unknown_and_canceled_owner_without_mutation() {
    let epoch = daemon_epoch(0x81);
    let service = HostResourceVector {
        paging_io_slots: 1,
        task_slots: 4,
        file_descriptors: 32,
        ..node_resources()
    };
    let assignment = HostResourceVector {
        resident_peak_bytes: 2 * 1024 * 1024,
        ..service
    };
    let mut actor = supervisor()
        .with_host_assignment_resources(assignment, resources(1, 1024, 2048), 1024 * 1024)
        .expect("authored assignment");
    let request = request(0x91, 0xa1, epoch, resources(1, 512, 1024));
    let execution = accepted_execution(&actor.submit_attempt(&request).expect("child assignment"));
    let queued = actor.next_queued().expect("active child");
    queued.cancellation().cancel();
    let original = actor.host_resource_availability();

    for existing_owner in [[0x99; 32], owner_target(epoch, execution).owner_id] {
        assert!(
            actor
                .reserve_host_ram_service_with_admitted_assignment(
                    [0x71; 32],
                    service,
                    existing_owner
                )
                .is_err()
        );
        assert_eq!(actor.host_resource_availability(), original);
        assert!(actor.host_service_resources.is_empty());
    }
}

#[test]
fn operational_admission_requires_explicit_deployed_capacity() {
    let epoch = daemon_epoch(0x81);
    let mut actor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        AllowAllAttemptAdmission,
        epoch,
        ExecutorCapacity::new(4, 8, 8192, 16384, 64).expect("capacity"),
    );
    let assignment = request(0x91, 0xa1, epoch, resources(1, 2048, 4096));
    let execution = accepted_execution(&actor.submit_attempt(&assignment).expect("assignment"));
    let target = owner_target(epoch, execution);

    assert!(
        actor
            .configure_host_ram_owner(target.daemon_epoch, target.owner_id, node_resources())
            .is_err()
    );
    assert!(actor.host_ram_resources.is_empty());
}

#[test]
fn global_paging_task_and_descriptor_limits_are_independent() {
    for dimension in 0..3 {
        let mut actor = supervisor();
        let epoch = daemon_epoch(0x81);
        let first = request(0x91, 0xa1, epoch, resources(1, 2048, 4096));
        let execution =
            accepted_execution(&actor.submit_attempt(&first).expect("first assignment"));
        let target = owner_target(epoch, execution);
        let mut first_resources = node_resources();
        first_resources.paging_io_slots = if dimension == 0 { 2 } else { 1 };
        first_resources.task_slots = if dimension == 1 { 8 } else { 1 };
        first_resources.file_descriptors = if dimension == 2 { 64 } else { 1 };
        actor
            .configure_host_ram_owner(target.daemon_epoch, target.owner_id, first_resources)
            .expect("first owner");
        let second = request(0x92, 0xa2, epoch, resources(1, 2048, 4096));
        let second_execution = accepted_execution(
            &actor
                .submit_attempt(&second)
                .expect("physical capacity available"),
        );
        let second_target = owner_target(epoch, second_execution);
        let mut second_resources = first_resources;
        second_resources.paging_io_slots = 1;
        second_resources.task_slots = 1;
        second_resources.file_descriptors = 1;

        assert!(
            actor
                .configure_host_ram_owner(
                    second_target.daemon_epoch,
                    second_target.owner_id,
                    second_resources
                )
                .is_err()
        );
        assert!(!actor.host_ram_resources.contains_key(&second_execution));
        actor
            .release_active(execution)
            .expect("release unused first partition");
        actor
            .configure_host_ram_owner(
                second_target.daemon_epoch,
                second_target.owner_id,
                second_resources,
            )
            .expect("returned operational capacity");
    }
}

#[test]
fn finished_execution_keeps_physical_template_and_service_charges_until_cleanup() {
    let mut actor = supervisor();
    let epoch = daemon_epoch(0x81);
    let assignment = request(0x91, 0xa1, epoch, resources(1, 2048, 4096));
    let execution = accepted_execution(&actor.submit_attempt(&assignment).expect("assignment"));
    let target = owner_target(epoch, execution);
    let held = node_resources();
    actor
        .configure_host_ram_owner(target.daemon_epoch, target.owner_id, held)
        .expect("complete owner partition");
    actor
        .admit_host_ram_node(target, held)
        .expect("physical node");

    actor
        .release_active(execution)
        .expect("complete modeled execution");

    assert!(!actor.active.contains_key(&execution));
    assert_eq!(actor.used.vcpus, 1);
    assert_eq!(actor.used.resident_bytes, 1024);
    assert_eq!(actor.used.disk_bytes, 2048);
    assert_eq!(actor.host_operational_used.task_slots, 8);
    assert_eq!(actor.host_operational_used.file_descriptors, 64);
    assert_eq!(actor.host_retained_resources.get(&execution), Some(&held));
    let next = request(0x92, 0xa2, epoch, resources(1, 2048, 4096));
    let next_execution =
        accepted_execution(&actor.submit_attempt(&next).expect("new modeled slot"));
    let next_target = owner_target(epoch, next_execution);
    assert!(
        actor
            .configure_host_ram_owner(next_target.daemon_epoch, next_target.owner_id, held)
            .is_err()
    );

    actor
        .release_host_ram_node_after_cleanup(target)
        .expect("proved native and service cleanup");

    assert_eq!(actor.used.resident_bytes, 2048);
    assert_eq!(actor.used.disk_bytes, 4096);
    assert_eq!(actor.host_operational_used.task_slots, 0);
    assert_eq!(actor.host_operational_used.file_descriptors, 0);
    assert!(actor.host_retained_resources.is_empty());
    actor
        .configure_host_ram_owner(next_target.daemon_epoch, next_target.owner_id, held)
        .expect("physical capacity reusable after cleanup");
    assert!(actor.release_host_ram_node_after_cleanup(target).is_err());
}

#[test]
fn active_cleanup_retains_the_assignment_partition_until_completion() {
    let mut actor = supervisor();
    let epoch = daemon_epoch(0x81);
    let assignment = request(0x91, 0xa1, epoch, resources(1, 2048, 4096));
    let execution = accepted_execution(&actor.submit_attempt(&assignment).expect("assignment"));
    let target = owner_target(epoch, execution);
    let held = node_resources();
    actor
        .configure_host_ram_owner(target.daemon_epoch, target.owner_id, held)
        .expect("owner");
    actor.admit_host_ram_node(target, held).expect("node");
    actor
        .release_host_ram_node_after_cleanup(target)
        .expect("first replay cleanup");

    assert_eq!(actor.used.resident_bytes, 2048);
    assert_eq!(actor.host_operational_used.task_slots, 8);
    let replacement = HostRamTarget {
        arena_generation: 2,
        owner_generation: 2,
        ..target
    };
    actor
        .admit_host_ram_node(replacement, held)
        .expect("replacement replay inside existing partition");
    actor
        .release_host_ram_node_after_cleanup(replacement)
        .expect("replacement cleanup");
    actor
        .release_active(execution)
        .expect("complete assignment");

    assert_eq!(actor.used.resident_bytes, 0);
    assert_eq!(actor.host_operational_used.task_slots, 0);
    assert!(actor.host_retained_resources.is_empty());
}

#[test]
fn preparation_service_has_real_global_charge_and_requires_physical_cleanup() {
    let mut actor = supervisor();
    let service = [0xf1; 32];
    let held = node_resources();
    actor
        .reserve_host_ram_service(service, held)
        .expect("real service entitlement");
    let target = HostRamTarget {
        daemon_epoch: crate::host_operational_registry::operational_identity(
            daemon_epoch(0x81).as_bytes(),
        ),
        owner_id: service,
        node_id: [0x42; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    actor
        .configure_host_ram_owner(target.daemon_epoch, service, held)
        .expect("same configured service partition");
    actor
        .admit_host_ram_node(target, held)
        .expect("preparation physical node");

    assert_eq!(actor.used.resident_bytes, 1024);
    assert_eq!(actor.host_operational_used.task_slots, 8);
    assert!(actor.active.is_empty());
    assert!(
        actor
            .release_host_ram_service_after_cleanup(service)
            .is_err()
    );
    assert!(actor.reserve_host_ram_service([0xf2; 32], held).is_err());

    actor
        .release_host_ram_node_after_cleanup(target)
        .expect("service node actual cleanup");
    assert_eq!(actor.used.resident_bytes, 1024);
    actor
        .release_host_ram_service_after_cleanup(service)
        .expect("service completion after native cleanup");

    assert_eq!(actor.used.resident_bytes, 0);
    assert_eq!(actor.host_operational_used.task_slots, 0);
    assert!(
        actor
            .release_host_ram_service_after_cleanup(service)
            .is_err()
    );
    actor
        .reserve_host_ram_service([0xf2; 32], held)
        .expect("returned complete service capacity");
}

#[test]
fn zero_guest_disk_allowance_keeps_separate_positive_host_backing_charge() {
    let vector = HostResourceVector {
        resident_peak_bytes: 2 * 1024 * 1024,
        ..node_resources()
    };
    let original = resources(1, 512, 0);
    let mut actor = supervisor()
        .with_host_assignment_resources(vector, original, 1024 * 1024)
        .expect("independent physical and request ceilings");
    assert_eq!(actor.assignment_resource_limits(), Some(original));
    let assignment = request(0x91, 0xa1, daemon_epoch(0x81), original);
    let execution = accepted_execution(
        &actor
            .submit_attempt(&assignment)
            .expect("zero guest disk request"),
    );
    assert_eq!(actor.used.disk_bytes, vector.backing_peak_bytes);
    actor
        .release_active(execution)
        .expect("complete empty physical owner");
    assert_eq!(actor.used.disk_bytes, 0);
}
