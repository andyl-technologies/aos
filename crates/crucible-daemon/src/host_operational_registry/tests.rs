//! Behavioral qualification for durable live policy and cap authority.

// crucible-lint: allow panic-shortcut -- component fixtures panic to localize failed authority and durable-history assumptions.
#![allow(clippy::unwrap_used)]

use crucible_linux_resource::host_supervision::{HostOperationBudgets, HostOperationClass};
use crucible_linux_resource::ram_policy::HostResourceLedger;

use super::*;
use crucible_protocol::ram_control::RamControlOwnerInventory;

struct Admission(Mutex<HostResourceLedger>);

impl HostResourceAdmission for Admission {
    fn repartition_node_before_cpu(
        &self,
        target: HostRamTarget,
        expected_initial: HostResourceVector,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        self.0
            .lock()
            .unwrap()
            .repartition_before_execution(target, expected_initial, resources)
            .map_err(unavailable)
    }

    fn release_after_cleanup(&self, target: HostRamTarget) -> Result<(), HostOperationalError> {
        self.0
            .lock()
            .unwrap()
            .release_after_cleanup(target)
            .map_err(unavailable)
    }

    fn configure_owner(
        &self,
        _daemon: [u8; 32],
        _owner: [u8; 32],
        _ceiling: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        Ok(())
    }

    fn admit_node(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), HostOperationalError> {
        let mut ledger = self.0.lock().unwrap();
        if ledger.owner_reservation(target).is_some() {
            return Ok(());
        }
        ledger.admit(target, resources).map_err(unavailable)
    }

    fn begin_transition(
        &self,
        target: HostRamTarget,
        amendment: HostReservationAmendment,
    ) -> Result<HostResourceTransition, HostOperationalError> {
        self.0
            .lock()
            .unwrap()
            .begin_transition(
                target,
                amendment.expected_reservation_revision,
                amendment.requested,
                amendment.transition_peak,
            )
            .map_err(unavailable)
    }

    fn finish_transition(
        &self,
        transition: HostResourceTransition,
    ) -> Result<(), HostOperationalError> {
        self.0
            .lock()
            .unwrap()
            .finish_transition(transition)
            .map_err(unavailable)
    }
}

struct Fixture {
    registry: HostOperationalRegistry,
    admission: Arc<Admission>,
    target: HostRamTarget,
    cap: HostOuterCapTarget,
    principal: String,
    policy: HostRamPolicy,
    supervisor: HostOperationSupervisor,
    _directory: tempfile::TempDir,
}

fn placement_reply(status: &HostRamStatus) -> RamControlReply {
    RamControlReply {
        disposition: crucible_protocol::ram_control::RamControlDisposition::Accepted,
        requested_policy_revision: status.policy_revision,
        applied_policy_revision: status.applied_policy_revision,
        reservation_revision: status.reservation_revision,
        logical_ram_bytes: 4096,
        inventory: None,
        inventory_region: None,
        observation_sequence: status.observation_sequence,
        effective_resident_target_bytes: status.effective_resident_target_bytes,
        effective_floor_bytes: status.effective_floor_bytes,
        limitation_reasons: 0,
        measurements_available: false,
        private_resident_bytes: 0,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 0,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        convergence: crucible_protocol::ram_control::RamControlConvergence::Applying,
        activity: None,
        fault_actor: None,
        operation_failure: None,
        kernel_probe: None,
        placement_receipt: None,
    }
}

#[test]
fn placement_projection_keeps_old_applied_cut_while_new_policy_is_pending() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let owner = fixture.registry.node(fixture.target).unwrap();
    let mut status = output::copy_status(&owner.state.lock().unwrap()).unwrap();
    status.policy_revision = 2;
    status.applied_policy_revision = 1;
    status.applied_policy.mode = HostRamMode::DiskOriented;
    let mut requested = status.requested_policy;
    requested.mode = HostRamMode::ResidentRequired;
    let mut reply = placement_reply(&status);
    reply.placement_receipt = Some(crucible_protocol::ram_control::RamControlPlacementReceipt {
        mode: crucible_protocol::ram_control::RamControlMode::DiskOriented,
        policy_revision: 1,
        topology_generation: 7,
        placement_epoch: 9,
        locked_bytes: 0,
        disk_preserved_logical_pages: 1,
        disk_preserved_logical_bytes: 4096,
        ram_write_generation_at_cut: 11,
    });

    mutation::observe_reply(&mut status, reply, requested, 2).unwrap();

    assert_eq!(status.applied_policy_revision, 1);
    assert_eq!(status.applied_policy.mode, HostRamMode::DiskOriented);
    let receipt = status.placement_receipt.unwrap();
    assert_eq!(receipt.policy_revision, 1);
    assert_eq!(receipt.topology_generation, 7);
    assert_eq!(receipt.placement_epoch, 9);
    assert_eq!(receipt.ram_write_generation_at_cut, 11);
}

#[test]
fn placement_projection_refuses_inconsistent_receipts_before_status_changes() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let owner = fixture.registry.node(fixture.target).unwrap();
    let mut baseline = output::copy_status(&owner.state.lock().unwrap()).unwrap();
    baseline.policy_revision = 2;
    baseline.applied_policy_revision = 1;
    baseline.applied_policy.mode = HostRamMode::DiskOriented;
    let mut requested = baseline.requested_policy;
    requested.mode = HostRamMode::ResidentRequired;
    for case in 0..5 {
        let mut status = output::copy_status(&baseline).unwrap();
        let mut reply = placement_reply(&status);
        let mut receipt = crucible_protocol::ram_control::RamControlPlacementReceipt {
            mode: crucible_protocol::ram_control::RamControlMode::DiskOriented,
            policy_revision: 1,
            topology_generation: 7,
            placement_epoch: 9,
            locked_bytes: 0,
            disk_preserved_logical_pages: 1,
            disk_preserved_logical_bytes: 4096,
            ram_write_generation_at_cut: 11,
        };
        match case {
            0 => reply.applied_policy_revision = 0,
            1 => reply.applied_policy_revision = 3,
            2 => receipt.policy_revision = 2,
            3 => receipt.mode = crucible_protocol::ram_control::RamControlMode::ResidentRequired,
            4 => receipt.topology_generation = 0,
            _ => unreachable!(),
        }
        reply.placement_receipt = Some(receipt);

        assert!(matches!(
            mutation::observe_reply(&mut status, reply, requested, 2),
            Err(HostOperationalError::Unavailable)
        ));
        assert_eq!(status, baseline);
    }
}

#[test]
fn independent_cap_amendment_does_not_wait_for_a_busy_ram_policy_authority() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let owner = fixture.registry.node(fixture.target).unwrap();
    let _busy_policy = owner.mutation.lock().unwrap();

    let response = fixture
        .registry
        .execute(
            &fixture.principal,
            HostOperationalRequest::AmendOuterCap {
                target: fixture.cap,
                expected_cap_revision: 0,
                idempotency_key: [99; 32],
                allowance: Some(Duration::from_secs(120)),
            },
        )
        .unwrap();

    assert!(matches!(
        response.value(),
        HostOperationalResponse::OuterCapAmendment {
            disposition: HostOperationalDisposition::Accepted,
            accepted_cap_revision: Some(1),
            ..
        }
    ));
    assert_eq!(
        fixture.supervisor.outer_cap_status().unwrap().allowance,
        Some(Duration::from_secs(120))
    );
}

#[test]
fn saturated_control_query_retains_authority_and_authenticated_session() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    use crucible_protocol::ram_control::{
        RamControlConvergence, RamControlDisposition, RamControlMessage,
        ram_control_request_digest, read_ram_control, write_ram_control,
    };
    use std::os::unix::net::UnixStream;

    let fixture = fixture(64 * 1024);
    let owner = fixture.registry.node(fixture.target).unwrap();
    let initial = output::copy_status(&owner.state.lock().unwrap()).unwrap();
    let reply = RamControlReply {
        placement_receipt: None,
        disposition: RamControlDisposition::Accepted,
        requested_policy_revision: initial.policy_revision,
        applied_policy_revision: initial.policy_revision,
        reservation_revision: initial.reservation_revision,
        logical_ram_bytes: 64,
        inventory: None,
        inventory_region: None,
        observation_sequence: 1,
        effective_resident_target_bytes: 64,
        effective_floor_bytes: 32,
        limitation_reasons: 0,
        measurements_available: false,
        private_resident_bytes: 0,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 0,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        convergence: RamControlConvergence::Stable,
        activity: None,
        fault_actor: None,
        operation_failure: None,
        kernel_probe: None,
    };
    let (host, mut peer) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        // A refused local query must send no frame and consume no sequence.
        for _ in 0..2 {
            let mut frame = read_ram_control(&mut peer).unwrap().unwrap();
            frame.message = RamControlMessage::Reply {
                request_digest: ram_control_request_digest(&frame).unwrap(),
                state: reply,
            };
            write_ram_control(&mut peer, &frame).unwrap();
        }
    });
    let client = RamControlClient::connect_supervised(
        host,
        [4; 32],
        fixture.target,
        fixture.supervisor.clone(),
    )
    .unwrap();
    *owner.client.lock().unwrap() = Some(client);
    let guards = (0..crucible_linux_resource::host_supervision::MAX_HOST_OPERATIONS)
        .map(|_| {
            fixture
                .supervisor
                .begin(HostOperationClass::Cleanup)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let cached = fixture.registry.status(&owner).unwrap();
    assert_ne!(cached.convergence, HostRamConvergence::Quarantined);
    assert_eq!(
        fixture.supervisor.outer_cap_status().unwrap().state,
        HostOperationState::Running
    );

    drop(guards);
    let observed = fixture.registry.status(&owner).unwrap();
    assert_eq!(observed.convergence, HostRamConvergence::Stable);
    server.join().unwrap();
}

#[test]
fn busy_status_transport_refuses_policy_without_canceling_the_owner() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let owner = fixture.registry.node(fixture.target).unwrap();
    let _status_borrower = owner.client.lock().unwrap();
    let response = fixture
        .registry
        .execute(
            &fixture.principal,
            HostOperationalRequest::UpdatePolicy {
                target: fixture.target,
                expected_policy_revision: 0,
                idempotency_key: [98; 32],
                policy: Box::new(fixture.policy),
                reservation_amendment: None,
            },
        )
        .unwrap();

    assert!(matches!(
        response.value(),
        HostOperationalResponse::PolicyUpdate {
            disposition: HostOperationalDisposition::Unavailable,
            accepted_policy: None,
            ..
        }
    ));
    assert_eq!(
        fixture.supervisor.outer_cap_status().unwrap().state,
        HostOperationState::Running
    );
    assert_eq!(owner.state.lock().unwrap().policy_revision, 0);
}

#[test]
fn busy_native_transport_refuses_cap_amendment_without_partial_host_application() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let owner = fixture.registry.node(fixture.target).unwrap();
    let borrower = owner.client.lock().unwrap();
    let request = HostOperationalRequest::AmendOuterCap {
        target: fixture.cap,
        expected_cap_revision: 0,
        idempotency_key: [97; 32],
        allowance: Some(Duration::from_secs(120)),
    };
    let response = fixture
        .registry
        .execute(&fixture.principal, request.clone())
        .unwrap();

    assert!(matches!(
        response.value(),
        HostOperationalResponse::OuterCapAmendment {
            disposition: HostOperationalDisposition::Unavailable,
            accepted_cap_revision: None,
            accepted_allowance: None,
            ..
        }
    ));
    assert_eq!(fixture.supervisor.outer_cap_status().unwrap().revision, 0);
    drop(borrower);
    assert_eq!(
        fixture
            .registry
            .execute(&fixture.principal, request)
            .unwrap(),
        response
    );
    assert_eq!(fixture.supervisor.outer_cap_status().unwrap().revision, 0);
}

#[test]
fn inventory_requires_live_kernel_authority_and_ledger_subsets_remain_bounded() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    use crucible_api::host_operational::{
        HostRamInventoryLimits as Limits, HostRamInventoryRegion as RegionDescriptor,
        HostRamInventoryRegionClass as RegionClass, HostRamInventoryTopology as Topology,
    };

    let directory = tempfile::tempdir().unwrap();
    let registry = HostOperationalRegistry::open_component(directory.path(), 1024 * 1024)
        .unwrap()
        .with_component_metadata_budget(crucible::owned_decode::current_budget().unwrap())
        .unwrap();
    registry
        .configure_bootstrap_limits(
            crucible_api::vm_lifecycle::HostRamBootstrapLimits::new(4, 10, 1, 1, 8 * 1024 * 1024)
                .unwrap(),
        )
        .unwrap();
    let main_bytes = 1024 * 1024;
    let mut initial =
        crucible_qemu::ram_admission::known_ram_launch_requirements(main_bytes, 1).unwrap();
    initial.resident_peak_bytes += 64 * 1024 * 1024;
    initial.backing_peak_bytes = 1024 * 1024 * 1024;
    initial.cpu_slots = 1;
    initial.task_slots = 5;
    initial.file_descriptors = 11;
    let ceiling = HostResourceVector {
        metadata_bytes: 64 * 1024 * 1024,
        staging_bytes: 8 * 1024 * 1024,
        ..initial
    };
    let ledger = Arc::new(Admission(Mutex::new(HostResourceLedger::new(ceiling))));
    registry.attach_admission(ledger.clone()).unwrap();
    let target = HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    registry.admit_node(target, initial).unwrap();
    let topology = Topology::new(
        vec![
            RegionDescriptor::new("main", RegionClass::MutableMain, main_bytes).unwrap(),
            RegionDescriptor::new("device", RegionClass::MutableDevice, 16 * 1024 * 1024).unwrap(),
        ],
        Limits::default(),
    )
    .unwrap();

    let owner_resources = RamControlOwnerInventory {
        existing_tasks: 3,
        existing_file_descriptors: 6,
        registered_service_tasks: 1,
        prospective_tasks: 1,
        prospective_file_descriptors: 4,
    };
    let admission = RamInventoryAdmission {
        target,
        expected_initial: initial,
        declared_ram_bytes: main_bytes,
        topology: &topology,
        native_metadata_bytes: 8 * 1024 * 1024,
        native_scratch_bytes: 32 * 1024,
        owner_resources,
    };
    assert!(
        registry
            .admit_inventory(RamInventoryAdmission {
                owner_resources: RamControlOwnerInventory {
                    prospective_tasks: 2,
                    ..owner_resources
                },
                ..admission
            })
            .is_err()
    );
    assert!(
        registry
            .admit_inventory(RamInventoryAdmission {
                owner_resources: RamControlOwnerInventory {
                    prospective_file_descriptors: 5,
                    ..owner_resources
                },
                ..admission
            })
            .is_err()
    );

    assert!(matches!(
        registry.admit_inventory(admission),
        Err(RamControlError::AuthorityMismatch)
    ));
    assert_eq!(
        ledger
            .0
            .lock()
            .unwrap()
            .owner_reservation(target)
            .unwrap()
            .1,
        initial
    );

    // The pure ledger transition is independently verifiable. A genuine native
    // inventory grant additionally needs the retained cgroup/quota authority.
    let required = crucible_qemu::ram_admission::actual_inventory_ram_requirements(
        &topology,
        admission.native_metadata_bytes,
        admission.native_scratch_bytes,
        1,
    )
    .unwrap();
    let granted = HostResourceVector {
        metadata_bytes: initial.metadata_bytes.max(required.metadata_bytes),
        staging_bytes: initial.staging_bytes.max(required.staging_bytes),
        ..initial
    };
    registry
        .repartition_node_before_cpu(target, initial, granted)
        .unwrap();

    assert!(granted.metadata_bytes > initial.metadata_bytes);
    assert!(granted.staging_bytes > initial.staging_bytes);
    assert_eq!(granted.resident_peak_bytes, initial.resident_peak_bytes);
    assert_eq!(granted.backing_peak_bytes, initial.backing_peak_bytes);
    assert_eq!(granted.cpu_slots, initial.cpu_slots);
    assert_eq!(granted.task_slots, initial.task_slots);
    assert_eq!(granted.file_descriptors, initial.file_descriptors);
    assert!(registry.admit_inventory(admission).is_err());
    assert!(
        registry
            .admit_inventory(RamInventoryAdmission {
                expected_initial: granted,
                native_metadata_bytes: u64::MAX,
                ..admission
            })
            .is_err()
    );
}

#[test]
fn target_discovery_is_owner_bound_and_excludes_retired_arenas() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let target = fixture.target;
    let request = HostOperationalRequest::ListTargets {
        target: HostRamOwnerTarget {
            daemon_epoch: target.daemon_epoch,
            owner_id: target.owner_id,
        },
        after: None,
        limit: 1,
    };
    assert_eq!(
        fixture.registry.execute("ungranted", request.clone()),
        Err(HostOperationalError::PrincipalDenied)
    );
    assert!(
        matches!(fixture.registry.execute(&fixture.principal, request).unwrap().value(),
        HostOperationalResponse::Targets { targets, next: None, .. } if targets.as_slice() == [target])
    );

    assert_eq!(
        fixture
            .registry
            .registered_targets(target.daemon_epoch, target.owner_id, None, 1)
            .unwrap(),
        (vec![target], None)
    );
    assert_eq!(
        fixture
            .registry
            .registered_targets(target.daemon_epoch, target.owner_id, Some(target), 1)
            .unwrap(),
        (Vec::new(), None)
    );
    assert!(
        fixture
            .registry
            .registered_targets(target.daemon_epoch, target.owner_id, None, 0)
            .is_err()
    );
    let foreign = HostRamTarget {
        owner_id: [77; 32],
        ..target
    };
    assert!(
        fixture
            .registry
            .registered_targets(target.daemon_epoch, target.owner_id, Some(foreign), 1)
            .is_err()
    );

    fixture.registry.retire_node(target).unwrap();

    assert_eq!(
        fixture
            .registry
            .registered_targets(target.daemon_epoch, target.owner_id, None, 32)
            .unwrap(),
        (Vec::new(), None)
    );
}

fn fixture(history_bytes: u64) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let registry = HostOperationalRegistry::open_component(directory.path(), history_bytes)
        .unwrap()
        .with_component_metadata_budget(crucible::owned_decode::current_budget().unwrap())
        .unwrap();
    let principal = "a".repeat(64);
    registry.grant_principal(&principal).unwrap();
    let resources = HostResourceVector {
        resident_peak_bytes: 96,
        backing_peak_bytes: 256,
        metadata_bytes: 8,
        staging_bytes: 8,
        paging_io_slots: 2,
        cpu_slots: 1,
        task_slots: 8,
        file_descriptors: 16,
    };
    let admission = Arc::new(Admission(Mutex::new(HostResourceLedger::new(resources))));
    registry.attach_admission(admission.clone()).unwrap();
    let target = HostRamTarget {
        daemon_epoch: [1; 32],
        owner_id: [2; 32],
        node_id: [3; 32],
        owner_generation: 1,
        arena_generation: 1,
        retained_template: false,
    };
    let supervisor = HostOperationSupervisor::new(
        HostOperationBudgets::default(),
        Some(Duration::from_secs(60)),
    )
    .unwrap();
    let policy = HostRamPolicy {
        mode: HostRamMode::Managed,
        resident_target_bytes: 64,
        eviction_preference: 0,
        writeback_bytes_per_second: 64,
        maximum_paging_io_in_flight: 1,
        prefetch_on_increase: false,
        latency: HostOperationBudgets::default(),
    };
    registry
        .register_cap(
            HostOuterCapTarget {
                daemon_epoch: target.daemon_epoch,
                owner: HostOuterCapOwner::Execution(target.owner_id),
                owner_generation: 1,
                cap_id: supervisor.cap_id(),
            },
            HostOuterCapClass::Assignment,
            supervisor.clone(),
        )
        .unwrap();
    registry
        .register_node(NativeRamRegistration {
            native_resident_initial: false,
            target,
            policy,
            resources,
            capabilities: HostRamCapabilities {
                logical_ram_bytes: 64,
                compulsory_resident_bytes: 32,
                minimum_execution_peak_bytes: 64,
                maximum_paging_io_slots: 1,
                dynamic_residency: false,
                disk_oriented: false,
                resident_required: false,
            },
            qualification: HostRamQualification::default(),
            supervisor: supervisor.clone(),
            client: None,
        })
        .unwrap();
    let cap = registry.node(target).unwrap().cap;
    Fixture {
        registry,
        admission,
        target,
        cap,
        principal,
        policy,
        supervisor,
        _directory: directory,
    }
}

#[test]
fn independent_final_receipt_outlives_registrar_and_releases_original_node_ledger() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let target = fixture.target;
    let receipt = fixture.registry.retirement_authority(target).unwrap();
    assert!(receipt.retire_after_cleanup().is_err());
    assert!(
        fixture
            .admission
            .0
            .lock()
            .unwrap()
            .owner_reservation(target)
            .is_some()
    );

    fixture
        .registry
        .prepare_retirement_after_cleanup(target)
        .unwrap();
    assert!(
        fixture
            .registry
            .shared
            .state
            .lock()
            .unwrap()
            .nodes
            .is_empty()
    );
    assert!(
        fixture
            .admission
            .0
            .lock()
            .unwrap()
            .owner_reservation(target)
            .is_some()
    );
    let registry_lifetime = Arc::downgrade(&fixture.registry.shared);
    drop(fixture.registry);
    assert!(registry_lifetime.upgrade().is_none());

    receipt.retire_after_cleanup().unwrap();
    assert!(
        fixture
            .admission
            .0
            .lock()
            .unwrap()
            .owner_reservation(target)
            .is_none()
    );
    assert!(receipt.retire_after_cleanup().is_err());
}

#[test]
fn refused_retirement_prepare_keeps_lookup_and_original_charge() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let receipt = fixture
        .registry
        .retirement_authority(fixture.target)
        .unwrap();
    let owner = fixture.registry.node(fixture.target).unwrap();
    let _busy = owner.mutation.lock().unwrap();

    assert!(
        fixture
            .registry
            .prepare_retirement_after_cleanup(fixture.target)
            .is_err()
    );
    assert!(fixture.registry.node(fixture.target).is_ok());
    assert!(receipt.retire_after_cleanup().is_err());
    assert!(
        fixture
            .admission
            .0
            .lock()
            .unwrap()
            .owner_reservation(fixture.target)
            .is_some()
    );
}

fn update(fixture: &Fixture, key: u8, revision: u64, seconds: u64) -> HostOperationalRequest {
    let mut policy = fixture.policy;
    policy.latency.classes[HostOperationClass::PageIn as usize].total_timeout =
        Some(Duration::from_secs(seconds));
    HostOperationalRequest::UpdatePolicy {
        target: fixture.target,
        expected_policy_revision: revision,
        idempotency_key: [key; 32],
        policy: Box::new(policy),
        reservation_amendment: None,
    }
}

#[test]
fn live_budget_updates_replay_original_receipts_after_later_changes() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let request = update(&fixture, 4, 0, 120);
    let original = fixture
        .registry
        .execute(&fixture.principal, request.clone())
        .unwrap();
    assert!(matches!(
        original.value(),
        HostOperationalResponse::PolicyUpdate {
            disposition: HostOperationalDisposition::Accepted,
            policy_revision: 1,
            accepted_policy: Some(_),
            ..
        }
    ));
    assert_eq!(
        fixture.supervisor.budgets().unwrap().1.classes[HostOperationClass::PageIn as usize]
            .total_timeout,
        Some(Duration::from_secs(120))
    );
    fixture
        .registry
        .execute(&fixture.principal, update(&fixture, 5, 1, 240))
        .unwrap();

    let replay = fixture
        .registry
        .execute(&fixture.principal, request)
        .unwrap();
    assert!(matches!(
        replay.value(),
        HostOperationalResponse::PolicyUpdate {
            disposition: HostOperationalDisposition::Replayed,
            policy_revision: 1,
            ..
        }
    ));
    assert!(matches!(
        fixture
            .registry
            .execute(&fixture.principal, update(&fixture, 4, 0, 300)),
        Err(HostOperationalError::IdempotencyConflict)
    ));
    let status = fixture
        .registry
        .status(&fixture.registry.node(fixture.target).unwrap())
        .unwrap();
    assert_eq!(status.accepted_unique_update_count, 2);
    assert!(!status.measurements_available);
    codec::encode_response(&HostOperationalResponse::Status(Box::new(status))).unwrap();
}

#[test]
fn outer_cap_retries_retain_original_allowances_after_later_amendments() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let request = HostOperationalRequest::AmendOuterCap {
        target: fixture.cap,
        expected_cap_revision: 0,
        idempotency_key: [6; 32],
        allowance: Some(Duration::from_secs(120)),
    };
    fixture
        .registry
        .execute(&fixture.principal, request.clone())
        .unwrap();
    fixture
        .registry
        .execute(
            &fixture.principal,
            HostOperationalRequest::AmendOuterCap {
                target: fixture.cap,
                expected_cap_revision: 1,
                idempotency_key: [7; 32],
                allowance: Some(Duration::from_secs(240)),
            },
        )
        .unwrap();

    let replay = fixture
        .registry
        .execute(&fixture.principal, request)
        .unwrap();
    assert!(
        matches!(replay.value(), HostOperationalResponse::OuterCapAmendment {
        disposition: HostOperationalDisposition::Replayed, accepted_cap_revision: Some(1), accepted_allowance: Some(Some(duration)), ..
    } if *duration == Duration::from_secs(120))
    );
    assert_eq!(fixture.supervisor.outer_cap_status().unwrap().revision, 2);
}

#[test]
fn exhausted_history_refuses_without_effect_and_does_not_forget_old_keys() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(64 * 1024 + 2 * history::RECORD_CHARGE);
    let original = update(&fixture, 8, 0, 120);
    fixture
        .registry
        .execute(&fixture.principal, original.clone())
        .unwrap();
    fixture
        .registry
        .execute(&fixture.principal, update(&fixture, 9, 1, 240))
        .unwrap();

    let refused = fixture
        .registry
        .execute(&fixture.principal, update(&fixture, 10, 2, 360))
        .unwrap();
    assert!(matches!(
        refused.value(),
        HostOperationalResponse::PolicyUpdate {
            disposition: HostOperationalDisposition::HistoryCapacityRefused,
            accepted_policy: None,
            transition: None,
            ..
        }
    ));
    assert_eq!(fixture.supervisor.budgets().unwrap().0, 2);
    assert!(matches!(
        fixture
            .registry
            .execute(&fixture.principal, original)
            .unwrap()
            .value(),
        HostOperationalResponse::PolicyUpdate {
            disposition: HostOperationalDisposition::Replayed,
            policy_revision: 1,
            ..
        }
    ));
}

#[test]
fn unauthorized_principals_and_stale_generations_have_no_effect() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    assert_eq!(
        fixture
            .registry
            .execute(&"b".repeat(64), update(&fixture, 11, 0, 120)),
        Err(HostOperationalError::PrincipalDenied)
    );
    let mut stale = fixture.target;
    stale.arena_generation = 2;
    assert_eq!(
        fixture.registry.execute(
            &fixture.principal,
            HostOperationalRequest::Status { target: stale }
        ),
        Err(HostOperationalError::Unavailable)
    );
    assert_eq!(fixture.supervisor.budgets().unwrap().0, 0);
}

#[test]
fn interrupted_durable_intent_is_fenced_after_restart() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let directory = tempfile::tempdir().unwrap();
    let target = [12; 32];
    let key = [13; 32];
    let digest = [14; 32];
    {
        let mut history = history::History::open(directory.path(), 1024 * 1024).unwrap();
        assert!(history.prepare(target, key, digest).unwrap());
    }

    let reopened = history::History::open(directory.path(), 1024 * 1024).unwrap();
    assert_eq!(
        reopened.lookup(target, key, digest),
        Err(HostOperationalError::Unavailable)
    );
    assert_eq!(
        reopened.lookup(target, key, [15; 32]),
        Err(HostOperationalError::IdempotencyConflict)
    );
}

#[test]
fn borrowed_service_retirement_refuses_pending_amendment_and_preserves_caller_cap() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let registry = HostOperationalRegistry::default();
    let budgets = HostOperationBudgets {
        classes: [crucible_linux_resource::host_supervision::HostOperationBudget::finite(
            Duration::from_secs(300),
        ); crucible_linux_resource::host_supervision::HOST_OPERATION_CLASS_COUNT],
    };
    let original = HostOperationSupervisor::new(budgets, Some(Duration::from_secs(300))).unwrap();
    let borrowed = original.new_budget_owner(budgets).unwrap();
    let caller = HostOuterCapTarget {
        daemon_epoch: [0x71; 32],
        owner: HostOuterCapOwner::Service([0x72; 32]),
        owner_generation: 1,
        cap_id: original.cap_id(),
    };
    let service = HostOuterCapTarget {
        owner: HostOuterCapOwner::Service([0x73; 32]),
        ..caller
    };
    registry
        .register_cap(caller, HostOuterCapClass::Preparation, original.clone())
        .unwrap();
    registry
        .register_cap(service, HostOuterCapClass::Preparation, borrowed)
        .unwrap();
    let authority = registry.shared.state.lock().unwrap().caps[&service].clone();
    let amendment = authority.mutation.lock().unwrap();

    assert!(
        registry
            .retire_service(service.daemon_epoch, [0x73; 32])
            .is_err()
    );
    assert!(
        registry
            .shared
            .state
            .lock()
            .unwrap()
            .caps
            .contains_key(&service)
    );
    drop(amendment);
    registry
        .retire_service(service.daemon_epoch, [0x73; 32])
        .unwrap();

    let state = registry.shared.state.lock().unwrap();
    assert!(!state.caps.contains_key(&service));
    assert!(state.caps.contains_key(&caller));
    assert_eq!(
        original.outer_cap_status().unwrap().state,
        HostOperationState::Running
    );
}

#[test]
fn native_actor_control_contention_preserves_the_original_deadline_cause() {
    let _scope = crucible::test_support::fixture_decode_scope(256 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite registry component account: {error}"));
    let fixture = fixture(1024 * 1024);
    let owner = fixture.registry.node(fixture.target).unwrap();
    let (_, mut budgets) = fixture.supervisor.budgets().unwrap();
    budgets.classes[HostOperationClass::Cleanup as usize] =
        crucible_linux_resource::host_supervision::HostOperationBudget::finite(
            Duration::from_millis(2),
        );
    fixture.supervisor.update_budgets(0, budgets).unwrap();
    let _held_control = owner.client.lock().unwrap();
    let original_cap = fixture.supervisor.cap_id();

    let error = fixture
        .registry
        .fault_actor_status(fixture.target)
        .unwrap_err();

    let RamControlError::Io(source) = error else {
        panic!("control contention lost its original supervision cause: {error}");
    };
    assert!(matches!(
        source
            .get_ref()
            .and_then(|cause| cause
                .downcast_ref::<crucible_linux_resource::host_supervision::HostSupervisionError>()),
        Some(
            crucible_linux_resource::host_supervision::HostSupervisionError::DeadlineExpired {
                class: HostOperationClass::Cleanup,
                ..
            }
        )
    ));
    assert_eq!(fixture.supervisor.cap_id(), original_cap);
    assert!(
        fixture
            .admission
            .0
            .lock()
            .unwrap()
            .owner_reservation(fixture.target)
            .is_some()
    );
}
