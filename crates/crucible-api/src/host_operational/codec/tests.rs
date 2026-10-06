//! Golden and adversarial executable checks for host operational encoding.

use super::*;
use crucible_linux_resource::host_supervision::{HostEffectiveDeadline, HostOperationState};

fn target() -> HostRamTarget {
    HostRamTarget {
        daemon_epoch: [0x11; 32],
        owner_id: [0x22; 32],
        node_id: [0x33; 32],
        owner_generation: 7,
        arena_generation: 9,
        retained_template: false,
    }
}

#[test]
fn target_discovery_binds_owner_cursor_order_and_bounded_page() {
    let target = target();
    let owner = HostRamOwnerTarget {
        daemon_epoch: target.daemon_epoch,
        owner_id: target.owner_id,
    };
    let request = HostOperationalRequest::ListTargets {
        target: owner,
        after: Some(target),
        limit: 32,
    };
    assert_eq!(
        decode_request(&encode_request(&request).unwrap()).unwrap(),
        request
    );
    let mut arenas = Vec::new();
    for generation in 1..=32 {
        arenas.push(HostRamTarget {
            arena_generation: generation,
            ..target
        });
    }
    let response = HostOperationalResponse::Targets {
        target: owner,
        next: arenas.last().copied(),
        targets: arenas.clone(),
    };
    let bytes = encode_response(&response).unwrap();
    assert!(bytes.len() <= HOST_OPERATIONAL_MAX_BYTES);
    assert_eq!(decode_response(&bytes).unwrap(), response);
    arenas.reverse();
    assert!(
        encode_response(&HostOperationalResponse::Targets {
            target: owner,
            targets: arenas,
            next: None
        })
        .is_err()
    );
    assert!(
        encode_request(&HostOperationalRequest::ListTargets {
            target: owner,
            after: Some(HostRamTarget {
                owner_id: [0; 32],
                ..target
            }),
            limit: 1
        })
        .is_err()
    );
    assert!(
        encode_request(&HostOperationalRequest::ListTargets {
            target: owner,
            after: None,
            limit: 0
        })
        .is_err()
    );
}

fn policy() -> HostRamPolicy {
    HostRamPolicy {
        mode: HostRamMode::Managed,
        resident_target_bytes: 4096,
        eviction_preference: 80,
        writeback_bytes_per_second: 65536,
        maximum_paging_io_in_flight: 2,
        prefetch_on_increase: false,
        latency: HostOperationBudgets::default(),
    }
}

fn update() -> HostOperationalRequest {
    HostOperationalRequest::UpdatePolicy {
        target: target(),
        expected_policy_revision: 2,
        idempotency_key: [0x44; 32],
        policy: Box::new(policy()),
        reservation_amendment: Some(HostReservationAmendment {
            expected_reservation_revision: 3,
            requested: HostResourceVector {
                resident_peak_bytes: 8192,
                backing_peak_bytes: 4096,
                ..HostResourceVector::default()
            },
            transition_peak: HostResourceVector {
                resident_peak_bytes: 16384,
                backing_peak_bytes: 4096,
                ..HostResourceVector::default()
            },
        }),
    }
}

#[test]
fn status_request_has_frozen_explicit_width_big_endian_bytes() {
    let bytes = encode_request(&HostOperationalRequest::Status { target: target() }).unwrap();
    let mut expected = vec![0, 0, 0, 1, 1];
    expected.extend_from_slice(&[0x11; 32]);
    expected.extend_from_slice(&[0x22; 32]);
    expected.extend_from_slice(&[0x33; 32]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
    expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 9]);
    expected.push(0);

    assert_eq!(bytes, expected);
    assert_eq!(bytes.len(), 118);
    assert_eq!(
        decode_request(&bytes).unwrap(),
        HostOperationalRequest::Status { target: target() }
    );
}

#[test]
fn policy_request_roundtrip_binds_independent_reservation_and_budget_roster() {
    let request = update();
    let bytes = encode_request(&request).unwrap();

    assert_eq!(decode_request(&bytes).unwrap(), request);
    assert!(bytes.len() < HOST_OPERATIONAL_MAX_BYTES);
    for end in 0..bytes.len() {
        assert!(
            decode_request(&bytes[..end]).is_err(),
            "accepted truncation at {end}"
        );
    }
}

#[test]
fn operational_codec_refuses_unknown_tags_trailing_and_oversized_data() {
    let bytes = encode_request(&update()).unwrap();
    let mut invalid = bytes.clone();
    invalid[3] = 2;
    assert!(decode_request(&invalid).is_err());
    invalid = bytes.clone();
    invalid[4] = 4;
    assert!(decode_request(&invalid).is_err());
    invalid = bytes.clone();
    invalid[117] = 2;
    assert!(decode_request(&invalid).is_err());
    invalid = bytes.clone();
    invalid.push(0);
    assert!(decode_request(&invalid).is_err());
    assert!(decode_request(&vec![0; HOST_OPERATIONAL_MAX_BYTES + 1]).is_err());
}

#[test]
fn configured_durations_are_exact_nonzero_milliseconds() {
    let mut request = update();
    let HostOperationalRequest::UpdatePolicy { policy, .. } = &mut request else {
        panic!("fixture");
    };
    policy.latency.classes[0].poll_interval = Duration::ZERO;
    assert!(encode_request(&request).is_err());

    let mut request = update();
    let HostOperationalRequest::UpdatePolicy { policy, .. } = &mut request else {
        panic!("fixture");
    };
    policy.latency.classes[0].total_timeout = Some(Duration::from_nanos(1));
    assert!(encode_request(&request).is_err());

    let mut request = update();
    let HostOperationalRequest::UpdatePolicy { policy, .. } = &mut request else {
        panic!("fixture");
    };
    policy.latency.classes[0].total_timeout = Some(Duration::from_secs(u64::MAX));
    assert!(encode_request(&request).is_err());
}

#[test]
fn request_digest_binds_authenticated_principal_every_incarnation_and_payload() {
    let original = update();
    let digest = host_operational_request_digest("operator-a", &original).unwrap();
    assert_eq!(
        digest,
        host_operational_request_digest("operator-a", &original).unwrap()
    );
    assert_ne!(
        digest,
        host_operational_request_digest("operator-b", &original).unwrap()
    );

    for change in 0..6 {
        let mut changed = original.clone();
        let HostOperationalRequest::UpdatePolicy {
            target,
            expected_policy_revision,
            policy,
            ..
        } = &mut changed
        else {
            panic!("fixture");
        };
        match change {
            0 => target.daemon_epoch[0] ^= 1,
            1 => target.owner_id[0] ^= 1,
            2 => target.owner_generation += 1,
            3 => target.arena_generation += 1,
            4 => *expected_policy_revision += 1,
            _ => policy.resident_target_bytes += 1,
        }
        assert_ne!(
            digest,
            host_operational_request_digest("operator-a", &changed).unwrap()
        );
    }
    assert!(host_operational_request_digest("", &original).is_err());
    assert!(host_operational_request_digest("operator\nspoof", &original).is_err());
}

fn status() -> HostRamStatus {
    HostRamStatus {
        target: target(),
        observation_sequence: 11,
        policy_revision: 2,
        reservation_revision: 3,
        requested_policy: policy(),
        applied_policy: policy(),
        effective_resident_target_bytes: 4096,
        effective_floor_bytes: 4096,
        limitation_reasons: vec!["compulsory fault buffer".into()],
        measurements_available: true,
        activity: Some(HostRamActivity {
            successful_missing_installs: 3,
            successful_missing_read_installs: 1,
            successful_missing_write_installs: 2,
            write_protect_transitions: 2,
            preservation_reads: 3,
            preservation_writes: 4,
            physical_discards: 5,
            prefetched_pages: 6,
        }),
        private_resident_bytes: 4096,
        shared_resident_bytes_observed: 0,
        preserved_backing_bytes: 4096,
        private_dirty_bytes: 0,
        writeback_pending_bytes: 0,
        convergence: HostRamConvergence::Stable,
        accepted_unique_update_count: 1,
        remaining_unique_update_capacity: 99,
        history_disk_bytes: 512,
        transition: None,
        admitted_resources: HostResourceVector::default(),
        outer_caps: vec![HostOuterCapObservation {
            target: HostOuterCapTarget {
                daemon_epoch: [0x11; 32],
                owner: HostOuterCapOwner::Execution([0x22; 32]),
                owner_generation: 7,
                cap_id: [0x77; 32],
            },
            class: HostOuterCapClass::Assignment,
            status: HostOuterCapStatus {
                revision: 5,
                allowance: Some(Duration::from_secs(60)),
                remaining: Some(Duration::ZERO),
                state: HostOperationState::Expired,
            },
        }],
        outstanding_operations: vec![HostOperationStatus {
            operation_id: 6,
            class: HostOperationClass::PageIn,
            started_policy_revision: 1,
            applied_policy_revision: 2,
            completed_work_units: 10,
            outstanding_work_units: 2,
            progress_kind: HostProgressKind::AuthenticatedPage,
            state: HostOperationState::Running,
            effective_deadline: Some(HostEffectiveDeadline {
                remaining: Duration::ZERO,
                sources: vec![
                    HostDeadlineSource::Total(2),
                    HostDeadlineSource::Outer {
                        cap_id: [0x77; 32],
                        revision: 5,
                    },
                ],
            }),
        }],
    }
}

#[test]
fn status_roundtrip_keeps_acceptance_convergence_reservation_and_deadline_sources_separate() {
    let response = HostOperationalResponse::Status(Box::new(status()));
    let bytes = encode_response(&response).unwrap();

    assert_eq!(decode_response(&bytes).unwrap(), response);
    assert!(bytes.len() < HOST_OPERATIONAL_MAX_BYTES);
    for end in 0..bytes.len() {
        assert!(
            decode_response(&bytes[..end]).is_err(),
            "accepted truncation at {end}"
        );
    }
}

#[test]
fn status_refuses_unbounded_or_ambiguous_rosters_before_publication() {
    let mut fixture = status();
    fixture
        .outstanding_operations
        .push(fixture.outstanding_operations[0].clone());
    assert!(encode_response(&HostOperationalResponse::Status(Box::new(fixture))).is_err());

    let mut fixture = status();
    fixture.outer_caps.push(fixture.outer_caps[0].clone());
    assert!(encode_response(&HostOperationalResponse::Status(Box::new(fixture))).is_err());

    let mut fixture = status();
    fixture.limitation_reasons = vec!["bounded".into(); HOST_OPERATIONAL_MAX_REASONS + 1];
    assert!(encode_response(&HostOperationalResponse::Status(Box::new(fixture))).is_err());

    let mut fixture = status();
    fixture.outstanding_operations[0]
        .effective_deadline
        .as_mut()
        .unwrap()
        .sources
        .reverse();
    assert!(encode_response(&HostOperationalResponse::Status(Box::new(fixture))).is_err());
}

#[test]
fn policy_acceptance_roundtrip_does_not_claim_physical_convergence() {
    let response = HostOperationalResponse::PolicyUpdate {
        request_digest: [0x55; 32],
        target: target(),
        disposition: HostOperationalDisposition::Accepted,
        policy_revision: 8,
        reservation_revision: 3,
        transition: Some(17),
        accepted_policy: Some(Box::new(policy())),
    };
    assert_eq!(
        decode_response(&encode_response(&response).unwrap()).unwrap(),
        response
    );
}

#[test]
fn policy_receipt_rejects_invented_or_missing_acceptance() {
    let receipt =
        |disposition, accepted_policy, transition| HostOperationalResponse::PolicyUpdate {
            request_digest: [0x55; 32],
            target: target(),
            disposition,
            policy_revision: 8,
            reservation_revision: 3,
            transition,
            accepted_policy,
        };

    assert!(encode_response(&receipt(HostOperationalDisposition::Accepted, None, None)).is_err());
    assert!(
        encode_response(&receipt(
            HostOperationalDisposition::AdmissionRefused,
            Some(Box::new(policy())),
            None,
        ))
        .is_err()
    );
    assert!(
        encode_response(&receipt(
            HostOperationalDisposition::RevisionConflict,
            None,
            Some(17),
        ))
        .is_err()
    );
    assert!(
        encode_response(&receipt(
            HostOperationalDisposition::Replayed,
            Some(Box::new(policy())),
            Some(0),
        ))
        .is_err()
    );
}

#[test]
fn backend_preferences_do_not_imply_low_peak_or_lifecycle_qualification() {
    let capabilities = HostRamCapabilities {
        logical_ram_bytes: 8192,
        compulsory_resident_bytes: 4096,
        minimum_execution_peak_bytes: 8192,
        maximum_paging_io_slots: 2,
        dynamic_residency: true,
        disk_oriented: true,
        resident_required: false,
    };
    let mut qualification = HostRamQualification {
        backend: HostRamBackend::PausedPager,
        authenticated_pages: true,
        evidence: Some([0x66; 32]),
        ..HostRamQualification::default()
    };
    let response = HostOperationalResponse::Capabilities {
        target: target(),
        capabilities,
        qualification,
    };
    assert_eq!(
        decode_response(&encode_response(&response).unwrap()).unwrap(),
        response
    );

    qualification.bounded_execution_peak = true;
    let response = HostOperationalResponse::Capabilities {
        target: target(),
        capabilities,
        qualification,
    };
    assert!(encode_response(&response).is_err());
    qualification = HostRamQualification {
        backend: HostRamBackend::StrictPager,
        authenticated_pages: true,
        fault_safe_progress: true,
        bounded_execution_peak: true,
        ..HostRamQualification::default()
    };
    assert!(
        encode_response(&HostOperationalResponse::Capabilities {
            target: target(),
            capabilities,
            qualification,
        })
        .is_err()
    );
}

#[test]
fn positive_submillisecond_remaining_time_never_appears_expired() {
    let mut fixture = status();
    fixture.outer_caps[0].status.remaining = Some(Duration::from_nanos(1));
    fixture.outstanding_operations[0]
        .effective_deadline
        .as_mut()
        .unwrap()
        .remaining = Duration::from_nanos(999_999);
    let decoded = decode_response(
        &encode_response(&HostOperationalResponse::Status(Box::new(fixture))).unwrap(),
    )
    .unwrap();
    let HostOperationalResponse::Status(decoded) = decoded else {
        panic!("fixture");
    };
    assert_eq!(
        decoded.outer_caps[0].status.remaining,
        Some(Duration::from_millis(1))
    );
    assert_eq!(
        decoded.outstanding_operations[0]
            .effective_deadline
            .as_ref()
            .unwrap()
            .remaining,
        Duration::from_millis(1)
    );
}

#[test]
fn outer_cap_acceptance_is_original_receipt_and_service_namespace_is_distinct() {
    let target = HostOuterCapTarget {
        daemon_epoch: [0x11; 32],
        owner: HostOuterCapOwner::Service([0x22; 32]),
        owner_generation: 7,
        cap_id: [0x77; 32],
    };
    let request = HostOperationalRequest::AmendOuterCap {
        target,
        expected_cap_revision: 8,
        idempotency_key: [0x44; 32],
        allowance: None,
    };
    assert_eq!(
        decode_request(&encode_request(&request).unwrap()).unwrap(),
        request
    );
    let response = HostOperationalResponse::OuterCapAmendment {
        request_digest: [0x55; 32],
        target,
        disposition: HostOperationalDisposition::Replayed,
        accepted_cap_revision: Some(9),
        accepted_allowance: Some(None),
    };
    assert_eq!(
        decode_response(&encode_response(&response).unwrap()).unwrap(),
        response
    );
    let refused = HostOperationalResponse::OuterCapAmendment {
        request_digest: [0x55; 32],
        target,
        disposition: HostOperationalDisposition::Terminal,
        accepted_cap_revision: None,
        accepted_allowance: None,
    };
    assert_eq!(
        decode_response(&encode_response(&refused).unwrap()).unwrap(),
        refused
    );
    let inconsistent = HostOperationalResponse::OuterCapAmendment {
        request_digest: [0x55; 32],
        target,
        disposition: HostOperationalDisposition::RevisionConflict,
        accepted_cap_revision: Some(9),
        accepted_allowance: Some(None),
    };
    assert!(encode_response(&inconsistent).is_err());
}

#[test]
fn admitted_status_topology_fits_the_canonical_envelope_at_all_field_ceilings() {
    let mut fixture = status();
    fixture.limitation_reasons = vec!["r".repeat(128); HOST_OPERATIONAL_MAX_REASONS];
    for budget in &mut fixture.requested_policy.latency.classes {
        budget.progress_timeout = Some(Duration::from_secs(30));
        budget.total_timeout = Some(Duration::from_secs(60));
    }
    fixture.applied_policy = fixture.requested_policy;
    let cap = fixture.outer_caps[0].clone();
    fixture.outer_caps = (0..HOST_OPERATIONAL_MAX_OUTER_CAPS)
        .map(|index| {
            let mut cap = cap.clone();
            cap.target.cap_id = [0x77 + index as u8; 32];
            cap
        })
        .collect();
    let mut operation = fixture.outstanding_operations[0].clone();
    operation.effective_deadline.as_mut().unwrap().sources = vec![
        HostDeadlineSource::Progress(2),
        HostDeadlineSource::Total(2),
        HostDeadlineSource::Outer {
            cap_id: [0x77; 32],
            revision: 5,
        },
    ];
    fixture.outstanding_operations = (1..=HOST_OPERATIONAL_MAX_OPERATIONS)
        .map(|index| {
            let mut operation = operation.clone();
            operation.operation_id = index as u64;
            operation
        })
        .collect();

    let bytes = encode_response(&HostOperationalResponse::Status(Box::new(fixture))).unwrap();

    assert!(bytes.len() <= HOST_OPERATIONAL_MAX_BYTES);
    assert!(decode_response(&bytes).is_ok());
}

#[test]
fn unavailable_measurements_do_not_present_physical_zero_as_observed_residency() {
    let mut fixture = status();
    fixture.measurements_available = false;
    assert!(encode_response(&HostOperationalResponse::Status(Box::new(fixture.clone()))).is_err());
    fixture.private_resident_bytes = 0;
    fixture.preserved_backing_bytes = 0;
    assert!(fixture.activity.is_some());
    let response = HostOperationalResponse::Status(Box::new(fixture));
    assert_eq!(
        decode_response(&encode_response(&response).unwrap()).unwrap(),
        response
    );
}

#[test]
fn unavailable_activity_is_distinct_from_measured_zero_activity() {
    let mut fixture = status();
    fixture.activity = None;
    let unavailable = HostOperationalResponse::Status(Box::new(fixture.clone()));
    let unavailable_bytes = encode_response(&unavailable).unwrap();
    assert_eq!(decode_response(&unavailable_bytes).unwrap(), unavailable);

    fixture.activity = Some(HostRamActivity {
        successful_missing_installs: 0,
        successful_missing_read_installs: 0,
        successful_missing_write_installs: 0,
        write_protect_transitions: 0,
        preservation_reads: 0,
        preservation_writes: 0,
        physical_discards: 0,
        prefetched_pages: 0,
    });
    let measured = HostOperationalResponse::Status(Box::new(fixture));
    let measured_bytes = encode_response(&measured).unwrap();
    assert_ne!(measured_bytes, unavailable_bytes);
    assert_eq!(decode_response(&measured_bytes).unwrap(), measured);
}
