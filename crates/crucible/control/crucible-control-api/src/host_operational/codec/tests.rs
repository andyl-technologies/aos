//! Golden and adversarial executable checks for host operational encoding.

// crucible-lint: allow panic-shortcut -- executable format fixtures use panic shortcuts for precise refusal localization.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crucible_host_resources::host_supervision::{HostEffectiveDeadline, HostOperationState};

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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
    let bytes = encode_request(&HostOperationalRequest::Status { target: target() }).unwrap();
    let mut expected = vec![0, 0, 0, 4, 1];
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
    let bytes = encode_request(&update()).unwrap();
    let mut invalid = bytes.clone();
    invalid[3] = 1;
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

fn update_with_duration(duration: Duration) -> HostOperationalRequest {
    let mut request = update();
    let HostOperationalRequest::UpdatePolicy { policy, .. } = &mut request else {
        panic!("fixture policy request");
    };
    policy.latency.classes[0] = HostOperationBudget {
        poll_interval: duration,
        progress_timeout: Some(duration),
        total_timeout: Some(duration),
    };
    request
}

#[test]
fn configured_durations_preserve_exact_positive_nanoseconds() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024).unwrap();
    for duration in [
        Duration::from_nanos(1),
        Duration::from_micros(500),
        Duration::from_nanos(crucible_qemu_protocol::ram_control::RAM_CONTROL_MAX_ALLOWANCE_NS),
    ] {
        let request = update_with_duration(duration);
        let bytes = encode_request(&request).unwrap();
        assert_eq!(&bytes[..4], &4_u32.to_be_bytes());
        // Schema/tag, full RAM target, revision/key, then placement fields.
        let first_poll = 5 + 113 + 8 + 32 + 23;
        assert_eq!(
            &bytes[first_poll..first_poll + 8],
            &(duration.as_nanos() as u64).to_be_bytes()
        );
        assert!(validate_request(&bytes).is_ok());
        assert_eq!(decode_request(&bytes).unwrap(), request);

        let request = HostOperationalRequest::AmendOuterCap {
            target: HostOuterCapTarget {
                daemon_epoch: [0x11; 32],
                owner: HostOuterCapOwner::Execution([0x22; 32]),
                owner_generation: 7,
                cap_id: [0x77; 32],
            },
            expected_cap_revision: 5,
            idempotency_key: [0x44; 32],
            allowance: Some(duration),
        };
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );
    }
}

#[test]
fn configured_nanoseconds_refuse_zero_overflow_and_predecessor_schemas() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024).unwrap();
    for duration in [
        Duration::ZERO,
        Duration::from_nanos(crucible_qemu_protocol::ram_control::RAM_CONTROL_MAX_ALLOWANCE_NS + 1),
        Duration::MAX,
    ] {
        assert!(encode_request(&update_with_duration(duration)).is_err());
        let request = HostOperationalRequest::AmendOuterCap {
            target: HostOuterCapTarget {
                daemon_epoch: [0x11; 32],
                owner: HostOuterCapOwner::Execution([0x22; 32]),
                owner_generation: 7,
                cap_id: [0x77; 32],
            },
            expected_cap_revision: 5,
            idempotency_key: [0x44; 32],
            allowance: Some(duration),
        };
        assert!(encode_request(&request).is_err());
    }
    let current = encode_request(&update_with_duration(Duration::from_nanos(1))).unwrap();
    for value in [
        0,
        crucible_qemu_protocol::ram_control::RAM_CONTROL_MAX_ALLOWANCE_NS + 1,
        u64::MAX,
    ] {
        // First budget: poll:u64, progress:tag/u64, total:tag/u64.
        for offset in [181, 190, 199] {
            let mut invalid = current.to_vec();
            invalid[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            assert!(decode_request(&invalid).is_err());
            assert!(validate_request(&invalid).is_err());
        }
    }
    let response = encode_response(&HostOperationalResponse::Status(Box::new(status()))).unwrap();
    for schema in [1_u32, 2, 3] {
        let mut old = current.to_vec();
        old[..4].copy_from_slice(&schema.to_be_bytes());
        assert!(decode_request(&old).is_err());
        assert!(validate_request(&old).is_err());
        let mut old = response.to_vec();
        old[..4].copy_from_slice(&schema.to_be_bytes());
        assert!(decode_response(&old).is_err());
    }
}

#[test]
fn request_digest_distinguishes_nanosecond_allowances_and_wire_editions() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024).unwrap();
    let request = update_with_duration(Duration::from_nanos(1));
    let current = host_operational_request_digest("operator-a", &request).unwrap();
    assert_ne!(
        current,
        host_operational_request_digest(
            "operator-a",
            &update_with_duration(Duration::from_nanos(2))
        )
        .unwrap()
    );
    let wire = encode_request(&request).unwrap();
    let digest_wire = |bytes: &[u8]| {
        let mut digest = blake3::Hasher::new();
        digest.update(b"crucible.host-ram.request.v1\0");
        digest.update(&10_u32.to_be_bytes());
        digest.update(b"operator-a");
        digest.update(bytes);
        *digest.finalize().as_bytes()
    };
    assert_eq!(current, digest_wire(&wire));
    let mut predecessor = wire.to_vec();
    predecessor[..4].copy_from_slice(&3_u32.to_be_bytes());
    assert_ne!(current, digest_wire(&predecessor));
}

#[test]
fn request_digest_binds_authenticated_principal_every_incarnation_and_payload() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
        applied_policy_revision: 2,
        reservation_revision: 3,
        requested_policy: policy(),
        applied_policy: policy(),
        placement_receipt: None,
        effective_resident_target_bytes: 4096,
        effective_floor_bytes: 4096,
        limitation_reasons: vec!["compulsory fault buffer".into()],
        measurements_available: true,
        resident_observation: None,
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
    let mut fixture = status();
    fixture
        .outstanding_operations
        .push(status().outstanding_operations.remove(0));
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
fn remaining_time_preserves_exact_nanoseconds_and_expired_zero() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024).unwrap();
    for remaining in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_micros(500),
    ] {
        let mut fixture = status();
        fixture.outer_caps[0].status.remaining = Some(remaining);
        fixture.outstanding_operations[0]
            .effective_deadline
            .as_mut()
            .unwrap()
            .remaining = remaining;
        let response = HostOperationalResponse::Status(Box::new(fixture));
        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
    }
    let mut fixture = status();
    fixture.outer_caps[0].status.remaining = Some(Duration::from_nanos(
        crucible_qemu_protocol::ram_control::RAM_CONTROL_MAX_ALLOWANCE_NS + 1,
    ));
    assert!(encode_response(&HostOperationalResponse::Status(Box::new(fixture))).is_err());
}

#[test]
fn outer_cap_acceptance_is_original_receipt_and_service_namespace_is_distinct() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
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
    fixture.outstanding_operations = (1..=HOST_OPERATIONAL_MAX_OPERATIONS)
        .map(|index| {
            let mut rows = status().outstanding_operations;
            let mut operation = rows.remove(0);
            operation.operation_id = index as u64;
            operation.effective_deadline.as_mut().unwrap().sources = vec![
                HostDeadlineSource::Progress(2),
                HostDeadlineSource::Total(2),
                HostDeadlineSource::Outer {
                    cap_id: [0x77; 32],
                    revision: 5,
                },
            ];
            operation
        })
        .collect();

    let bytes = encode_response(&HostOperationalResponse::Status(Box::new(fixture))).unwrap();

    assert!(bytes.len() <= HOST_OPERATIONAL_MAX_BYTES);
    assert!(decode_response(&bytes).is_ok());
}

#[test]
fn unavailable_measurements_do_not_present_physical_zero_as_observed_residency() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
    let mut fixture = status();
    fixture.measurements_available = false;
    let mut invalid_fixture = status();
    invalid_fixture.measurements_available = false;
    assert!(encode_response(&HostOperationalResponse::Status(Box::new(invalid_fixture))).is_err());
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
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
    let mut fixture = status();
    fixture.activity = None;
    let mut unavailable_fixture = status();
    unavailable_fixture.activity = None;
    let unavailable = HostOperationalResponse::Status(Box::new(unavailable_fixture));
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

#[test]
fn strict_placement_roundtrips_completed_and_pending_revisions() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
    for mode in [HostRamMode::ResidentRequired, HostRamMode::DiskOriented] {
        let mut fixture = status();
        fixture.applied_policy.mode = mode;
        fixture.requested_policy.mode = mode;
        fixture.placement_receipt = Some(HostRamPlacementReceipt {
            mode,
            policy_revision: 2,
            topology_generation: 17,
            placement_epoch: 9,
            locked_bytes: if mode == HostRamMode::ResidentRequired {
                8192
            } else {
                0
            },
            disk_preserved_logical_pages: if mode == HostRamMode::DiskOriented {
                2
            } else {
                0
            },
            disk_preserved_logical_bytes: if mode == HostRamMode::DiskOriented {
                6000
            } else {
                0
            },
            ram_write_generation_at_cut: if mode == HostRamMode::DiskOriented {
                47
            } else {
                0
            },
        });
        // A newer accepted request does not silently relabel earlier evidence.
        fixture.policy_revision = 3;
        let response = HostOperationalResponse::Status(Box::new(fixture));

        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
    }
}

#[test]
fn strict_placement_refuses_mismatched_receipts_and_predecessor_schema() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite operational codec fixture: {error}"));
    let strict_fixture = || {
        let mut fixture = status();
        fixture.applied_policy.mode = HostRamMode::ResidentRequired;
        fixture.placement_receipt = Some(HostRamPlacementReceipt {
            mode: HostRamMode::ResidentRequired,
            policy_revision: 2,
            topology_generation: 17,
            placement_epoch: 9,
            locked_bytes: 8192,
            disk_preserved_logical_pages: 0,
            disk_preserved_logical_bytes: 0,
            ram_write_generation_at_cut: 0,
        });
        fixture
    };
    let encoded =
        encode_response(&HostOperationalResponse::Status(Box::new(strict_fixture()))).unwrap();
    let (mut predecessor, _credit) = encoded.into_parts();
    predecessor[..4].copy_from_slice(&1_u32.to_be_bytes());
    assert!(decode_response(&predecessor).is_err());

    for invalid in 0..5 {
        let mut candidate = strict_fixture();
        let receipt = candidate.placement_receipt.as_mut().unwrap();
        match invalid {
            0 => receipt.policy_revision = 3,
            1 => receipt.topology_generation = 0,
            2 => receipt.placement_epoch = 0,
            3 => receipt.locked_bytes = 8193,
            4 => receipt.disk_preserved_logical_pages = 1,
            _ => unreachable!(),
        }
        assert!(encode_response(&HostOperationalResponse::Status(Box::new(candidate))).is_err());
    }
}

#[test]
fn decoded_status_retains_all_owned_field_credit_until_final_output_drop() {
    use std::sync::atomic::Ordering;

    let response = HostOperationalResponse::Status(Box::new(status()));
    let bytes = {
        let budget = crate::admitted_output::test_support::fixture_budget().unwrap();
        let _scope = budget.enter();
        encode_response(&response).unwrap()
    };
    let (budget, used) = crate::admitted_output::test_support::tracked_fixture_budget(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite response authority: {error}"));
    let baseline = used.load(Ordering::SeqCst);
    let decoded = {
        let _scope = budget.enter();
        decode_response(&bytes).unwrap_or_else(|error| panic!("admitted coherent status: {error}"))
    };

    assert_eq!(decoded.value(), &response);
    let retained = used.load(Ordering::SeqCst);
    assert!(
        retained > baseline,
        "decoded fields retain their original child account"
    );
    // Transient canonical encoding is released before the returned DTO escapes.
    assert!(retained - baseline < HOST_OPERATIONAL_MAX_BYTES as u64);
    drop(decoded);
    assert_eq!(used.load(Ordering::SeqCst), baseline);
    drop(budget);
    assert_eq!(used.load(Ordering::SeqCst), 0);
}

#[test]
fn decoded_response_refuses_missing_or_exhausted_original_authority() {
    let response = HostOperationalResponse::Status(Box::new(status()));
    let bytes = {
        let budget = crate::admitted_output::test_support::fixture_budget().unwrap();
        let _scope = budget.enter();
        encode_response(&response).unwrap()
    };
    assert!(matches!(
        decode_response(&bytes),
        Err(HostOperationalError::Admission { .. })
    ));

    let (budget, _) = crate::admitted_output::test_support::tracked_fixture_budget(1024)
        .unwrap_or_else(|error| panic!("finite exhausted-response fixture: {error}"));
    let _scope = budget.enter();
    assert!(matches!(
        decode_response(&bytes),
        Err(HostOperationalError::Admission { .. })
    ));
}

#[test]
fn decoded_policy_keeps_original_credit_after_wire_and_budget_close() {
    use std::sync::atomic::Ordering;

    let request = update();
    let wire = {
        let budget = crate::admitted_output::test_support::fixture_budget().unwrap();
        let _scope = budget.enter();
        encode_request(&request).unwrap()
    };
    assert!(validate_request(&wire).is_ok());
    assert!(matches!(
        decode_request(&wire),
        Err(HostOperationalError::Admission { .. })
    ));
    let (budget, used) = crate::admitted_output::test_support::tracked_fixture_budget(1024 * 1024)
        .unwrap_or_else(|error| panic!("finite request authority: {error}"));
    let decoded = {
        let _scope = budget.enter();
        decode_request(&wire).unwrap()
    };
    assert_eq!(decoded.value(), &request);

    drop(wire);
    drop(budget);
    let retained = used.load(Ordering::SeqCst);
    assert!(retained >= std::mem::size_of::<HostRamPolicy>() as u64);
    let policy = decoded.map(|request| match request {
        HostOperationalRequest::UpdatePolicy { policy, .. } => policy,
        _ => panic!("fixture policy request"),
    });
    assert_eq!(used.load(Ordering::SeqCst), retained);
    assert_eq!(policy.maximum_paging_io_in_flight, 2);
    drop(policy);
    assert_eq!(used.load(Ordering::SeqCst), 0);
}

#[test]
fn partial_residency_interval_is_available_without_complete_measurements() {
    let _scope = crucible_engine::test_support::fixture_decode_scope(32 * 1024 * 1024)
        .unwrap_or_else(|error| panic!("finite interval fixture: {error}"));
    let mut fixture = status();
    fixture.measurements_available = false;
    fixture.private_resident_bytes = 0;
    fixture.shared_resident_bytes_observed = 0;
    fixture.preserved_backing_bytes = 0;
    fixture.private_dirty_bytes = 0;
    fixture.writeback_pending_bytes = 0;
    fixture.resident_observation = Some(HostRamResidentObservation {
        availability: crucible_qemu_protocol::ram_control::RAM_OBSERVATION_TOTAL_RESIDENT,
        topology_generation: fixture.target.arena_generation,
        policy_revision: fixture.applied_policy_revision,
        policy_generation: 3,
        worker_generation: 4,
        writer_generation: 7,
        covered_bytes: 8192,
        total_resident_bytes: 4096,
        effective_target_bytes: 4096,
        started_ns: 20,
        completed_ns: 25,
    });
    fixture.convergence = HostRamConvergence::Blocked;
    assert!(fixture.placement_receipt.is_none());
    let observation = fixture.resident_observation.unwrap();
    let response = HostOperationalResponse::Status(Box::new(fixture));
    let encoded = encode_response(&response).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        decode_response(&encoded).unwrap_or_else(|e| panic!("{e}")),
        response
    );
    // Locate the literal fixed record, not a guessed status-field offset. The
    // fixture has no placement receipt, exercising its validation early return.
    let mut record = observation.availability.to_be_bytes().to_vec();
    for field in [
        observation.topology_generation,
        observation.policy_revision,
        observation.policy_generation,
        observation.worker_generation,
        observation.writer_generation,
        observation.covered_bytes,
        observation.total_resident_bytes,
        observation.effective_target_bytes,
        observation.started_ns,
        observation.completed_ns,
    ] {
        record.extend_from_slice(&field.to_be_bytes());
    }
    let offset = encoded
        .windows(record.len())
        .position(|bytes| bytes == record)
        .unwrap();
    assert_eq!(
        encoded
            .windows(record.len())
            .filter(|bytes| *bytes == record)
            .count(),
        1
    );
    for (field_offset, value) in [
        (4, 0),
        (4, observation.topology_generation + 1),
        (12, 0),
        (12, observation.policy_revision + 1),
        (20, 0),
        (28, 0),
        (36, 0),
        (44, 0),
        (52, observation.covered_bytes + 1),
        (68, 0),
        (76, observation.started_ns - 1),
    ] {
        let mut invalid = encoded.clone();
        invalid[offset + field_offset..offset + field_offset + 8]
            .copy_from_slice(&value.to_be_bytes());
        let mut reader = Reader::new(&invalid).unwrap();
        assert_eq!(reader.u8().unwrap(), 1);
        assert!(reader.status().is_err());
        assert!(decode_response(&invalid).is_err());
    }
    for availability in [0_u32, 2] {
        let mut invalid = encoded.clone();
        invalid[offset..offset + 4].copy_from_slice(&availability.to_be_bytes());
        let mut reader = Reader::new(&invalid).unwrap();
        assert_eq!(reader.u8().unwrap(), 1);
        assert!(reader.status().is_err());
        assert!(decode_response(&invalid).is_err());
    }
    let mut old = encoded.to_vec();
    old[..4].copy_from_slice(&2_u32.to_be_bytes());
    assert!(decode_response(&old).is_err());
}
