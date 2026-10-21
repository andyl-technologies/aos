//! Exercises real physical session syscalls with explicit component checks.
//!
//! Unit custody below supplies no Main payer, Source, Native service, process
//! selection, queued-child retirement or operational permission.
// SPDX-License-Identifier: Apache-2.0

use super::*;

fn physical_fixture() -> SessionBody<()> {
    SessionBody {
        roles: std::array::from_fn(|_| None),
        closing_roles: [None; 3],
        fdinfo: None,
        closing_fdinfo: None,
        mapping: None,
        mapping_return_uncertain: false,
        exported: false,
        purpose: None,
        failure: None,
        original_after: None,
        _custody: (),
    }
}

fn header() -> PublisherHeader {
    PublisherHeader {
        lender_generation: 1,
        account_generation: 3,
        process_generation: 7,
        capability: [1; 32],
        reservation: [2; 32],
        node_index: 0,
        node_count: 1,
    }
}

#[test]
fn physical_session_has_exact_seals_header_zero_tail_and_distinct_events() {
    let mut body = physical_fixture();
    body.construct_with(|| Ok(()), header()).unwrap();

    let region = body.roles[0].as_ref().unwrap();
    assert_eq!(rustix::fs::fstat(region).unwrap().st_size, 4096);
    assert_eq!(
        rustix::fs::fcntl_get_seals(region).unwrap(),
        rustix::fs::SealFlags::SEAL | rustix::fs::SealFlags::SHRINK | rustix::fs::SealFlags::GROW
    );
    let mut bytes = [255; PUBLISHER_REGION_BYTES];
    assert_eq!(
        rustix::io::pread(region, &mut bytes, 0).unwrap(),
        bytes.len()
    );
    assert_eq!(
        &bytes[..PUBLISHER_HEADER_BYTES],
        &header().encode().unwrap()
    );
    assert!(
        bytes[PUBLISHER_HEADER_BYTES..]
            .iter()
            .all(|byte| *byte == 0)
    );
    let purpose = body.purpose.unwrap();
    assert_eq!(
        purpose.producer_event,
        crate::spawn::plugin_startup::event_identity(body.roles[1].as_ref().unwrap().as_raw_fd())
            .unwrap()
    );
    assert_eq!(
        purpose.receiver_event,
        crate::spawn::plugin_startup::event_identity(body.roles[2].as_ref().unwrap().as_raw_fd())
            .unwrap()
    );
    assert_ne!(purpose.producer_event, purpose.receiver_event);
    assert!(body.fdinfo.is_none());
    assert!(body.mapping.is_some());

    assert!(body.return_physical(false));
    assert!(body.mapping.is_none());
    assert!(body.roles.iter().all(Option::is_none));
}

#[test]
fn every_component_check_refusal_preserves_born_physical_roles_until_return() {
    let mut positive = physical_fixture();
    let mut checks = 0;
    positive
        .construct_with(
            || {
                checks += 1;
                Ok(())
            },
            header(),
        )
        .unwrap();
    assert!(positive.return_physical(false));

    for refusal in 1..=checks {
        let mut body = physical_fixture();
        let mut calls = 0;
        let result = body.construct_with(
            || {
                calls += 1;
                if calls == refusal {
                    Err(HostSupervisionError::Unavailable)
                } else {
                    Ok(())
                }
            },
            header(),
        );

        assert!(result.is_err(), "check {refusal}");
        assert_eq!(
            calls,
            refusal + usize::from(refusal < checks),
            "check {refusal}"
        );
        for descriptor in body.roles.iter().flatten().map(AsRawFd::as_raw_fd) {
            // SAFETY: the physical fixture still owns each journaled alias.
            assert!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0);
        }
        assert!(body.return_physical(false), "check {refusal}");
    }
}

#[test]
fn physical_construction_retains_first_refusal_and_independent_negative_post() {
    let mut body = physical_fixture();
    let mut calls = 0;
    let error = body
        .construct_with(
            || {
                calls += 1;
                Err(if calls == 1 {
                    HostSupervisionError::CapacityExhausted
                } else {
                    HostSupervisionError::Unavailable
                })
            },
            header(),
        )
        .unwrap_err();

    assert!(matches!(
        error.cause,
        SessionCause::Operation(OperationFailure::Original(
            HostSupervisionError::CapacityExhausted
        ))
    ));
    assert_eq!(
        error.original_after,
        Some(HostSupervisionError::Unavailable)
    );
    assert_eq!(calls, 2);
    assert!(body.roles.iter().all(Option::is_none));
    assert!(body.return_physical(false));
}

#[test]
fn exported_session_cannot_close_roles_or_mapping_without_actual_remote_return() {
    let mut body = physical_fixture();
    body.construct_with(|| Ok(()), header()).unwrap();
    body.exported = true;
    let mapping = body.mapping;
    let roles = body
        .roles
        .each_ref()
        .map(|role| role.as_ref().unwrap().as_raw_fd());

    assert!(!body.return_physical(false));
    assert_eq!(body.mapping, mapping);
    assert_eq!(
        body.roles
            .each_ref()
            .map(|role| role.as_ref().unwrap().as_raw_fd()),
        roles
    );

    // This boolean only exercises the private physical leaf. Production derives
    // it from the same retained LaunchCleanup, never from bytes or this fixture.
    assert!(body.return_physical(true));
}

#[test]
fn uncertain_mapping_disposition_refuses_retry_and_retains_every_physical_role() {
    let mut body = physical_fixture();
    body.construct_with(|| Ok(()), header()).unwrap();
    body.mapping_return_uncertain = true;
    let mapping = body.mapping;

    assert!(!body.return_physical(false));
    assert!(!body.return_physical(false));
    assert_eq!(body.mapping, mapping);
    assert!(body.roles.iter().all(Option::is_some));

    // The test has not called munmap; clear only this injected component fact
    // to dispose its known-live fixture. Production never resets uncertainty.
    body.mapping_return_uncertain = false;
    assert!(body.return_physical(false));
}

#[test]
fn invalid_header_refuses_before_any_kernel_session_birth() {
    let mut body = physical_fixture();
    let mut invalid = header();
    invalid.account_generation = 0;
    assert!(body.construct_with(|| Ok(()), invalid).is_err());
    assert!(body.roles.iter().all(Option::is_none));
    assert!(body.fdinfo.is_none());
    assert!(body.mapping.is_none());
}
