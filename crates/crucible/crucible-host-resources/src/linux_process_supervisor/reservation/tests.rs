//! Checks actual issuer/identity/refusal helpers without installing shared test limits.

use super::*;

fn incomplete() -> OriginalDeploymentResourceReservation {
    OriginalDeploymentResourceReservation {
        original: Arc::new(Original {
            process: std::process::id(),
            policy: LinuxProcessLimits {
                cpu_seconds: 7,
                address_space_bytes: 11,
                descriptors: 13,
            },
            installed: None,
            supervisor: None,
            failure: Some(LinuxProcessSupervisorError::UnsupportedFacet),
            revoked: AtomicBool::new(false),
        }),
    }
}

#[test]
fn actual_process_handoff_types_are_send_and_sync() {
    fn check<T: Send + Sync>() {}
    check::<OriginalDeploymentResourceReservation>();
    check::<DeploymentResourceLease>();
}

#[test]
fn issuance_helper_cannot_reissue_or_replace_its_original_process() {
    let latch = AtomicU32::new(0);
    assert_eq!(
        claim_issuance(&latch, 0),
        Err(LinuxProcessSupervisorError::ForeignAuthority)
    );
    claim_issuance(&latch, 17).unwrap();
    assert_eq!(
        claim_issuance(&latch, 17),
        Err(LinuxProcessSupervisorError::DuplicateOperation)
    );
    assert_eq!(
        claim_issuance(&latch, 19),
        Err(LinuxProcessSupervisorError::DuplicateOperation)
    );
    assert_eq!(latch.load(Ordering::Acquire), 17);
}

#[test]
fn incomplete_original_never_mints_a_completed_lease_or_context() {
    let owner = incomplete();
    assert!(matches!(
        owner.lease(),
        Err(LinuxProcessSupervisorError::OutstandingObligations)
    ));
    assert!(matches!(
        owner.read_context(),
        Err(LinuxProcessSupervisorError::OutstandingObligations)
    ));
    assert!(owner.reserved_policy_data().is_err());
    assert_eq!(
        owner.failure_data(),
        Some(LinuxProcessSupervisorError::UnsupportedFacet)
    );
}

#[test]
fn same_numbers_do_not_match_original_and_drop_revokes_retained_read() {
    let first = incomplete();
    let second = incomplete();
    // These private incomplete prefixes test only refusal/identity, never a
    // completed deployment, Source grant or permission to start a process.
    let read = DeploymentResourceLease {
        original: first.original.clone(),
    };
    let foreign_context = DeploymentResourceReadContext { owner: &second };
    assert_eq!(
        read.authenticate_in(&foreign_context),
        Err(LinuxProcessSupervisorError::ForeignAuthority)
    );
    drop(first);
    assert!(read.original.revoked.load(Ordering::Acquire));
    assert_eq!(
        read.authenticate_current(),
        Err(LinuxProcessSupervisorError::ForeignAuthority)
    );
}

#[test]
fn incomplete_prefix_and_foreign_process_reads_preserve_original_failure() {
    let mut owner = incomplete();
    Arc::get_mut(&mut owner.original).unwrap().process = std::process::id().wrapping_add(1);
    assert_eq!(
        owner.authenticate_current(),
        Err(LinuxProcessSupervisorError::ForeignAuthority)
    );
    assert_eq!(
        owner.failure_data(),
        Some(LinuxProcessSupervisorError::UnsupportedFacet)
    );
    assert!(owner.lease().is_err());
}

#[test]
fn deployment_layout_data_preserves_incomplete_and_revoked_originals() {
    let owner = incomplete();
    let read = DeploymentResourceLease {
        original: owner.original.clone(),
    };
    let references = Arc::strong_count(&read.original);

    let layout = read.retained_payload_layout_data();

    assert_eq!(layout.size(), std::mem::size_of::<Original>());
    assert_eq!(layout.align(), std::mem::align_of::<Original>());
    assert_eq!(Arc::strong_count(&read.original), references);
    assert!(read.original.installed.is_none());
    assert!(matches!(
        owner.lease(),
        Err(LinuxProcessSupervisorError::OutstandingObligations)
    ));
    assert_eq!(
        owner.failure_data(),
        Some(LinuxProcessSupervisorError::UnsupportedFacet)
    );
    drop(owner);

    assert_eq!(read.retained_payload_layout_data(), layout);
    assert!(read.original.revoked.load(Ordering::Acquire));
    assert_eq!(
        read.authenticate_current(),
        Err(LinuxProcessSupervisorError::ForeignAuthority)
    );
}
