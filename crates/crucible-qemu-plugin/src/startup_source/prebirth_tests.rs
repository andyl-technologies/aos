//! Checks the retained original before fixed-control holder use.
// SPDX-License-Identifier: GPL-2.0-only

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use super::{
    InstallerStartupSource, StartupSourceError, test_support::InstallerStartupSourceModel,
};
use crate::ram_error::RamError;

fn retained_source() -> (InstallerStartupSource, UnixStream) {
    let (received, peer) = UnixStream::pair().unwrap();
    let descriptor: OwnedFd = received.into();
    (
        InstallerStartupSource::retain_received_plan(1, descriptor),
        peer,
    )
}

fn assert_plan_retained(source: &InstallerStartupSource) {
    let plan = source.plan.as_ref().unwrap();
    // SAFETY: this read-only descriptor query borrows the actual retained FD.
    assert!(unsafe { libc::fcntl(plan.as_raw_fd(), libc::F_GETFD) } >= 0);
}

#[test]
fn unacquired_source_preserves_the_original_ownership_refusal() {
    let (mut source, _peer) = retained_source();
    let result = source.require_installer_control_purpose();

    assert!(matches!(
        result,
        Err(RamError::InstallerSource(
            StartupSourceError::Ownership { .. }
        ))
    ));
    assert!(!source.acquisition_attempted);
    assert!(!source.registration_completed);
    assert_plan_retained(&source);
    drop(source.plan.take());
}

#[test]
fn temporal_installer_success_does_not_issue_allocation_credit() {
    let (mut source, _peer) = retained_source();
    source.inject_model(InstallerStartupSourceModel::ready());
    source.acquire().unwrap();

    let result = source.require_installer_control_purpose();

    assert!(matches!(
        result,
        Err(RamError::InstallerSource(StartupSourceError::Ownership {
            reason: "fixed control reservation checker is absent",
        }))
    ));
    assert!(source.acquired);
    assert!(!source.registration_completed);
    assert_eq!(
        source
            .first_status
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    assert_plan_retained(&source);
    drop(source.plan.take());
}

#[test]
fn original_signed_failure_precedes_the_missing_control_purpose() {
    let (mut source, _peer) = retained_source();
    source.inject_model(InstallerStartupSourceModel::refused_acquisition());
    assert_eq!(
        source.acquire(),
        Err(StartupSourceError::NativeStatus { status: -229 })
    );

    let result = source.require_installer_control_purpose();

    assert!(matches!(
        result,
        Err(RamError::InstallerSource(
            StartupSourceError::NativeStatus { status: -229 }
        ))
    ));
    assert!(!source.registration_completed);
    assert_plan_retained(&source);
    drop(source.plan.take());
}
