//! Checks physical artifact destruction using actual component file handles.
//!
//! These generic cell controls issue no Source funding, launch or restore proof.

use super::*;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

struct ObservedArtifact {
    file: Option<File>,
    cell: Weak<ExactArtifactCell<Self>>,
    closed_outside_lock: Arc<AtomicBool>,
    panic_after_close: bool,
}

impl Drop for ObservedArtifact {
    fn drop(&mut self) {
        let Some(cell) = self.cell.upgrade() else {
            panic!("actual containing cell remains held");
        };
        assert!(cell.state.try_lock().is_ok());
        assert!(!cell.returned());
        assert!(!cell.close());
        drop(self.file.take());
        self.closed_outside_lock.store(true, Ordering::Release);
        assert!(
            !self.panic_after_close,
            "component artifact destructor refusal"
        );
    }
}

struct Fixture {
    cell: Arc<ExactArtifactCell<ObservedArtifact>>,
    closed: Arc<AtomicBool>,
    descriptor: i32,
    identity: std::fs::Metadata,
}

fn same_file(descriptor: i32, identity: &std::fs::Metadata) -> bool {
    std::fs::metadata(format!("/proc/self/fd/{descriptor}"))
        .is_ok_and(|found| found.dev() == identity.dev() && found.ino() == identity.ino())
}

fn fixture(panic_after_close: bool) -> Result<Fixture, Box<dyn std::error::Error>> {
    let cell = Arc::new(ExactArtifactCell::default());
    let closed = Arc::new(AtomicBool::new(false));
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let identity = file.metadata()?;
    let body = ObservedArtifact {
        file: Some(file),
        cell: Arc::downgrade(&cell),
        closed_outside_lock: Arc::clone(&closed),
        panic_after_close,
    };
    assert!(cell.retain(body).is_ok());
    Ok(Fixture {
        cell,
        closed,
        descriptor,
        identity,
    })
}

#[test]
fn actual_file_closes_outside_metadata_lock_before_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        cell,
        closed,
        descriptor,
        identity,
    } = fixture(false)?;
    assert!(!cell.returned());
    assert!(same_file(descriptor, &identity));

    assert!(cell.close());

    assert!(closed.load(Ordering::Acquire));
    assert!(!same_file(descriptor, &identity));
    assert!(cell.returned());
    assert!(cell.close());
    Ok(())
}

#[test]
fn destructor_unwind_keeps_closure_uncertain_after_actual_file_close()
-> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        cell,
        closed,
        descriptor,
        identity,
    } = fixture(true)?;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cell.close()));

    assert!(result.is_err());
    assert!(closed.load(Ordering::Acquire));
    assert!(!same_file(descriptor, &identity));
    assert!(!cell.returned());
    assert!(!cell.close());
    Ok(())
}

#[test]
fn duplicate_delivery_retains_both_real_files_and_blocks_completion()
-> Result<(), Box<dyn std::error::Error>> {
    let cell = ExactArtifactCell::default();
    let first = tempfile::tempfile()?;
    let second = tempfile::tempfile()?;
    let first_descriptor = first.as_raw_fd();
    let second_descriptor = second.as_raw_fd();
    assert!(cell.retain(first).is_ok());

    let second = match cell.retain(second) {
        Err(second) => second,
        Ok(()) => panic!("duplicate must remain with its actual sender"),
    };

    assert!(!cell.close());
    assert!(!cell.returned());
    assert!(std::fs::metadata(format!("/proc/self/fd/{first_descriptor}")).is_ok());
    assert!(std::fs::metadata(format!("/proc/self/fd/{second_descriptor}")).is_ok());

    // Explicit component cleanup extracts both files only after production
    // closure has refused; it cannot grant a Source return or reset its cell.
    let first = {
        let mut state = cell.state.lock().unwrap();
        let ArtifactState::Uncertain(Some(first)) =
            std::mem::replace(&mut *state, ArtifactState::Uncertain(None))
        else {
            panic!("the same first artifact must remain in quarantine");
        };
        first
    };
    drop((first, second));
    assert!(!cell.close());
    assert!(!cell.returned());
    Ok(())
}

#[test]
fn issued_artifact_transfer_blocks_cleanup_until_actual_return()
-> Result<(), Box<dyn std::error::Error>> {
    let cell = ExactArtifactCell::default();
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let identity = file.metadata()?;

    assert!(cell.reserve_transfer());
    assert!(!cell.reserve_transfer());
    assert!(!cell.returned());
    assert!(!cell.close());
    assert!(same_file(descriptor, &identity));
    assert!(cell.retain(file).is_ok());
    assert!(!cell.finish_transfer());
    assert!(!cell.returned());

    assert!(cell.close());
    assert!(!same_file(descriptor, &identity));
    assert!(cell.returned());
    Ok(())
}

#[test]
fn successful_transfer_releases_only_the_original_issued_cell() {
    let cell = ExactArtifactCell::<File>::default();
    assert!(!cell.finish_transfer());
    assert!(cell.reserve_transfer());
    assert!(cell.finish_transfer());
    assert!(!cell.finish_transfer());
    assert!(cell.returned());
}
