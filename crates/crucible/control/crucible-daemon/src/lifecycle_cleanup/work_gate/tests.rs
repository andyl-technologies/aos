//! Exercises the pure transfer gate with real owned file bodies, without Main issuance.

use super::*;
use std::io::{Read, Seek, SeekFrom, Write};

#[test]
fn retirement_before_commit_retains_the_same_file_box() {
    let gate = WorkGate::new();
    let requested = AtomicBool::new(false);
    let mut file = Box::new(tempfile::tempfile().unwrap());
    file.write_all(b"same untransferred body").unwrap();
    let original = std::ptr::from_ref(file.as_ref());
    let mut retained = Some(file);

    gate.request_retirement(&requested);
    assert!(gate.commit(&requested).is_none());

    let file = retained.as_mut().unwrap();
    assert_eq!(std::ptr::from_ref(file.as_ref()), original);
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"same untransferred body");
}

#[test]
fn admitted_transfer_keeps_its_owner_and_never_reopens_after_later_request() {
    let gate = WorkGate::new();
    let requested = AtomicBool::new(false);
    let file = Box::new(tempfile::tempfile().unwrap());
    let original = std::ptr::from_ref(file.as_ref());
    let mut retained = Some(file);

    let commit = gate.commit(&requested).unwrap();
    gate.request_retirement(&requested);
    let transferred = retained.take().unwrap();
    drop(commit);

    assert!(retained.is_none());
    assert_eq!(std::ptr::from_ref(transferred.as_ref()), original);
    assert_eq!(gate.state.load(Ordering::Acquire), RETIRING);
    assert!(gate.commit(&requested).is_none());
    assert!(transferred.metadata().is_ok());
}

#[test]
fn unwind_keeps_the_original_body_and_closes_later_transfers() {
    let gate = WorkGate::new();
    let requested = AtomicBool::new(false);
    let file = Box::new(tempfile::tempfile().unwrap());
    let original = std::ptr::from_ref(file.as_ref());
    let retained = Some(file);

    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _commit = gate.commit(&requested).unwrap();
        panic!("component stops before the pure ownership move");
    }));

    assert!(failure.is_err());
    assert_eq!(
        std::ptr::from_ref(retained.as_ref().unwrap().as_ref()),
        original
    );
    assert!(retained.as_ref().unwrap().metadata().is_ok());
    assert!(requested.load(Ordering::Acquire));
    assert_eq!(gate.state.load(Ordering::Acquire), RETIRING);
    assert!(gate.commit(&requested).is_none());
}
