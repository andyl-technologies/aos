//! Checks the actual shared-allocation exclusion seam without issuing Main.

use super::*;
use std::fs::File;
use std::os::fd::AsRawFd;

#[test]
fn strong_and_weak_aliases_preserve_the_same_file_body_before_exclusion() {
    let mut owner = Arc::new(Mutex::new(File::open("/dev/null").unwrap()));
    let original = Arc::as_ptr(&owner);
    let descriptor = owner.lock().unwrap().as_raw_fd();
    let strong = Arc::clone(&owner);

    assert!(matches!(
        unique_shared_body(&mut owner),
        Err(CleanupError::SharedAliasesPending)
    ));
    assert_eq!(Arc::as_ptr(&owner), original);
    assert_eq!(strong.lock().unwrap().as_raw_fd(), descriptor);
    drop(strong);

    let weak = Arc::downgrade(&owner);
    assert!(matches!(
        unique_shared_body(&mut owner),
        Err(CleanupError::SharedAliasesPending)
    ));
    assert_eq!(Arc::as_ptr(&owner), original);
    assert_eq!(
        weak.upgrade().unwrap().lock().unwrap().as_raw_fd(),
        descriptor
    );
    drop(weak);

    assert_eq!(
        unique_shared_body(&mut owner).unwrap().as_raw_fd(),
        descriptor
    );
    assert_eq!(Arc::as_ptr(&owner), original);
}

#[test]
fn a_borrowed_shared_mutex_refuses_without_waiting_or_changing_ownership() {
    let mut owner = Arc::new(Mutex::new(File::open("/dev/null").unwrap()));
    let alias = Arc::clone(&owner);
    let borrowed = alias.lock().unwrap();
    let descriptor = borrowed.as_raw_fd();

    assert!(matches!(
        unique_shared_body(&mut owner),
        Err(CleanupError::SharedAliasesPending)
    ));
    assert_eq!(borrowed.as_raw_fd(), descriptor);
    assert!(Arc::ptr_eq(&owner, &alias));

    drop(borrowed);
    drop(alias);
    assert_eq!(
        unique_shared_body(&mut owner).unwrap().as_raw_fd(),
        descriptor
    );
}

#[test]
fn poison_keeps_the_same_allocation_and_actual_file_without_reconstruction() {
    let mut owner = Arc::new(Mutex::new(File::open("/dev/null").unwrap()));
    let original = Arc::as_ptr(&owner);
    let descriptor = owner.lock().unwrap().as_raw_fd();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _borrowed = owner.lock().unwrap();
        panic!("retain the actual poisoned shared body");
    }));
    assert!(panic.is_err());

    assert!(matches!(
        unique_shared_body(&mut owner),
        Err(CleanupError::Poisoned)
    ));
    assert_eq!(Arc::as_ptr(&owner), original);
    let retained = owner.lock().unwrap_err().into_inner();
    assert_eq!(retained.as_raw_fd(), descriptor);
    assert!(owner.is_poisoned());
}
