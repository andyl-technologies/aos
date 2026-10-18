//! Exercises the exact healthy-pending queue arm with real shared file custody.
//!
//! These unissued component cells prove no Main, World, or Service return.

use super::*;

struct SharedFileBody {
    file: Option<File>,
    emptied_allocation_dropped: Arc<AtomicBool>,
}

impl Drop for SharedFileBody {
    fn drop(&mut self) {
        assert!(
            self.file.is_none(),
            "the body must move before its allocation dies"
        );
        self.emptied_allocation_dropped
            .store(true, Ordering::Release);
    }
}

struct SharedFileOwner {
    shared: Option<Arc<Mutex<SharedFileBody>>>,
    file: Option<File>,
    allocation_dropped: Arc<AtomicBool>,
    cleanup_calls: Arc<AtomicUsize>,
    first: Option<crate::ProductionVmConstructionCleanupError>,
}

impl crucible_api::ProductionVmCleanupOwner for SharedFileOwner {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        if let Some(shared) = self.shared.as_mut() {
            let body = Arc::get_mut(shared)
                .ok_or(Self::Failure::SharedAliasesPending)?
                .get_mut()
                .map_err(|_| Self::Failure::Poisoned)?;
            self.file = body.file.take();
            drop(self.shared.take());
        }
        assert!(self.allocation_dropped.load(Ordering::Acquire));
        self.cleanup_calls.fetch_add(1, Ordering::AcqRel);
        if let Some(first) = self.first.take() {
            return Err(first);
        }
        drop(self.file.take());
        Ok(())
    }

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        assert!(self.shared.is_none() && self.file.is_none());
        // This real-file component has no native return obligation.
        Ok(None)
    }
}

#[test]
fn shared_alias_pending_keeps_same_owner_then_preserves_actual_cleanup_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(149, false)?;
    let original = selected.slot.cell.lock().unwrap().owner.take();
    drop(original);
    let allocation_dropped = Arc::new(AtomicBool::new(false));
    let cleanup_calls = Arc::new(AtomicUsize::new(0));
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let metadata = file.metadata()?;
    let identity = (metadata.dev(), metadata.ino());
    let shared = Arc::new(Mutex::new(SharedFileBody {
        file: Some(file),
        emptied_allocation_dropped: Arc::clone(&allocation_dropped),
    }));
    let alias = Arc::clone(&shared);
    let raw_message = String::from("actual file cleanup first after shared allocation death");
    let raw_identity = raw_message.as_ptr();
    let owner = Box::new(SharedFileOwner {
        shared: Some(shared),
        file: None,
        allocation_dropped: Arc::clone(&allocation_dropped),
        cleanup_calls: Arc::clone(&cleanup_calls),
        first: Some(crate::ProductionVmConstructionCleanupError::Authority(
            LifecycleApiError::LoopFactory {
                message: raw_message,
            },
        )),
    });
    let owner_identity = &*owner as *const SharedFileOwner as *const ();
    selected.slot.cell.lock().unwrap().owner = Some(owner);

    assert!(retry_slot(&selected.slot, Some(149)).is_err());
    assert!(selected.slot.cell.lock().unwrap().first_failure.is_none());
    assert_eq!(cleanup_calls.load(Ordering::Acquire), 0);
    assert!(!allocation_dropped.load(Ordering::Acquire));
    let service = selected.slot.service.lock().unwrap();
    let retained = service.queued_owner.as_ref().unwrap();
    assert_eq!(&**retained as *const _ as *const (), owner_identity);
    drop(service);
    assert_eq!(
        alias.lock().unwrap().file.as_ref().unwrap().as_raw_fd(),
        descriptor
    );

    let weak = Arc::downgrade(&alias);
    drop(alias);
    assert!(retry_slot(&selected.slot, Some(149)).is_err());
    assert!(selected.slot.cell.lock().unwrap().first_failure.is_none());
    assert_eq!(cleanup_calls.load(Ordering::Acquire), 0);
    drop(weak);

    assert!(retry_slot(&selected.slot, Some(149)).is_err());
    assert!(allocation_dropped.load(Ordering::Acquire));
    assert_eq!(cleanup_calls.load(Ordering::Acquire), 1);
    let cell = selected.slot.cell.lock().unwrap();
    let Some(crate::ProductionVmConstructionCleanupError::Authority(first)) = &cell.first_failure
    else {
        panic!("actual cleanup first must remain typed");
    };
    assert_eq!(loop_failure_message(first).as_ptr(), raw_identity);
    drop(cell);
    let retained = fs::metadata(format!("/proc/self/fd/{descriptor}"))?;
    assert_eq!((retained.dev(), retained.ino()), identity);

    assert!(retry_slot(&selected.slot, Some(149)).is_err());
    assert_eq!(cleanup_calls.load(Ordering::Acquire), 2);
    assert_eq!(
        selected.slot.body_destroyed_epoch.load(Ordering::Acquire),
        149
    );
    assert_eq!(selected.slot.completed_epoch.load(Ordering::Acquire), 0);
    assert!(
        fs::metadata(format!("/proc/self/fd/{descriptor}"))
            .map_or(true, |current| (current.dev(), current.ino()) != identity)
    );
    Ok(())
}

struct PoisonedSharedFileOwner(Arc<Mutex<File>>);

impl crucible_api::ProductionVmCleanupOwner for PoisonedSharedFileOwner {
    type Failure = crate::ProductionVmConstructionCleanupError;
    type PostBody = crate::ProductionVmConstructionPostBody;

    fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
        Arc::get_mut(&mut self.0)
            .ok_or(Self::Failure::SharedAliasesPending)?
            .get_mut()
            .map_err(|_| Self::Failure::Poisoned)?;
        panic!("the poisoned body cannot enter ordinary cleanup");
    }

    fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
        panic!("the poisoned body cannot transfer a return obligation");
    }
}

#[test]
fn shared_storage_pending_arm_does_not_mask_actual_mutex_poison()
-> Result<(), Box<dyn std::error::Error>> {
    let selected = fixture(150, false)?;
    let file = tempfile::tempfile()?;
    let descriptor = file.as_raw_fd();
    let mut shared = Arc::new(Mutex::new(file));
    let identity = Arc::as_ptr(&shared);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = shared.lock().unwrap();
        panic!("retain real shared mutex poison");
    }));
    assert!(panic.is_err());
    assert!(Arc::get_mut(&mut shared).is_some());
    assert_eq!(Arc::as_ptr(&shared), identity);
    let old = selected
        .slot
        .cell
        .lock()
        .unwrap()
        .owner
        .replace(Box::new(PoisonedSharedFileOwner(shared)));
    drop(old);

    assert!(retry_slot(&selected.slot, Some(150)).is_err());
    let cell = selected.slot.cell.lock().unwrap();
    assert!(matches!(
        cell.first_failure,
        Some(crate::ProductionVmConstructionCleanupError::Poisoned)
    ));
    assert!(!cell.owner_cleanup_complete);
    assert!(!cell.owner_post_body_taken);
    drop(cell);
    assert!(fs::metadata(format!("/proc/self/fd/{descriptor}")).is_ok());
    assert_eq!(
        selected.slot.body_destroyed_epoch.load(Ordering::Acquire),
        0
    );
    assert_eq!(
        selected.slot.controls_closed_epoch.load(Ordering::Acquire),
        0
    );
    assert_eq!(
        selected.slot.worlds_returned_epoch.load(Ordering::Acquire),
        0
    );
    assert_eq!(selected.slot.completed_epoch.load(Ordering::Acquire), 0);
    Ok(())
}
