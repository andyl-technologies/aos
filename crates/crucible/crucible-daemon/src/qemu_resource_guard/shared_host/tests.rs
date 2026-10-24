//! Tests real shared mutex/poison behavior without an authenticated provider.

// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn ordinary_factory_cannot_acquire_source_origin_even_when_its_mutex_is_busy() {
    let body = SharedHostBody::ordinary(73_u64);
    let held = body.host.lock().unwrap();
    let allocation = std::ptr::from_ref(&*held);

    let refusal = body.world_origin();

    assert!(
        matches!(refusal, Err(QemuVmRealizationError::ExecutorUnavailable { ref message, .. })
        if message == "shared factory has no prepublished authentic normal pool")
    );
    assert_eq!(std::ptr::from_ref(&*held), allocation);
    assert_eq!(*held, 73);
}

#[test]
fn actual_poison_refuses_origin_without_borrowing_or_clearing_the_mutex() {
    let body = SharedHostBody::ordinary(81_u64);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = body.host.lock().unwrap();
        panic!("poison the actual shared constructor mutex");
    }));
    assert!(failed.is_err());
    assert!(body.host.is_poisoned());

    let refusal = body.world_origin();

    assert!(
        matches!(refusal, Err(QemuVmRealizationError::ExecutorUnavailable { ref message, .. })
        if message == "host-resource allocator lock is poisoned")
    );
    assert!(body.host.is_poisoned());
    assert!(body.host.try_lock().is_err());
}

#[test]
fn shared_body_price_includes_actual_origin_slot_and_arc_counters() {
    let (expected, _) = std::alloc::Layout::new::<(AtomicUsize, AtomicUsize)>()
        .extend(std::alloc::Layout::new::<SharedHostBody<u64>>())
        .unwrap();

    assert_eq!(
        shared_body_extent::<u64>(),
        Some(expected.pad_to_align().size())
    );
    assert!(
        std::mem::size_of::<SharedHostBody<u64>>()
            >= std::mem::size_of::<Mutex<u64>>()
                + std::mem::size_of::<Option<LinuxQemuNativeWorldPreparationOrigin>>()
    );
}
