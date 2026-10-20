//! Checks fixed scratch and actual backing refusals without a native process.

use std::rc::Rc;

use super::*;

#[test]
fn scratch_exact_layout_and_one_short_allowance() {
    let bytes = CnpPreparationStorageScratch::requested_bytes();
    assert_eq!(bytes, size_of::<CnpPreparationStorageScratch>());
    assert!(CnpPreparationStorageScratch::new(bytes).is_ok());
    assert!(matches!(
        CnpPreparationStorageScratch::new(bytes - 1),
        Err(RuntimeError::ResourceLimit)
    ));
}

#[test]
fn actual_busy_scratch_refuses_and_releases_without_erasing_original_loan()
-> Result<(), RuntimeError> {
    let scratch = CnpPreparationStorageScratch::new(usize::MAX)?;
    let mut original = scratch.loan(8192)?;
    original.0.add(17)?;

    assert!(matches!(scratch.loan(1), Err(RuntimeError::OwnerBusy)));
    assert_eq!(original.0.finish().known_requested_bytes(), 17);
    drop(original);

    let next = scratch.loan(1)?;
    assert_eq!(next.0.finish().known_requested_bytes(), 0);
    Ok(())
}

#[test]
fn foreign_scratch_origin_precedes_even_an_existing_mutable_loan() -> Result<(), RuntimeError> {
    let mut scratch = CnpPreparationStorageScratch::new(usize::MAX)?;
    scratch.process = scratch.process.wrapping_add(1);
    let mut original = scratch.counter.borrow_mut();
    original.reset(usize::MAX);
    original.add(19)?;

    assert!(matches!(
        scratch.loan(0),
        Err(RuntimeError::ForeignAuthority)
    ));
    assert_eq!(original.finish().known_requested_bytes(), 19);
    Ok(())
}

#[test]
fn foreign_thread_marker_refuses_before_scratch_loan() -> Result<(), Box<dyn std::error::Error>> {
    let mut scratch = CnpPreparationStorageScratch::new(usize::MAX)?;
    scratch.thread = std::thread::spawn(|| std::thread::current().id())
        .join()
        .map_err(|_| "thread-id fixture failed")?;
    let original = scratch.counter.borrow_mut();

    assert!(matches!(scratch.loan(0), Err(RuntimeError::ThreadAffinity)));
    assert_eq!(original.finish().known_requested_bytes(), 0);
    Ok(())
}

#[test]
fn actual_shared_backing_preserves_spare_and_rejects_one_short() -> Result<(), RuntimeError> {
    let mut value = String::with_capacity(4096);
    value.push('x');
    let owner = Rc::new(value);
    let alias = Rc::clone(&owner);
    let separate = Rc::new(owner.as_ref().clone());
    let mut counter = PreparationCounter::new(usize::MAX);

    assert!(counter.rc(&owner)?);
    counter.add(owner.capacity())?;
    let first = counter.finish().known_requested_bytes();
    assert!(!counter.rc(&alias)?);
    assert_eq!(counter.finish().known_requested_bytes(), first);
    assert!(counter.rc(&separate)?);
    counter.add(separate.capacity())?;
    let total = counter.finish().known_requested_bytes();

    let mut exact = PreparationCounter::new(total);
    assert!(exact.rc(&owner)?);
    exact.add(owner.capacity())?;
    assert!(exact.rc(&separate)?);
    exact.add(separate.capacity())?;
    assert_eq!(exact.finish().known_requested_bytes(), total);

    let mut short = PreparationCounter::new(total - 1);
    assert!(short.rc(&owner)?);
    short.add(owner.capacity())?;
    assert!(short.rc(&separate)?);
    assert_eq!(
        short.add(separate.capacity()),
        Err(RuntimeError::ResourceLimit)
    );
    Ok(())
}

#[test]
fn refusal_and_unwind_clear_only_scratch_pointer_observations() -> Result<(), RuntimeError> {
    let owner = Rc::new(());
    let scratch = CnpPreparationStorageScratch::new(usize::MAX)?;
    {
        let mut loan = scratch.loan(usize::MAX)?;
        assert!(loan.0.rc(&owner)?);
        assert_eq!(loan.0.add(usize::MAX), Err(RuntimeError::ResourceLimit));
    }
    assert_eq!(Rc::strong_count(&owner), 1);
    assert_eq!(scratch.counter.borrow().finish().known_requested_bytes(), 0);

    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<(), RuntimeError> {
            let mut loan = scratch.loan(usize::MAX)?;
            loan.0.rc(&owner)?;
            panic!("test-only interruption after actual owner observation");
        },
    ));
    assert!(unwind.is_err());
    assert_eq!(Rc::strong_count(&owner), 1);
    assert_eq!(scratch.counter.borrow().finish().known_requested_bytes(), 0);
    assert!(scratch.loan(0).is_ok());
    Ok(())
}

#[test]
fn actual_shared_owner_limit_refuses_before_changing_the_original_count() -> Result<(), RuntimeError>
{
    let originals: Vec<_> = (0..257).map(|_| Rc::new(())).collect();
    let mut counter = PreparationCounter::new(usize::MAX);
    for owner in &originals[..256] {
        assert!(counter.rc(owner)?);
    }
    let before = counter.finish().known_requested_bytes();

    assert_eq!(
        counter.rc(&originals[256]),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(counter.finish().known_requested_bytes(), before);
    assert!(originals.iter().all(|owner| Rc::strong_count(owner) == 1));
    Ok(())
}

#[test]
fn incomplete_owner_report_has_raw_refusal_even_at_equal_known_bytes() {
    let report = CnpRetainedStorageReport {
        known_requested_bytes: 123,
        unknowns: super::super::CnpRetainedStorageUnknowns {
            installed_source_owners: true,
            ..Default::default()
        },
        std_child_layout: false,
    };

    assert_eq!(report.known_requested_bytes(), 123);
    assert_eq!(
        report.complete_requested_bytes_precredit_data(),
        Err(RuntimeError::UnsupportedFacet)
    );
}
