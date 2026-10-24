//! Checks actual reference control lifetimes under finite fixture loans.
//!
//! These controls do not install a project quota or authenticate an actor.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;

struct Fixture(FixtureResourceBudget);

impl StorePhysicalQuotaGuard for Fixture {
    fn verify(&self) -> Result<(), StoreError> {
        self.0.usage().map(|_| ())
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.0.reserve_with_control(bytes).and_then(|loan| {
            if descriptors == 0 {
                Ok(loan)
            } else {
                Err(StoreError::Quota)
            }
        })
    }
}

#[test]
fn reference_mutation_and_inventory_share_one_actual_control()
-> Result<(), Box<dyn std::error::Error>> {
    let quota = Arc::new(Fixture(FixtureResourceBudget::new(1, 1 << 20)));
    let mut owner = OriginalDirectoryRefOwner::open(Path::new("unused-ref-root"), quota.clone())?;
    let (backend, admin) = owner.authorities()?;
    let weak = Arc::downgrade(&backend);
    drop(backend);

    assert!(owner.try_close().is_err());
    drop(admin);
    assert!(owner.try_close().is_err());
    assert!(quota.0.usage()?.1 > 0);
    drop(weak);

    owner.try_close()?;
    assert_eq!(quota.0.usage()?, (0, 0));
    Ok(())
}

#[test]
fn external_loan_outlives_actual_reference_body_drop() -> Result<(), Box<dyn std::error::Error>> {
    let quota = Arc::new(Fixture(FixtureResourceBudget::new(1, 1 << 20)));
    let mut owner = OriginalDirectoryRefOwner::open(Path::new("unused-ref-root"), quota.clone())?;

    drop(owner.backend.take());
    assert!(quota.0.usage()?.1 > 0);

    owner.try_close()?;
    assert_eq!(quota.0.usage()?, (0, 0));
    Ok(())
}

#[test]
fn first_reference_reservation_refuses_before_root_buffer_and_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let quota = Arc::new(Fixture(FixtureResourceBudget::new(1, 1)));
    let directory = tempfile::TempDir::new()?;
    let path = directory.path().join("refs");

    assert!(OriginalDirectoryRefOwner::open(&path, quota.clone()).is_err());
    assert!(!path.exists());
    assert_eq!(quota.0.usage()?, (0, 0));
    Ok(())
}
