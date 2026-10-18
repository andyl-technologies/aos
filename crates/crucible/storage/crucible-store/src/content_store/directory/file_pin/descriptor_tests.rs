//! Descriptor custody through the existing terminal shared file-pin control.
//!
//! The same finite portable profile models original descriptor and resident
//! counters. Physical quota, fixture startup, and System-free observation are
//! separate qualifications; these controls assert normal and unwind alias custody.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{StoreError, StorePhysicalQuotaGuard};
use crate::owned_decode::{DecodeBudget, DecodeDescriptorLoan, ResourceLoan};

struct Quota {
    resources: FixtureResourceBudget,
}

impl Quota {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            resources: FixtureResourceBudget::new(8, 4 * 1024 * 1024),
        })
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.resources.reserve(descriptors, bytes)
    }
}

#[test]
fn shared_pin_retains_descriptor_and_control_credit_through_final_alias_and_unwind() {
    for unwind in [false, true] {
        let quota = Quota::new();
        let original = DecodeBudget::for_store(quota.clone()).expect("saved original");
        let resident = quota.resources.usage().expect("original usage").1;
        let root = tempfile::tempdir().expect("fixture root");
        let path = root.path().join("pinned");
        let descriptors = original
            .reserve_descriptors(1)
            .expect("original descriptor");
        let bytes = FilePin::<DecodeDescriptorLoan>::allocation_bytes();
        let credit = original
            .reserve_scratch_bytes(bytes)
            .expect("exact original pin control");
        let file = File::create(path).expect("open after descriptor and control prepayment");
        let pin = FilePin::with_resources(file, credit, descriptors);
        let alias = pin.clone();
        drop(pin);
        assert!(alias.file().is_some());
        assert_eq!(
            quota.resources.usage().expect("live final alias"),
            (1, resident + bytes)
        );

        if unwind {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _pin = alias;
                panic!("intentional original descriptor owner unwind");
            }));
            assert!(result.is_err());
        } else {
            drop(alias);
        }
        assert_eq!(
            quota.resources.usage().expect("all aliases closed"),
            (0, resident)
        );
        original
            .verify_live()
            .expect("healthy original after final pin close");
    }
}
