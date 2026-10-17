//! Finite metadata custody for durable archive transfer component fixtures.
//!
//! The descriptor and resident counters are portable test entitlements. They
//! certify neither installed filesystem quota nor native process admission.

use std::sync::{Arc, Mutex};

use crucible_cas::content_store::{StoreError, StorePhysicalQuotaGuard};

pub(super) struct TransferResources {
    maximum_descriptors: u64,
    maximum_resident_bytes: u64,
    usage: Arc<Mutex<(u64, u64)>>,
}

impl TransferResources {
    pub(super) fn new(maximum_descriptors: u64, maximum_resident_bytes: u64) -> Self {
        Self {
            maximum_descriptors,
            maximum_resident_bytes,
            usage: Arc::new(Mutex::new((0, 0))),
        }
    }
}

impl StorePhysicalQuotaGuard for TransferResources {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(self.maximum_resident_bytes)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        let mut usage = self.usage.lock().map_err(|_| StoreError::Quota)?;
        let next_descriptors = usage
            .0
            .checked_add(descriptors)
            .filter(|next| *next <= self.maximum_descriptors)
            .ok_or(StoreError::Quota)?;
        let next_resident_bytes = usage
            .1
            .checked_add(resident_bytes)
            .filter(|next| *next <= self.maximum_resident_bytes)
            .ok_or(StoreError::Quota)?;

        *usage = (next_descriptors, next_resident_bytes);
        Ok(crucible_cas::owned_decode::ResourceLoan::new(
            TransferResourceLoan {
                usage: self.usage.clone(),
                descriptors,
                resident_bytes,
            },
        ))
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

struct TransferResourceLoan {
    usage: Arc<Mutex<(u64, u64)>>,
    descriptors: u64,
    resident_bytes: u64,
}

impl Drop for TransferResourceLoan {
    fn drop(&mut self) {
        let Ok(mut usage) = self.usage.lock() else {
            return;
        };
        usage.0 -= self.descriptors;
        usage.1 -= self.resident_bytes;
    }
}

#[test]
fn archive_component_credits_are_finite_and_close_after_the_last_reader() {
    let resources = TransferResources::new(2, 4096);
    let loan = resources.reserve_resources(2, 4096).expect("complete loan");
    let retained = loan.clone();
    assert!(matches!(
        resources.reserve_resources(1, 0),
        Err(StoreError::Quota)
    ));
    assert!(matches!(
        resources.reserve_resources(0, 1),
        Err(StoreError::Quota)
    ));

    drop(loan);
    assert!(matches!(
        resources.reserve_resources(1, 0),
        Err(StoreError::Quota)
    ));
    drop(retained);
    resources
        .reserve_resources(2, 4096)
        .expect("released credits");
}
