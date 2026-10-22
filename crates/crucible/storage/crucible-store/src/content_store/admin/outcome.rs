//! Paid administrative results and exact deletion progress through acceptance.

use super::*;
use crate::owned_decode::{DecodeBudget, DecodeScratch};

/// Retains a checked administrative failure and its observed deletion prefix.
pub struct AdministrativeScopeError {
    body: Box<Failure>,
    _credit: DecodeScratch,
}

struct Failure {
    work: StoreError,
    deleted: u8,
    uncertain: bool,
    // Work-owned paths and provider tokens close before this payload loan.
    _diagnostic: Option<DecodeScratch>,
}

impl AdministrativeScopeError {
    /// Borrows the original typed work or acceptance failure.
    #[must_use]
    pub fn work_failure(&self) -> &StoreError {
        &self.body.work
    }

    /// Returns the number of deletions positively observed before refusal.
    #[must_use]
    pub fn deleted_objects(&self) -> u8 {
        self.body.deleted
    }

    /// Reports whether an attempted mutation lacked a terminal confirmation.
    #[must_use]
    pub fn mutation_uncertain(&self) -> bool {
        self.body.uncertain
    }
}

impl std::fmt::Debug for AdministrativeScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdministrativeScopeError")
            .field("work", &self.body.work)
            .field("deleted", &self.body.deleted)
            .field("uncertain", &self.body.uncertain)
            .finish()
    }
}

impl std::fmt::Display for AdministrativeScopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "checked administration failed after {} deletions (uncertain: {})",
            self.body.deleted, self.body.uncertain
        )
    }
}

impl std::error::Error for AdministrativeScopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.work_failure())
    }
}

pub(in crate::content_store) struct Progress {
    deleted: u8,
    uncertain: bool,
    credit: DecodeScratch,
    diagnostic: Option<DecodeScratch>,
}

impl Progress {
    pub(in crate::content_store) fn reserve(original: &DecodeBudget) -> Result<Self, StoreError> {
        let credit = original
            .reserve_scratch_array::<Failure>(1)
            .map_err(|error| batch::admission_under(original, error))?;
        Ok(Self {
            deleted: 0,
            uncertain: false,
            credit,
            diagnostic: None,
        })
    }

    pub(in crate::content_store) fn reserve_diagnostic(
        original: &DecodeBudget,
        bytes: u64,
    ) -> Result<Self, StoreError> {
        let mut progress = Self::reserve(original)?;
        progress.diagnostic = Some(
            original
                .reserve_scratch_bytes(bytes)
                .map_err(|error| batch::admission_under(original, error))?,
        );
        Ok(progress)
    }

    pub(in crate::content_store) fn begin_mutation(&mut self) {
        self.uncertain = true;
    }

    pub(in crate::content_store) fn complete(&mut self, disposition: PlannedDeleteDisposition) {
        self.uncertain = false;
        if disposition == PlannedDeleteDisposition::Deleted {
            self.deleted += 1;
        }
    }

    pub(in crate::content_store) fn refuse(self, work: StoreError) -> StoreError {
        StoreError::AdministrativeScope {
            source: AdministrativeScopeError {
                body: Box::new(Failure {
                    work,
                    deleted: self.deleted,
                    uncertain: self.uncertain,
                    _diagnostic: self.diagnostic,
                }),
                _credit: self.credit,
            },
        }
    }

    pub(in crate::content_store) fn accept<T>(self, value: T) -> Accepted<T> {
        Accepted {
            value,
            progress: self,
        }
    }
}

pub(in crate::content_store) struct Accepted<T> {
    value: T,
    progress: Progress,
}

impl<T> Accepted<T> {
    pub(in crate::content_store) fn value(&self) -> &T {
        &self.value
    }

    pub(in crate::content_store) fn check(
        mut self,
        check: impl FnOnce(&mut T) -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        match check(&mut self.value) {
            Ok(()) => Ok(self),
            Err(work) => {
                let Self { value, progress } = self;
                drop(value);
                Err(progress.refuse(work))
            }
        }
    }
}

#[cfg(test)]
pub(in crate::content_store) mod test_original {
    use super::*;
    use crate::content_store::test_resources::FixtureResourceBudget;

    pub(in crate::content_store) struct Quota {
        pub(in crate::content_store) resources: FixtureResourceBudget,
    }

    impl StorePhysicalQuotaGuard for Quota {
        fn verify(&self) -> Result<(), StoreError> {
            Ok(())
        }

        fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
            Ok(64 * 1024 * 1024)
        }

        fn reserve_resources(
            &self,
            descriptors: u64,
            bytes: u64,
        ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
            self.resources.reserve(descriptors, bytes)
        }
    }

    pub(in crate::content_store) fn account() -> (Arc<Quota>, DecodeBudget) {
        let quota = Arc::new(Quota {
            resources: FixtureResourceBudget::new(128, 64 * 1024 * 1024),
        });
        let original = DecodeBudget::for_store(quota.clone()).unwrap();
        (quota, original)
    }

    pub(in crate::content_store) fn assert_closed(
        fence: &mut CheckedInventoryFence<'_>,
        id: ContentId,
    ) {
        let mut boundaries = 0;
        let deleted = fence.delete_candidates_with_boundary(&[id], &mut || {
            boundaries += 1;
            Ok(())
        });
        assert!(matches!(deleted, Err(StoreError::Unsupported { .. })));
        let mut visits = 0;
        let inventory = fence.visit_inventory_with_boundary(
            &mut |_| {
                visits += 1;
                Ok(())
            },
            &mut || {
                boundaries += 1;
                Ok(())
            },
        );
        assert!(matches!(inventory, Err(StoreError::Unsupported { .. })));
        assert_eq!((boundaries, visits), (0, 0));
    }
}
