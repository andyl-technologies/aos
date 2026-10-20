//! Monotonic reservations of original callback-owned device request tokens.
//!
//! The constructor preallocates before HOLD without selecting the poll gate.
//! A one-shot original source adoption then closes ordinary polling. A stage binds
//! an unused slot to its original journal allocation and record index; the token
//! remains in its original map. Poll permission comes only from the selected
//! native Compute loan, never the stored integers or a caller-provided boolean.

use super::super::whole_sources::{SourceResult, WholeSourceError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OriginalRequestFamily {
    Block,
    ReadonlyNineP,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct OriginalRequestKey {
    pub(super) family: OriginalRequestFamily,
    pub(super) epoch: u64,
    pub(super) id: u32,
}

struct Reservation {
    key: OriginalRequestKey,
    stage_allocation: usize,
    record_index: u32,
    response_capacity: usize,
}

pub(super) struct OriginalTokenReservations {
    entries: Vec<Reservation>,
    limit: Option<usize>,
    preparation_attempted: bool,
    activation_attempted: bool,
    selected: bool,
    failed: bool,
}

impl OriginalTokenReservations {
    pub(super) fn uninitialized() -> Self {
        Self {
            entries: Vec::new(),
            limit: None,
            preparation_attempted: false,
            activation_attempted: false,
            selected: false,
            failed: false,
        }
    }

    pub(super) fn initialize(&mut self, capacity: usize, byte_limit: u64) -> SourceResult<()> {
        if self.preparation_attempted || self.activation_attempted {
            self.failed = true;
            self.selected = false;
            return Err(WholeSourceError::Mismatch(
                "original reservation preparation already attempted",
            ));
        }
        self.preparation_attempted = true;
        if capacity == 0
            || capacity > u32::MAX as usize
            || capacity
                .checked_mul(std::mem::size_of::<Reservation>())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .is_none_or(|bytes| bytes > byte_limit)
        {
            self.failed = true;
            return Err(WholeSourceError::Mismatch(
                "original device reservation geometry",
            ));
        }
        if self.entries.try_reserve_exact(capacity).is_err() {
            self.failed = true;
            return Err(WholeSourceError::Mismatch(
                "original device reservation backing",
            ));
        }
        if self.storage_bytes()? > byte_limit {
            self.failed = true;
            return Err(WholeSourceError::Mismatch(
                "actual original reservation allocation",
            ));
        }
        self.limit = Some(capacity);
        Ok(())
    }

    // Activation only closes ordinary polling and selects the exact Compute
    // query. A failed attempt is sticky; it cannot renew backing or credits.
    pub(super) fn activate(&mut self, original_source_matches: bool) -> SourceResult<()> {
        if self.activation_attempted {
            self.failed = true;
            self.selected = false;
            return Err(WholeSourceError::Mismatch(
                "original reservation activation already attempted",
            ));
        }
        self.activation_attempted = true;
        if !original_source_matches || self.limit.is_none() || self.failed {
            self.failed = true;
            return Err(WholeSourceError::Mismatch(
                "original reservation activation source",
            ));
        }
        self.selected = true;
        Ok(())
    }

    pub(super) fn storage_bytes(&self) -> SourceResult<u64> {
        self.entries
            .capacity()
            .checked_mul(std::mem::size_of::<Reservation>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(WholeSourceError::Mismatch("actual reservation byte extent"))
    }

    pub(super) fn reserve(
        &mut self,
        key: OriginalRequestKey,
        stage_allocation: usize,
        record_index: u32,
        response_capacity: usize,
    ) -> SourceResult<()> {
        if !self.selected || self.failed {
            return Err(WholeSourceError::Mismatch(
                "original reservation table not adopted",
            ));
        }
        if stage_allocation == 0 {
            return Err(WholeSourceError::Mismatch("original stage allocation"));
        }
        if let Some(existing) = self
            .entries
            .iter()
            .find(|reservation| reservation.key == key)
        {
            return if existing.stage_allocation == stage_allocation
                && existing.record_index == record_index
                && existing.response_capacity == response_capacity
            {
                Ok(())
            } else {
                Err(WholeSourceError::Mismatch(
                    "original token already reserved",
                ))
            };
        }
        if self.limit.is_none_or(|limit| self.entries.len() >= limit)
            || self.entries.iter().any(|reservation| {
                reservation.stage_allocation == stage_allocation
                    && reservation.record_index == record_index
            })
        {
            return Err(WholeSourceError::Mismatch(
                "original token reservation extent",
            ));
        }
        self.entries.push(Reservation {
            key,
            stage_allocation,
            record_index,
            response_capacity,
        });
        Ok(())
    }

    pub(super) fn poll_current(&self, key: OriginalRequestKey) -> bool {
        if !self.activation_attempted {
            return true;
        }
        if !self.selected || self.failed {
            return false;
        }
        self.entries
            .iter()
            .find(|reservation| reservation.key == key)
            .is_some_and(|reservation| {
                crate::runtime::whole_compute_scope::reservation_current(
                    reservation.stage_allocation,
                    reservation.record_index,
                )
            })
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "Reservation controls intentionally panic when their expected successful setup or operation fails."
)]
mod tests {
    use super::*;

    fn key(id: u32) -> OriginalRequestKey {
        OriginalRequestKey {
            family: OriginalRequestFamily::Block,
            epoch: 7,
            id,
        }
    }

    #[test]
    fn original_stage_reservation_denies_poll_without_native_compute_loan() {
        let mut table = OriginalTokenReservations::uninitialized();
        assert!(table.poll_current(key(0)));
        table.initialize(2, 4096).unwrap();
        table.activate(true).unwrap();
        assert!(!table.poll_current(key(0)));
        let allocated = table.storage_bytes().unwrap();
        table.reserve(key(0), 32, 0, 512).unwrap();

        assert!(!table.poll_current(key(0)));
        assert!(!table.poll_current(key(1)));
        assert_eq!(table.storage_bytes().unwrap(), allocated);
    }

    #[test]
    fn original_reservation_is_idempotent_but_refuses_foreign_stage_and_shape() {
        let mut table = OriginalTokenReservations::uninitialized();
        table.initialize(2, 4096).unwrap();
        table.activate(true).unwrap();
        table.reserve(key(0), 32, 0, 512).unwrap();
        table.reserve(key(0), 32, 0, 512).unwrap();

        assert!(table.reserve(key(0), 64, 0, 512).is_err());
        assert!(table.reserve(key(0), 32, 1, 512).is_err());
        assert!(table.reserve(key(0), 32, 0, 511).is_err());
        assert!(table.reserve(key(1), 32, 0, 512).is_err());
        assert!(!table.poll_current(key(0)));
    }

    #[test]
    fn original_constructor_table_never_grows_or_recycles_stage_slots() {
        let mut table = OriginalTokenReservations::uninitialized();
        assert!(table.reserve(key(0), 32, 0, 512).is_err());
        let mut failed = OriginalTokenReservations::uninitialized();
        assert!(failed.initialize(1, 0).is_err());
        assert!(failed.initialize(1, 4096).is_err());
        table.initialize(1, 4096).unwrap();
        table.activate(true).unwrap();
        let bytes = table.storage_bytes().unwrap();
        table.reserve(key(0), 32, 0, 512).unwrap();
        assert!(table.initialize(2, 4096).is_err());
        assert!(table.reserve(key(0), 32, 0, 512).is_err());

        assert!(table.reserve(key(1), 32, 1, 512).is_err());
        assert!(table.reserve(key(1), 0, 1, 512).is_err());
        assert_eq!(table.storage_bytes().unwrap(), bytes);
        assert!(!table.poll_current(key(0)));
    }

    #[test]
    fn preowned_backing_preserves_ordinary_drain_until_original_adoption() {
        let mut table = OriginalTokenReservations::uninitialized();
        table.initialize(2, 4096).unwrap();
        let bytes = table.storage_bytes().unwrap();

        assert!(table.poll_current(key(0)));
        assert!(table.reserve(key(0), 32, 0, 512).is_err());
        table.activate(true).unwrap();
        assert!(!table.poll_current(key(0)));
        table.reserve(key(0), 32, 0, 512).unwrap();
        assert!(!table.poll_current(key(0)));
        assert!(!table.poll_current(key(1)));
        assert_eq!(table.storage_bytes().unwrap(), bytes);
    }

    #[test]
    fn foreign_or_unprepared_adoption_closes_poll_without_retry() {
        for prepared in [false, true] {
            let mut table = OriginalTokenReservations::uninitialized();
            if prepared {
                table.initialize(1, 4096).unwrap();
            }
            let bytes = table.storage_bytes().unwrap();

            assert!(table.activate(false).is_err());
            assert!(!table.poll_current(key(0)));
            assert!(table.activate(true).is_err());
            assert!(table.initialize(1, 4096).is_err());
            assert!(table.reserve(key(0), 32, 0, 512).is_err());
            assert_eq!(table.storage_bytes().unwrap(), bytes);
        }
    }

    #[test]
    fn repeated_adoption_cannot_grow_or_renew_original_reservations() {
        let mut table = OriginalTokenReservations::uninitialized();
        table.initialize(1, 4096).unwrap();
        table.activate(true).unwrap();
        table.reserve(key(0), 32, 0, 512).unwrap();
        let bytes = table.storage_bytes().unwrap();

        assert!(table.activate(true).is_err());
        assert!(!table.selected);
        assert!(table.reserve(key(0), 32, 0, 512).is_err());
        assert!(table.initialize(2, 4096).is_err());
        assert!(table.reserve(key(1), 32, 1, 512).is_err());
        assert!(!table.poll_current(key(0)));
        assert!(!table.poll_current(key(1)));
        assert_eq!(table.storage_bytes().unwrap(), bytes);
    }

    #[test]
    fn second_preparation_cannot_adopt_first_attempts_backing() {
        let mut table = OriginalTokenReservations::uninitialized();
        table.initialize(1, 4096).unwrap();
        let bytes = table.storage_bytes().unwrap();

        assert!(table.initialize(1, 4096).is_err());
        assert!(table.poll_current(key(0)));
        assert!(table.activate(true).is_err());
        assert!(!table.poll_current(key(0)));
        assert!(table.reserve(key(0), 32, 0, 512).is_err());
        assert_eq!(table.storage_bytes().unwrap(), bytes);
    }
}
