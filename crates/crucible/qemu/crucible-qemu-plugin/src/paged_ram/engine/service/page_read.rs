//! Borrows an entered PageIn Original through authenticated backing reads.
//!
//! Backing transport completes a page exchange, while its parent retains its
//! total start through population, state publication, wake and final settlement.
//! This adapter issues no operation, native writer participant or page fence.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::paged_ram::source::ObservationOperationError;
use std::time::Duration;

/// Reports one authenticated page as progress on the still-live page owner.
struct PageReadOperation<'a> {
    original: &'a dyn SourceOperation,
    completed: AtomicBool,
}

impl SourceOperation for PageReadOperation<'_> {
    fn wait_slice(&self) -> io::Result<Duration> {
        self.wait_slice_for_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
        if self.completed.load(Ordering::Acquire) {
            return Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "page backing exchange already completed",
            });
        }
        self.original.wait_slice_for_observation()
    }

    fn complete(&self) -> io::Result<()> {
        self.complete_observation()
            .map_err(ObservationOperationError::into_io)
    }

    fn complete_observation(&self) -> Result<(), ObservationOperationError> {
        self.wait_slice_for_observation()?;
        self.completed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ObservationOperationError::Static {
                kind: io::ErrorKind::Other,
                message: "page backing exchange completed twice",
            })?;
        // Each adapter performs at most one backing read. Only verified
        // page completion qualifies; transport polls and bytes report no units.
        self.original
            .progress(1)
            .map_err(ObservationOperationError::Io)
    }
}

impl FaultService {
    /// Reads preservation under a fault or prefetch operation already entered.
    ///
    /// # Errors
    /// Preserves source, spill, authentication or Original refusal. Failure
    /// publishes neither resident state nor an accessor wake.
    pub(in crate::paged_ram::engine) fn read_page_source(
        &self,
        arena: &Arena,
        page_index: u64,
        coordinate: usize,
        original: &dyn SourceOperation,
        scratch: &mut [u8; PAGE_BYTES],
    ) -> Result<u32, RamError> {
        let exchange = PageReadOperation {
            original,
            completed: AtomicBool::new(false),
        };
        let record = self
            .states
            .try_lock()
            .map_err(|_| "page preservation ownership unavailable")?
            .get(coordinate)
            .ok_or("page preservation coordinate absent")?
            .preserved
            .clone();
        if let Some(record) = record {
            exchange
                .wait_slice_for_observation()
                .map_err(SourceFetchError::from)
                .map_err(SourceFetchError::into_ram)?;
            let spill = self
                .spill
                .try_lock()
                .map_err(|_| "page spill ownership unavailable")?;
            spill
                .read_with_borrowed_hasher(&record, scratch, None)
                .map_err(SourceFetchError::into_ram)?;
            drop(spill);
            exchange
                .complete_observation()
                .map_err(SourceFetchError::from)
                .map_err(SourceFetchError::into_ram)?;
            count_completed(&self.counters.preserved_reads)?;
            return Ok(record.valid_length());
        }
        let source = self
            .source
            .as_ref()
            .ok_or("cold page has no authenticated preservation")?;
        source
            .fetch_with_retained_operation(
                arena.native.region_index,
                page_index,
                &exchange,
                scratch,
                None,
            )
            .map(|(valid, _)| valid)
            .map_err(SourceFetchError::into_ram)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct Original {
        canceled: AtomicBool,
        completed_units: AtomicU64,
        terminal_completions: AtomicUsize,
    }

    impl SourceOperation for Original {
        fn wait_slice(&self) -> io::Result<Duration> {
            self.wait_slice_for_observation()
                .map_err(ObservationOperationError::into_io)
        }

        fn wait_slice_for_observation(&self) -> Result<Duration, ObservationOperationError> {
            if self.canceled.load(Ordering::Acquire) {
                return Err(ObservationOperationError::Static {
                    kind: io::ErrorKind::Interrupted,
                    message: "the supplied fault Original canceled",
                });
            }
            Ok(Duration::from_micros(500))
        }

        fn progress(&self, units: u64) -> io::Result<()> {
            self.wait_slice()?;
            self.completed_units.store(units, Ordering::Release);
            Ok(())
        }

        fn complete(&self) -> io::Result<()> {
            self.wait_slice()?;
            self.terminal_completions.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn complete_observation(&self) -> Result<(), ObservationOperationError> {
            self.complete().map_err(ObservationOperationError::Io)
        }
    }

    fn original() -> Original {
        Original {
            canceled: AtomicBool::new(false),
            completed_units: AtomicU64::new(0),
            terminal_completions: AtomicUsize::new(0),
        }
    }

    #[test]
    fn authenticated_backing_completion_keeps_the_fault_original_open() {
        let original = original();
        let exchange = PageReadOperation {
            original: &original,
            completed: AtomicBool::new(false),
        };

        exchange.complete_observation().unwrap();

        assert_eq!(original.completed_units.load(Ordering::Acquire), 1);
        assert_eq!(original.terminal_completions.load(Ordering::Acquire), 0);
        assert!(exchange.complete_observation().is_err());
        assert_eq!(original.wait_slice().unwrap(), Duration::from_micros(500));
        original.complete().unwrap();
        assert_eq!(original.terminal_completions.load(Ordering::Acquire), 1);
    }

    #[test]
    fn canceled_fault_original_cannot_publish_backing_progress() {
        let original = original();
        let exchange = PageReadOperation {
            original: &original,
            completed: AtomicBool::new(false),
        };
        original.canceled.store(true, Ordering::Release);

        let failure = exchange.complete_observation();

        assert!(matches!(
            failure,
            Err(ObservationOperationError::Static {
                kind: io::ErrorKind::Interrupted,
                message: "the supplied fault Original canceled",
            })
        ));
        assert_eq!(original.completed_units.load(Ordering::Acquire), 0);
        assert_eq!(original.terminal_completions.load(Ordering::Acquire), 0);
        assert!(!exchange.completed.load(Ordering::Acquire));
    }
}
