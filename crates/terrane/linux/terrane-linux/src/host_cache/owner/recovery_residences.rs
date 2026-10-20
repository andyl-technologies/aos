//! Chooses one verified residence per chunk across supported recovery bodies.
//!
//! Input records remain candidate policy. Their native/source verification and
//! durable owner synchronization are separate requirements. Duplicate verified
//! occurrences do not require duplicate embedded residence records.

use std::{collections::BTreeMap, io};
use terrane_sdk::host::cache::ResidenceRecord;

/// Accumulates bounded deterministic residence selection without native effects.
pub(super) struct ResidenceSelection {
    records: BTreeMap<String, ResidenceRecord>,
    preferred: BTreeMap<String, ResidenceRecord>,
    limit: usize,
}

impl ResidenceSelection {
    /// Bounds actual outputs and original cold preferences by the state budget.
    ///
    /// Preferences supply no output records. An exact original range must
    /// independently arrive through [`Self::extend`] before it can be selected.
    ///
    /// # Errors
    /// Refuses duplicate preference keys or more preferences than the limit.
    pub(super) fn new(limit: usize, preferred: &[ResidenceRecord]) -> io::Result<Self> {
        if preferred.len() > limit {
            return Err(invalid("cold residence preferences exceed state budget"));
        }
        let mut candidates = BTreeMap::new();
        for record in preferred {
            if candidates
                .insert(record.chunk.clone(), record.clone())
                .is_some()
            {
                return Err(invalid("cold residence preference duplicates a chunk"));
            }
        }
        Ok(Self {
            records: BTreeMap::new(),
            preferred: candidates,
            limit,
        })
    }

    /// Selects a verified original range, otherwise the earliest canonical range.
    ///
    /// # Errors
    /// Refuses conflicting lengths, overflowing ranges and configured capacity.
    /// Duplicate chunks never silently change their verified plaintext length.
    pub(super) fn extend(
        &mut self,
        records: impl IntoIterator<Item = ResidenceRecord>,
    ) -> io::Result<()> {
        for record in records {
            record
                .offset
                .checked_add(record.length)
                .ok_or_else(|| invalid("recovered residence range overflows"))?;
            if let Some(previous) = self.records.get_mut(&record.chunk) {
                if previous.length != record.length {
                    return Err(invalid(
                        "one verified chunk has conflicting recovered lengths",
                    ));
                }
                let preferred = self.preferred.get(&record.chunk);
                let incoming_original = preferred.is_some_and(|old| same_range(old, &record));
                let retained_original = preferred.is_some_and(|old| same_range(old, previous));
                if incoming_original
                    || (!retained_original
                        && (&record.object, record.offset) < (&previous.object, previous.offset))
                {
                    *previous = record;
                }
            } else {
                if self.records.len() >= self.limit {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        "recovered residences exceed state record budget",
                    ));
                }
                self.records.insert(record.chunk.clone(), record);
            }
        }
        Ok(())
    }

    /// Returns canonical chunk order for final bounded state validation.
    pub(super) fn finish(self) -> Vec<ResidenceRecord> {
        self.records.into_values().collect()
    }
}

fn same_range(a: &ResidenceRecord, b: &ResidenceRecord) -> bool {
    a.chunk == b.chunk && a.object == b.object && a.offset == b.offset && a.length == b.length
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn range(chunk: &str, object: &str, offset: u64, length: u64) -> ResidenceRecord {
        ResidenceRecord {
            chunk: chunk.into(),
            object: object.into(),
            offset,
            length,
        }
    }

    #[test]
    fn repeated_occurrences_select_one_stable_range_independent_of_scan_order() {
        let records = vec![
            range("chunk", "b", 0, 3),
            range("chunk", "a", 9, 3),
            range("chunk", "a", 2, 3),
        ];
        let mut first = ResidenceSelection::new(1, &[]).unwrap();
        first.extend(records.clone()).unwrap();
        let mut second = ResidenceSelection::new(1, &[]).unwrap();
        second.extend(records.clone().into_iter().rev()).unwrap();
        for selected in [first.finish(), second.finish()] {
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].object, "a");
            assert_eq!(selected[0].offset, 2);
        }

        // Existing valid backing wins even when another verified copy sorts
        // earlier. A preference alone never fabricates an output residence.
        for input in [records.clone(), records.clone().into_iter().rev().collect()] {
            let mut selected = ResidenceSelection::new(1, &[range("chunk", "b", 0, 3)]).unwrap();
            selected.extend(input).unwrap();
            assert_eq!(selected.finish()[0].object, "b");
        }
        let mut missing =
            ResidenceSelection::new(1, &[range("chunk", "unobserved", 0, 3)]).unwrap();
        assert!(missing.records.is_empty());
        missing.extend(records).unwrap();
        assert_eq!(missing.finish()[0].object, "a");
    }

    #[test]
    fn conflicts_and_capacity_are_refused_without_clearing_prior_candidates() {
        assert!(ResidenceSelection::new(0, &[range("one", "body", 0, 3)]).is_err());
        assert!(
            ResidenceSelection::new(
                2,
                &[range("one", "body", 0, 3), range("one", "other", 0, 3)]
            )
            .is_err()
        );

        let mut selected = ResidenceSelection::new(1, &[]).unwrap();
        selected.extend([range("one", "body", 0, 3)]).unwrap();
        assert!(selected.extend([range("one", "body", 0, 4)]).is_err());
        assert!(selected.extend([range("two", "body", 3, 3)]).is_err());
        assert_eq!(selected.finish()[0].length, 3);
    }
}
