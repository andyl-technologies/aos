//! Conservative validation admission and observed vector-capacity charges.
//!
//! Names and table slots stay in immutable input. The remaining heterogeneous
//! decoder/map allocations retain the existing 64-times-encoded model; that
//! model is deliberately conservative, not an allocator-exact heap ledger.

use super::input::ValidatedInput;
use super::*;

const DECODED_RECORD_FACTOR: u64 = 64;
const SCRATCH_OVERHEAD: u64 = 4_096;
const PATH_BASE: u64 = 256;
const PATH_COMPONENT: u64 = 128 + 255 * 4;

pub(super) struct ValidationBudget {
    records: usize,
    seen_bytes: usize,
    scratch: u64,
    hardlink_records: u64,
    pub(super) hardlink_paths: u64,
}

impl ValidationBudget {
    /// Scans bounded borrowed frames only; full semantics remain in validate_record.
    pub(super) fn estimate(
        input: &ValidatedInput<'_>,
        artifact: ObjectDigest,
    ) -> Result<Self, IndexError> {
        let seen_bytes = input.record_capacity.div_ceil(8);
        let mut peak_record = 0_u64;
        let mut hardlink_records = 0_u64;
        let mut hardlink_paths = 0_u64;
        let mut offset = 0_usize;
        for id in 0..input.summary.records {
            let view = decode_record_view(input.records, offset, id, artifact)?;
            let encoded =
                u64::try_from(view.encoded_record.len()).map_err(|_| IndexError::LimitExceeded)?;
            peak_record = peak_record.max(encoded);
            if record_hardlink_group(view.encoded_record, view.kind)?.is_some() {
                hardlink_records = hardlink_records
                    .checked_add(encoded)
                    .ok_or(IndexError::LimitExceeded)?;
                // Every validated component is at most 255 bytes. The actual
                // ancestry/depth join is still checked by the full validator.
                let path = u64::from(view.depth)
                    .checked_mul(PATH_COMPONENT)
                    .and_then(|bytes| bytes.checked_add(PATH_BASE))
                    .ok_or(IndexError::LimitExceeded)?;
                hardlink_paths = hardlink_paths
                    .checked_add(path)
                    .ok_or(IndexError::LimitExceeded)?;
            }
            offset = offset
                .checked_add(view.encoded_record.len())
                .ok_or(IndexError::LimitExceeded)?;
        }
        if offset != input.records.len() {
            return Err(IndexError::InvalidRecord);
        }
        Ok(Self {
            records: input.record_capacity,
            seen_bytes,
            scratch: peak_record
                .checked_mul(DECODED_RECORD_FACTOR)
                .and_then(|bytes| bytes.checked_add(SCRATCH_OVERHEAD))
                .ok_or(IndexError::LimitExceeded)?,
            hardlink_records: hardlink_records
                .checked_mul(DECODED_RECORD_FACTOR)
                .ok_or(IndexError::LimitExceeded)?,
            hardlink_paths,
        })
    }

    pub(super) fn requested_vector_bytes(&self) -> Result<u64, IndexError> {
        Self::vector_bytes(self.records, self.seen_bytes, self.records)
    }

    fn vector_bytes(nodes: usize, seen: usize, nlinks: usize) -> Result<u64, IndexError> {
        let nodes = vector_charge::<IndexNodeRecord<'_>>(nodes)?;
        let seen = vector_charge::<u8>(seen)?;
        let nlinks = vector_charge::<u64>(nlinks)?;
        nodes
            .checked_add(seen)
            .and_then(|bytes| bytes.checked_add(nlinks))
            .ok_or(IndexError::LimitExceeded)
    }

    pub(super) fn total(&self, vector_bytes: u64) -> Result<u64, IndexError> {
        vector_bytes
            .checked_add(self.scratch)
            .and_then(|bytes| bytes.checked_add(self.hardlink_records))
            .and_then(|bytes| bytes.checked_add(self.hardlink_paths))
            .ok_or(IndexError::LimitExceeded)
    }

    pub(super) fn require(&self, vectors: u64, maximum: u64) -> Result<(), IndexError> {
        if self.total(vectors)? > maximum {
            return Err(IndexError::LimitExceeded);
        }
        Ok(())
    }

    pub(super) fn reserve_vectors<'a>(
        &self,
        nodes: &mut Vec<IndexNodeRecord<'a>>,
        seen: &mut Vec<u8>,
        nlinks: &mut Vec<u64>,
        maximum: u64,
    ) -> Result<(), IndexError> {
        self.require(self.requested_vector_bytes()?, maximum)?;
        reserve_exact(nodes, self.records)?;
        self.require(
            Self::vector_bytes(nodes.capacity(), self.seen_bytes, self.records)?,
            maximum,
        )?;
        reserve_exact(seen, self.seen_bytes)?;
        self.require(
            Self::vector_bytes(nodes.capacity(), seen.capacity(), self.records)?,
            maximum,
        )?;
        reserve_exact(nlinks, self.records)?;
        self.require(
            Self::vector_bytes(nodes.capacity(), seen.capacity(), nlinks.capacity())?,
            maximum,
        )?;
        seen.resize(self.seen_bytes, 0);
        Ok(())
    }
}

/// Performs one already-admitted, fallible vector allocation without hidden growth.
fn reserve_exact<T>(values: &mut Vec<T>, capacity: usize) -> Result<(), IndexError> {
    values
        .try_reserve_exact(capacity)
        .map_err(|_| IndexError::AllocationRefused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_unrepresentable_allocation_is_refused() {
        // Exercise the same checked admission/allocation path with a byte
        // capacity that is representable in the model but not in a Rust Vec.
        // No hostile-size allocation can reach the allocator for this value.
        let model = ValidationBudget {
            records: 1,
            seen_bytes: isize::MAX as usize + 1,
            scratch: 4_096,
            hardlink_records: 0,
            hardlink_paths: 0,
        };
        model
            .require(model.requested_vector_bytes().unwrap(), u64::MAX)
            .unwrap();
        let mut nodes = Vec::new();
        let mut bytes: Vec<u8> = Vec::new();
        let mut nlinks = Vec::new();
        assert!(matches!(
            model.reserve_vectors(&mut nodes, &mut bytes, &mut nlinks, u64::MAX),
            Err(IndexError::AllocationRefused)
        ));
        assert_eq!(bytes.capacity(), 0);
        assert_eq!(nlinks.capacity(), 0);
    }

    #[test]
    fn observed_capacity_overage_refuses_before_remaining_vectors_grow() {
        let model = ValidationBudget {
            records: 1,
            seen_bytes: 1,
            scratch: 4_096,
            hardlink_records: 0,
            hardlink_paths: 0,
        };
        let cap = model
            .total(model.requested_vector_bytes().unwrap())
            .unwrap();
        let mut nodes = Vec::with_capacity(2);
        let mut seen = Vec::new();
        let mut nlinks = Vec::new();
        assert!(matches!(
            model.reserve_vectors(&mut nodes, &mut seen, &mut nlinks, cap),
            Err(IndexError::LimitExceeded)
        ));
        assert!(nodes.is_empty());
        assert_eq!(seen.capacity(), 0);
        assert_eq!(nlinks.capacity(), 0);
    }

    #[test]
    fn checked_live_charge_rejects_overflow() {
        assert!(matches!(
            ValidationBudget::vector_bytes(usize::MAX, 0, 0),
            Err(IndexError::LimitExceeded)
        ));
        let model = ValidationBudget {
            records: 0,
            seen_bytes: 0,
            scratch: u64::MAX,
            hardlink_records: 1,
            hardlink_paths: 0,
        };
        assert!(matches!(model.total(0), Err(IndexError::LimitExceeded)));
    }
}
