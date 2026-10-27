//! Bounds ordinary Bytes leaf formatter demand from one complete typed walk.
//!
//! An ordinary `Bytes` serializer temporarily owns one unpadded base64 String.
//! Those leaf calls run in sequence, so the maximum visited Bytes length bounds
//! that allocation. Some typed fields also use a compact wrapper; including them
//! is conservative. Raw Vec banks do not contribute to this Bytes-only maximum.
//! This demand neither covers other serializer work nor grants native credit.

use super::*;

/// Retains a conservative formatter maximum from actual visited Bytes leaves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OrdinaryBytesFormatterDemandData {
    maximum_input_bytes: usize,
}

impl OrdinaryBytesFormatterDemandData {
    pub(super) fn include_data(&mut self, bytes: &Bytes) {
        self.maximum_input_bytes = self.maximum_input_bytes.max(bytes.as_slice().len());
    }

    /// Returns the largest initialized length among actual visited Bytes leaves.
    pub(crate) const fn maximum_input_bytes_data(self) -> usize {
        self.maximum_input_bytes
    }

    /// Bounds one ordinary formatter by the defining encoder's exact extent.
    ///
    /// The pinned `Bytes::serialize` uses URL_SAFE_NO_PAD.encode, which creates
    /// one Vec of encoded_len(input,false) and moves that same bank into String.
    /// Its String/Vec headers are counted separately as fixed formatter views.
    /// A typed field that instead compact-streams its Bytes contributes only a
    /// conservative bound here; this method does not classify wrapper choices.
    ///
    /// # Errors
    /// Refuses an encoded extent that overflows the defining base64 calculator.
    pub(crate) fn maximum_temporary_requested_bytes_data(self) -> Result<usize, ProviderError> {
        base64::encoded_len(self.maximum_input_bytes, false).ok_or_else(overflow)
    }
}

/// Names the bound calculation and outer sequential Bytes formatter views.
///
/// As with the existing serialization counter, compiler-generated and private
/// encoder frames are not reconstructed from guessed scalar multipliers.
pub(crate) const fn ordinary_bytes_formatter_counter_scratch_data() -> usize {
    size_of::<OrdinaryBytesFormatterDemandData>()
        + size_of::<Result<OrdinaryBytesFormatterDemandData, ProviderError>>()
        + size_of::<&Bytes>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<String>()
        + size_of::<Vec<u8>>()
        + size_of::<&[u8]>()
        + size_of::<&base64::engine::general_purpose::GeneralPurpose>()
        + size_of::<usize>()
}

// crucible-lint: allow panic-shortcut -- These controls measure DATA and cannot construct a native action.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demand_matches_the_actual_unpadded_encoder_at_all_tail_boundaries() {
        for length in [0, 1, 2, 3, 4, 5, 6, 31, 32, 33, 3071, 3072, 3073] {
            let bytes = Bytes::new(vec![255; length]);
            let mut observer = MetadataObserver::new();
            observer.observe(&bytes).unwrap();
            let demand = observer.ordinary_bytes_formatter_data();
            assert_eq!(demand.maximum_input_bytes_data(), length);
            let serialized = serde_json::to_vec(&bytes).unwrap();
            assert_eq!(
                demand.maximum_temporary_requested_bytes_data().unwrap(),
                serialized.len() - 2,
            );
        }
    }

    #[test]
    fn formatter_uses_initialized_length_and_maximum_instead_of_spare_capacity_or_sum() {
        let mut backing = Vec::with_capacity(4096);
        backing.extend_from_slice(&[1, 2, 3, 4]);
        let first = Bytes::new(backing);
        let second = Bytes::new(vec![7; 65]);
        let first_capacity = first.allocation_capacity();
        let nested = Some(vec![first, second.clone()]);
        let mut observer = MetadataObserver::new();
        observer.observe(&nested).unwrap();
        observer.observe(&second).unwrap();
        let demand = observer.ordinary_bytes_formatter_data();
        assert_eq!(demand.maximum_input_bytes_data(), 65);
        assert_eq!(demand.maximum_temporary_requested_bytes_data().unwrap(), 87);
        let facts = observer.finish();
        assert!(facts.vector_capacity_bytes >= first_capacity + 2 * 65);
    }

    #[test]
    fn ordinary_formatter_demand_does_not_charge_compact_raw_vec_backing() {
        let mut compact_bank = Vec::<u8>::with_capacity(1_048_576);
        compact_bank.extend_from_slice(&[0; 32]);
        let mut observer = MetadataObserver::new();
        observer.observe(&compact_bank).unwrap();
        let demand = observer.ordinary_bytes_formatter_data();
        assert_eq!(demand.maximum_input_bytes_data(), 0);
        assert_eq!(demand.maximum_temporary_requested_bytes_data().unwrap(), 0);
        assert_eq!(
            observer.finish().vector_capacity_bytes,
            compact_bank.capacity()
        );
    }

    #[test]
    fn recording_constructors_keep_the_same_formatter_and_capacity_facts() {
        let value = Bytes::new(vec![4; 127]);
        let mut plain = MetadataObserver::new();
        plain.observe(&value).unwrap();
        let expected_formatter = plain.ordinary_bytes_formatter_data();
        let expected_facts = plain.finish();

        let mut records = MetadataRecordBank::reserve(8).unwrap();
        let mut recorded = MetadataObserver::recording(&mut records);
        recorded.observe(&value).unwrap();
        assert_eq!(recorded.ordinary_bytes_formatter_data(), expected_formatter);
        assert_eq!(recorded.finish(), expected_facts);
        assert_eq!(records.rows().len(), 1);

        let mut records = MetadataRecordBank::reserve(8).unwrap();
        let mut aliases = aliases::MetadataAliasBank::reserve(8).unwrap();
        let mut recorded = MetadataObserver::recording_with_aliases(&mut records, &mut aliases);
        recorded.observe(&value).unwrap();
        assert_eq!(recorded.ordinary_bytes_formatter_data(), expected_formatter);
        assert_eq!(recorded.finish(), expected_facts);
        assert_eq!(records.rows().len(), 1);
        assert_eq!(aliases.retained_rows(), 0);
    }

    #[test]
    fn formatter_note_preserves_the_existing_capacity_facts() {
        let value = Bytes::new(vec![0; 43]);
        let mut ordinary = MetadataObserver::new();
        value.observe_metadata(&mut ordinary).unwrap();
        let mut previous = MetadataObserver::new();
        previous.vector::<u8>(value.allocation_capacity()).unwrap();
        assert_eq!(ordinary.finish(), previous.finish());
        assert!(
            OrdinaryBytesFormatterDemandData {
                maximum_input_bytes: usize::MAX
            }
            .maximum_temporary_requested_bytes_data()
            .is_err()
        );
    }
}
