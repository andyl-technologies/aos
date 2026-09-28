//! Bounded transaction preparation using the journal's existing record codec.
//!
//! The wrapper preserves transaction identity and ordered native record bytes;
//! it is not a committed journal, proof of protected persistence, or authority.
//! Native frame, payload, and namespace semantics remain owned by `journal`.
//! Wrapper integers are big endian; native record payload fields retain the
//! existing journal's little-endian layout rather than a duplicate format.
//!
//! ```text
//! AOSJPT01 | version:u16be=1 | reserved:u16be=0 | transaction-ID:16 |
//! record-count:u32be | repeated(record-length:u32be | native-record-payload)
//! ```

use super::{
    JournalError, JournalLimits, JournalTransaction, decode_record, encode_record,
    validate_transaction,
};

const MAGIC: &[u8; 8] = b"AOSJPT01";
const HEADER_BYTES: usize = 32;

impl JournalTransaction {
    /// Returns the maximum bounded preparation width for the supplied native limits.
    ///
    /// This is sizing only and reserves no disk, memory, or journal capacity.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits or overflowing framing arithmetic.
    #[doc(hidden)]
    pub fn maximum_prepared_bytes_v1(limits: JournalLimits) -> Result<usize, JournalError> {
        super::validate_limits(limits)?;
        limits
            .maximum_records_per_transaction
            .checked_mul(4)
            .and_then(|framing| framing.checked_add(HEADER_BYTES))
            .and_then(|framing| framing.checked_add(limits.maximum_transaction_bytes))
            .ok_or(JournalError::LimitExceeded("prepared transaction bytes"))
    }

    /// Encodes one exact bounded transaction without writing or committing it.
    ///
    /// Reuses the ordinary journal record encoder and validation, including
    /// namespace codes, put/delete representation, keys, and aggregate limits.
    ///
    /// # Errors
    ///
    /// Rejects invalid or oversized native records, duplicate keys, a zero ID,
    /// and framing fields exceeding their integer widths.
    #[doc(hidden)]
    pub fn encode_prepared_v1(&self, limits: JournalLimits) -> Result<Vec<u8>, JournalError> {
        let maximum_bytes = Self::maximum_prepared_bytes_v1(limits)?;
        validate_transaction(self, limits)?;
        let count = u32::try_from(self.records.len())
            .map_err(|_| JournalError::LimitExceeded("prepared record count"))?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&count.to_be_bytes());
        for record in &self.records {
            let payload = encode_record(record)?;
            let length = u32::try_from(payload.len())
                .map_err(|_| JournalError::LimitExceeded("prepared record bytes"))?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&payload);
        }
        if bytes.len() > maximum_bytes {
            return Err(JournalError::LimitExceeded("prepared transaction bytes"));
        }
        Ok(bytes)
    }

    /// Decodes only an exact bounded preparation, not a committed journal frame.
    ///
    /// The result is ordinary transaction data. A protected owner must separately
    /// validate provenance, exact predecessor/current HEAD, and admission limits.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing/version/reserved bytes, truncation or padding,
    /// zero IDs, count/record/aggregate overflow, and malformed native records.
    #[doc(hidden)]
    pub fn decode_prepared_v1(bytes: &[u8], limits: JournalLimits) -> Result<Self, JournalError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > Self::maximum_prepared_bytes_v1(limits)?
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[8..12] != [0, 1, 0, 0]
        {
            return Err(JournalError::MalformedTransaction(
                "invalid preparation framing",
            ));
        }
        let id = read_array(bytes, 12)?;
        if id == [0; 16] {
            return Err(JournalError::InvalidTransaction);
        }
        let count = usize::try_from(u32::from_be_bytes(read_array(bytes, 28)?))
            .map_err(|_| JournalError::LimitExceeded("prepared record count"))?;
        if count == 0
            || count > limits.maximum_records_per_transaction
            || count
                .checked_mul(12)
                .and_then(|minimum| minimum.checked_add(HEADER_BYTES))
                .is_none_or(|minimum| minimum > bytes.len())
        {
            return Err(JournalError::LimitExceeded("prepared record count"));
        }
        let mut cursor = HEADER_BYTES;
        let mut records = Vec::with_capacity(count);
        let mut payload_bytes = 0_usize;
        for _ in 0..count {
            let length = usize::try_from(u32::from_be_bytes(read_array(bytes, cursor)?))
                .map_err(|_| JournalError::LimitExceeded("prepared record bytes"))?;
            cursor = cursor
                .checked_add(4)
                .ok_or(JournalError::LimitExceeded("prepared transaction bytes"))?;
            if length < 7 || length > limits.maximum_record_bytes {
                return Err(JournalError::LimitExceeded("prepared record bytes"));
            }
            let end = cursor
                .checked_add(length)
                .ok_or(JournalError::LimitExceeded("prepared transaction bytes"))?;
            let payload = bytes
                .get(cursor..end)
                .ok_or(JournalError::MalformedTransaction("truncated preparation"))?;
            payload_bytes = payload_bytes
                .checked_add(length)
                .filter(|total| *total <= limits.maximum_transaction_bytes)
                .ok_or(JournalError::LimitExceeded("transaction bytes"))?;
            records.push(decode_record(payload, limits)?);
            cursor = end;
        }
        if cursor != bytes.len() {
            return Err(JournalError::MalformedTransaction("padded preparation"));
        }
        let transaction = Self::new(id, records)?;
        validate_transaction(&transaction, limits)?;
        Ok(transaction)
    }
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], JournalError> {
    let end = offset
        .checked_add(N)
        .ok_or(JournalError::LimitExceeded("prepared transaction bytes"))?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(JournalError::MalformedTransaction("truncated preparation"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalRecord, RecordNamespace};

    fn transaction() -> JournalTransaction {
        JournalTransaction::new(
            [7; 16],
            vec![
                JournalRecord::put(RecordNamespace::BrokerSessionTraffic, b"a".to_vec(), vec![]),
                JournalRecord::delete(RecordNamespace::BrokerSessionTraffic, b"b".to_vec()),
            ],
        )
        .unwrap()
    }

    #[test]
    fn journal_prepared_transaction_roundtrip_preserves_identity_order_and_empty_put() {
        let transaction = transaction();
        let bytes = transaction
            .encode_prepared_v1(JournalLimits::default())
            .unwrap();
        assert_eq!(
            JournalTransaction::decode_prepared_v1(&bytes, JournalLimits::default()).unwrap(),
            transaction
        );
        assert_eq!(
            &bytes[..32],
            &[
                b"AOSJPT01".as_slice(),
                &[0, 1, 0, 0],
                &[7; 16],
                &[0, 0, 0, 2]
            ]
            .concat()
        );
        // Literal native payloads, independently laid out from the existing
        // record format: namespace47, key length LE, value length LE (or delete).
        assert_eq!(
            &bytes[32..],
            &[
                0, 0, 0, 8, 47, 1, 0, 0, 0, 0, 0, b'a', 0, 0, 0, 8, 47, 1, 0, 255, 255, 255, 255,
                b'b',
            ]
        );
    }

    #[test]
    fn journal_prepared_transaction_rejects_hostile_framing_and_native_payload() {
        let bytes = transaction()
            .encode_prepared_v1(JournalLimits::default())
            .unwrap();
        for offset in [0, 8, 9, 10, 11, 31] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            assert!(
                JournalTransaction::decode_prepared_v1(&changed, JournalLimits::default()).is_err(),
                "offset {offset}"
            );
        }
        for end in 0..bytes.len() {
            assert!(
                JournalTransaction::decode_prepared_v1(&bytes[..end], JournalLimits::default())
                    .is_err()
            );
        }
        let mut padded = bytes.clone();
        padded.push(0);
        assert!(JournalTransaction::decode_prepared_v1(&padded, JournalLimits::default()).is_err());
        let mut zero_id = bytes.clone();
        zero_id[12..28].fill(0);
        assert!(
            JournalTransaction::decode_prepared_v1(&zero_id, JournalLimits::default()).is_err()
        );
        let mut overflowing = bytes;
        overflowing[32..36].fill(255);
        assert!(
            JournalTransaction::decode_prepared_v1(&overflowing, JournalLimits::default()).is_err()
        );
    }

    #[test]
    fn journal_prepared_transaction_checks_actual_native_and_aggregate_limits() {
        let transaction = transaction();
        let bytes = transaction
            .encode_prepared_v1(JournalLimits::default())
            .unwrap();
        for limits in [
            JournalLimits {
                maximum_records_per_transaction: 1,
                ..JournalLimits::default()
            },
            JournalLimits {
                maximum_record_bytes: 7,
                ..JournalLimits::default()
            },
            JournalLimits {
                maximum_transaction_bytes: 7,
                ..JournalLimits::default()
            },
        ] {
            assert!(transaction.encode_prepared_v1(limits).is_err());
            assert!(JournalTransaction::decode_prepared_v1(&bytes, limits).is_err());
        }
    }
}
