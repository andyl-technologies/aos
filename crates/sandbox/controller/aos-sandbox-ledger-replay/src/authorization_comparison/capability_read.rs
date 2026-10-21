//! Shares the existing saved-map capability resolution and canonical decoder.

/// Resolves passive saved rows through the caller's existing strict codec.
#[macro_export]
macro_rules! resolve_current_capability_read_data_v2 {
    ($records:expr, $id:expr, $maximum:expr, $unknown:expr, $revoked:expr $(,)?) => {{

        let key = capability_key($id);
        let value = $records
            .get(RecordNamespace::PublisherAuthority, &key)
            .ok_or($unknown)?;
        let record = decode_record(&key, value, $maximum)?;
        match record.state {
            DurableCapabilityStateV1::Active => Ok(record.capability),
            DurableCapabilityStateV1::Revoked => Err($revoked),
        }
    }};
}
