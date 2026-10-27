//! Checks actual full packet literals for the original invocation phase.
//!
//! This proves only the absence of Query/PrepareBinding occurrences. Complete
//! envelope/schema/proof/currency validation remains with the actual selected
//! connection and historical full-class reader; this predicate grants nothing.

use crate::{ProviderError, protocol_snapshot::owned11::OriginalOwned11Fields as Fields};

pub(crate) fn authenticate_literal_data(input: &[u8]) -> Result<(), ProviderError> {
    let invalid =
        || ProviderError::Correlation("original invocation contains fresh protocol history");
    let mut fields = Fields::object(input)?;
    let mut found = false;
    while let Some((key, value)) = fields.pair()? {
        if crate::protocol_snapshot::owned11::original_owned11_plain_string(key)? != "extensions" {
            continue;
        }
        if std::mem::replace(&mut found, true) {
            return Err(invalid());
        }
        let mut extensions = Fields::object(value)?;
        while let Some((key, _)) = extensions.pair()? {
            use crate::reference_packet::service::fresh_restore_allocation::PacketNativeFreshRestoreAllocationSchema as Schema;
            let key = crate::protocol_snapshot::owned11::original_owned11_plain_string(key)?;
            if key == Schema::Query.id() || key == Schema::PrepareBinding.id() {
                return Err(invalid());
            }
        }
        extensions.finish()?;
    }
    fields.finish()?;
    if !found {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn authenticate_bank(
    bank: &crate::transport::original_frames::OriginalFrameReservation,
) -> Result<(), ProviderError> {
    for frame in bank.frames() {
        if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
            return Err(ProviderError::Correlation("invocation literal incomplete"));
        }
        authenticate_literal_data(&frame.bytes[4..])?;
    }
    Ok(())
}

pub(crate) fn counter_scratch_data() -> usize {
    2 * std::mem::size_of::<Fields<'static>>()
        + std::mem::size_of::<[u8; 128]>()
        + 4 * std::mem::size_of::<&[u8]>()
        + std::mem::size_of::<crate::transport::original_frames::OriginalFrame<'static>>()
        + std::mem::size_of::<bool>()
        + std::mem::size_of::<
            std::cell::Ref<'static, crate::transport::original_frames::OriginalFrameReservation>,
        >()
        + std::mem::size_of::<Result<(), ProviderError>>()
        + std::mem::size_of::<super::NativeInvocationConnectionView<'static>>()
        + std::mem::size_of::<super::NativeCurrentConnectionView<'static>>()
        + std::mem::size_of::<
            Result<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
                std::cell::BorrowError,
            >,
        >()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_packet::service::fresh_restore_allocation::PacketNativeFreshRestoreAllocationSchema as Schema;

    #[test]
    fn original_literal_data_refuses_each_actual_fresh_occurrence_and_ambiguous_extension_roster() {
        let mut original = serde_json::json!({"extensions":{},"body":{"extensions":{}}});
        let encoded = serde_json::to_vec(&original).unwrap();
        authenticate_literal_data(&encoded).unwrap();
        for key in [Schema::Query.id(), Schema::PrepareBinding.id()] {
            original["extensions"][key] = serde_json::json!({"retained":"actual field"});
            let encoded = serde_json::to_vec(&original).unwrap();
            assert!(authenticate_literal_data(&encoded).is_err());
            assert!(String::from_utf8(encoded).unwrap().contains("actual field"));
            original["extensions"].as_object_mut().unwrap().remove(key);
        }
        assert!(authenticate_literal_data(br#"{}"#).is_err());
        assert!(authenticate_literal_data(br#"{"extensions":{},"extensions":{}}"#).is_err());
        assert!(authenticate_literal_data(br#"{"extensions":null}"#).is_err());
    }
}
