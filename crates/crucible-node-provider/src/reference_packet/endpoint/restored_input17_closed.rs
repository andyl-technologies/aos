//! Closes every legacy Endpoint dispatch path to the distinct Input17 family.
//!
//! The ordinary selected wire codec parses transport DATA only. Until a genuine
//! same-Boot Source-MAC/action-row dispatcher is installed, none of that family
//! may reach older restoration, upload, control or observation implementations.
//! The caller retains the original literal and sticky Endpoint before this check.

use super::*;
use crate::reference_packet::service::restored_input_reactive17::RESTORED_INPUT_REACTIVE17_FEATURE;
#[cfg(test)]
use serde_json::Value;

pub(super) fn require_legacy_dispatch_data(original: &Envelope) -> Result<(), ProviderError> {
    if original
        .extensions
        .contains_key(RESTORED_INPUT_REACTIVE17_FEATURE)
    {
        return Err(ProviderError::Correlation(
            "Input17 native action dispatcher not installed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_input17_method_is_closed_even_with_forged_or_mixed_artifacts() {
        for method in [
            Method::Input,
            Method::Begin,
            Method::Poll,
            Method::Retire,
            Method::Observe,
            Method::BlobBegin,
            Method::BlobChunk,
            Method::BlobFinish,
        ] {
            for artifact in [
                Value::Null,
                json!({"request":{"native_allocation":{
                "retained_requested_bytes":"18446744073709551615"}},"proof":{}}),
            ] {
                let mut original = crate::envelope::tests::request();
                original.method = method;
                original.extensions.clear();
                original
                    .extensions
                    .insert(RESTORED_INPUT_REACTIVE17_FEATURE.into(), artifact);
                assert!(matches!(
                    require_legacy_dispatch_data(&original),
                    Err(ProviderError::Correlation(
                        "Input17 native action dispatcher not installed"
                    ))
                ));
                original
                    .extensions
                    .insert("source-owned.packet-input/4".into(), json!({}));
                assert!(require_legacy_dispatch_data(&original).is_err());
            }
        }
    }

    #[test]
    fn closure_does_not_replace_the_existing_legacy_dispatch_guards() {
        for method in [
            Method::Input,
            Method::Begin,
            Method::Poll,
            Method::Retire,
            Method::Observe,
            Method::BlobBegin,
            Method::BlobChunk,
            Method::BlobFinish,
        ] {
            let mut original = crate::envelope::tests::request();
            original.method = method;
            original.extensions.clear();
            require_legacy_dispatch_data(&original).unwrap();
            original
                .extensions
                .insert("source-owned.packet-input/4".into(), json!({}));
            require_legacy_dispatch_data(&original).unwrap();
        }
    }
}
