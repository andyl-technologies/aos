//! Retains upper entry points for the shared pure Blob ACK geometry.
//!
//! Every private header width comes from the actual compiled upper type. The
//! true const record has no runtime initializer, native owner or frame grant.
//! Raw, successful-prefix and selected-native lifetime algorithms remain distinct.

use super::*;
use crate::bodies::{BlobBeginResult, BlobChunkResult, BlobFinishResult};
use crucible_source_birth_data::profile::reference_packet::service::native_startup::report_ack as shared;

#[cfg(test)]
use shared::native_original_canonical_output_bytes;
pub(super) use shared::{OpenAckLifetimeStorageData, serde_error_storage};

pub(in crate::connection) const ACK_FIXED_LAYOUT: shared::AckFixedLayoutData =
    shared::AckFixedLayoutData {
        response_body_bytes: size_of::<ResponseBody>(),
        received_frame_bytes: size_of::<ReceivedFrame>(),
        maximum_blob_result_bytes: {
            let begin = size_of::<BlobBeginResult>();
            let chunk = size_of::<BlobChunkResult>();
            let finish = size_of::<BlobFinishResult>();
            let first = if begin > chunk { begin } else { chunk };
            if first > finish { first } else { finish }
        },
    };

pub(super) fn successful_ack_storage() -> Result<usize, ProviderError> {
    shared::successful_ack_storage(&ACK_FIXED_LAYOUT)
}

pub(super) fn open_ack_storage(bytes: usize) -> Result<usize, ProviderError> {
    shared::open_ack_storage(bytes, &ACK_FIXED_LAYOUT)
}

pub(super) fn open_ack_lifetime_storage_data(
    bytes: usize,
) -> Result<OpenAckLifetimeStorageData, ProviderError> {
    shared::open_ack_lifetime_storage_data(bytes, &ACK_FIXED_LAYOUT)
}

pub(super) fn native_original_open_ack_lifetime_storage_data(
    bytes: usize,
) -> Result<OpenAckLifetimeStorageData, ProviderError> {
    shared::native_original_open_ack_lifetime_storage_data(bytes, &ACK_FIXED_LAYOUT)
}

pub(super) fn native_original_open_ack_storage(bytes: usize) -> Result<usize, ProviderError> {
    shared::native_original_open_ack_storage(bytes, &ACK_FIXED_LAYOUT)
}

// The lower getters count only lower facts inputs. These additional terms name
// the upper formed loan and new returned Result, plus the getter's usize return.
pub(super) const fn open_ack_lifetime_counter_scratch_data() -> usize {
    shared::open_ack_lifetime_counter_scratch_data()
        + size_of::<&shared::AckFixedLayoutData>()
        + size_of::<Result<OpenAckLifetimeStorageData, ProviderError>>()
        + size_of::<usize>()
}

pub(super) const fn native_original_open_ack_counter_scratch_data() -> usize {
    shared::native_original_open_ack_counter_scratch_data()
        + size_of::<&shared::AckFixedLayoutData>()
        // The existing native family has both real scalar and lifetime entries.
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<OpenAckLifetimeStorageData, ProviderError>>()
        + size_of::<usize>()
}

// Actual successful and raw entry arguments each introduce a lower input loan;
// their upper calls each form one loan and return one additional scalar Result.
// No upper forwarder cost is exported into the pure lower counters.
pub(super) const PREFIX_ACK_COUNTER_ADDITIONAL: usize =
    2 * size_of::<&shared::AckFixedLayoutData>()
        + 2 * size_of::<&shared::AckFixedLayoutData>()
        + 2 * size_of::<Result<usize, ProviderError>>();

#[cfg(test)]
mod canonical_output_tests {
    use super::*;
    use crucible_node_format::{Validate, canonical};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn actual_canonical_numbers_escaping_and_subtrees_fit_selected_output() -> TestResult {
        // These run the strict production parser and authoritative writer;
        // lexical expansion is checked against its actual emitted bytes.
        for (raw, expected) in [
            ("4.9406564584124654e-324", "5e-324"),
            ("1.7976931348623157e308", "1.7976931348623157e+308"),
            ("-0", "0"),
            ("1e20", "100000000000000000000"),
            ("1.0", "1"),
            ("18446744073709551615", "18446744073709552000"),
            (r#""\u00e9""#, "\"é\""),
        ] {
            let value = canonical::parse_json(raw.as_bytes(), raw.len())?;
            let output = canonical::canonical_json(&value)?;

            assert_eq!(output, expected.as_bytes());
            assert!(output.len() <= native_original_canonical_output_bytes(raw.len())?);
            assert!(canonical::parse_json(raw.as_bytes(), raw.len() - 1).is_err());
        }

        let raw = br#"{"status":"error","operation_state":"unknown","error":{"code":"PROTOCOL_ERROR","message":"retained","effect":"unknown","retryable":false,"details":{"array":[-0,1e20,5e-324,{"escaped":"\u0000\n\"\\"}],"extension":{"z":1.7976931348623157e308}}},"extensions":{}}"#;
        let value = canonical::parse_json(raw, raw.len())?;
        let body = value.as_object().ok_or("test body is not an object")?;
        let response = crate::bodies::decode_response_shape(body)?;
        response.validate()?;
        let output = canonical::canonical_json(&value)?;

        assert!(output.len() <= native_original_canonical_output_bytes(raw.len())?);
        let crate::bodies::ResponseShape::Error { error, .. } = response else {
            return Err("test response is not an Error".into());
        };
        let details = canonical::canonical_json(&Value::Object(error.details.clone()))?;
        assert!(details.len() <= native_original_canonical_output_bytes(raw.len())?);
        assert!(error.details.contains_key("array"));
        assert!(error.details.contains_key("extension"));
        Ok(())
    }

    #[test]
    fn strict_parse_failures_and_body_validation_order_are_unchanged() -> TestResult {
        for raw in [
            r#"{"x":1,"x":2}"#,
            r#"{"x":"\ud800"}"#,
            "1e309",
            "01",
            "1 true",
            "1e+",
        ] {
            assert!(canonical::parse_json(raw.as_bytes(), raw.len()).is_err());
        }

        // Canonical depth validation runs before the closed body decoder can
        // report missing Error fields, just as for the unchanged full quote.
        let mut nested = Value::Null;
        for _ in 0..65 {
            nested = Value::Array(vec![nested]);
        }
        let body = Map::from_iter([("unknown".to_owned(), nested)]);
        let expected = canonical::canonical_json(&Value::Object(body.clone()))
            .expect_err("invalid depth must refuse before typed decode");
        let actual = crate::bodies::decode_response_shape(&body)
            .expect_err("body depth validation must remain first");

        assert_eq!(actual.to_string(), expected.to_string());
        assert!(native_original_open_ack_storage(0).is_err());
        assert!(native_original_open_ack_storage(crate::transport::MAX_FRAME_BYTES + 1).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[path = "exchange_ack_storage/original.rs"]
mod original;

#[cfg(test)]
#[path = "exchange_ack_storage/relocation_tests.rs"]
mod relocation_tests;
