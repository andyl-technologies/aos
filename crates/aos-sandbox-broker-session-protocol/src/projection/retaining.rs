//! Retains partial canonical protobuf projections at their existing failure boundaries.
//!
//! These captures contain comparison DATA only. They neither authenticate a peer
//! nor fund an operation. Ordinary callers use the same validation engine with
//! local values; selected callers park the actual message before Buffa merges it.

use super::*;
use std::ops::{Deref, DerefMut};

// Local values keep the ordinary lexical destruction order. Retained values are
// installed before the next fallible step and survive an error in the caller.
pub(crate) enum CaptureValueV1<'a, T> {
    Local(T),
    Retained(&'a mut T),
}

impl<'a, T: Default> CaptureValueV1<'a, T> {
    pub(crate) fn new(value: T, capture: Option<&'a mut Option<T>>) -> Self {
        match capture {
            Some(capture) => Self::Retained(capture.insert(value)),
            None => Self::Local(value),
        }
    }

    pub(crate) fn take(self) -> T {
        match self {
            Self::Local(value) => value,
            Self::Retained(value) => std::mem::take(value),
        }
    }

    fn dispose(self) {
        match self {
            Self::Local(value) => drop(value),
            Self::Retained(value) => drop(std::mem::take(value)),
        }
    }
}

impl<T> Deref for CaptureValueV1<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self {
            Self::Local(value) => value,
            Self::Retained(value) => value,
        }
    }
}

impl<T> DerefMut for CaptureValueV1<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        match self {
            Self::Local(value) => value,
            Self::Retained(value) => value,
        }
    }
}

fn decode_message<'a, M: buffa::Message>(
    bytes: &[u8],
    capture: Option<&'a mut Option<M>>,
    decode_result: Option<&mut Option<Result<(), buffa::DecodeError>>>,
) -> Result<CaptureValueV1<'a, M>, BrokerSessionProjectionError> {
    if capture.is_none() {
        // Preserve Buffa's ordinary partial-message destruction before mapping
        // the parser error to the existing diagnostic String.
        return M::decode_from_slice(bytes)
            .map(CaptureValueV1::Local)
            .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()));
    }

    let mut message = CaptureValueV1::new(M::default(), capture);
    let result = message.merge_retaining_from_slice(bytes);
    let mapped = result.as_ref().map(|_| ())
        .map_err(|error| BrokerSessionProjectionError::Malformed(error.to_string()));
    if let Some(capture) = decode_result {
        *capture = Some(result);
    }
    mapped?;
    Ok(message)
}

macro_rules! projection_capture {
    ($capture:ident, $message:ty, $model:ty, $signed:ty, $decode:ident, $engine:ident) => {
        /// Retains one reached canonical decode, including its partial protobuf.
        ///
        /// A successful model moves to its consumer once. Failed canonical or
        /// cleared encodings remain here; successfully compared canonical scratch
        /// is disposed at its original final borrower. This is comparison DATA.
        #[derive(Default)]
        pub struct $capture {
            message: Option<$message>,
            canonical: Option<Vec<u8>>,
            cleared: Option<Vec<u8>>,
            signed: Option<$signed>,
            features: FeatureValidationCaptureV1,
            decode_result: Option<Result<(), buffa::DecodeError>>,
            model: Option<$model>,
            result: Option<Result<(), BrokerSessionProjectionError>>,
            attempted: bool,
            closed: Option<BrokerSessionProjectionError>,
        }

        impl $capture {
            /// Constructs an empty, once-only decode capture.
            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }

            /// Borrows the original failure without moving the partial model.
            #[must_use]
            pub fn failure(&self) -> Option<&BrokerSessionProjectionError> {
                self.result.as_ref().and_then(|result| result.as_ref().err())
                    .or(self.closed.as_ref())
            }

            /// Borrows the fully validated canonical model when complete.
            #[must_use]
            pub fn model(&self) -> Option<&$model> {
                if self.closed.is_none() && matches!(self.result, Some(Ok(()))) {
                    self.model.as_ref()
                } else { None }
            }

            /// Moves the fully validated model to its actual consumer once.
            ///
            /// # Errors
            /// Returns the original failure, or invalid semantics before success
            /// and after the completed model has already been moved.
            pub fn take_model_once(&mut self) -> Result<$model, BrokerSessionProjectionError> {
                if let Some(error) = self.failure() {
                    return Err(error.clone());
                }
                self.model.take().ok_or(BrokerSessionProjectionError::InvalidSemantics)
            }

            /// Returns this actual inline owner extent, excluding dynamic storage.
            #[must_use]
            pub const fn inline_bytes_v1() -> usize {
                std::mem::size_of::<Self>()
            }

            /// Bounds fixed receiving field/control cells, excluding model allocations.
            ///
            /// Counts message/canonical/cleared/signed/model slots, the feature
            /// table/current-input/registry-result slots, parser and outer Results,
            /// attempted and closed state. Dynamic protobuf cells are priced by
            /// the caller's shared schema supplier, not by this inline count.
            #[must_use]
            pub const fn receiving_metadata_cells_v1() -> Option<usize> {
                Some(12)
            }
        }

        /// Decodes through the existing canonical engine while retaining partial DATA.
        ///
        /// # Errors
        /// Returns the same malformed, canonical, bound or semantic classification
        /// as the ordinary decoder. Reentry never overwrites the first attempt.
        pub fn $decode(bytes: &[u8], capture: &mut $capture) -> Result<(), BrokerSessionProjectionError> {
            if capture.attempted {
                capture.closed = Some(BrokerSessionProjectionError::InvalidSemantics);
                return Err(capture.failure().cloned()
                    .unwrap_or(BrokerSessionProjectionError::InvalidSemantics));
            }
            capture.attempted = true;
            let result = $engine(bytes, Some(capture));
            match result {
                Ok(model) => {
                    capture.model = Some(model);
                    capture.result = Some(Ok(()));
                    Ok(())
                }
                Err(error) => {
                    capture.result = Some(Err(error));
                    Err(capture.failure().cloned()
                        .unwrap_or(BrokerSessionProjectionError::InvalidSemantics))
                }
            }
        }
    };
}

projection_capture!(CanonicalBrokerClientHelloDecodeCaptureV1, BrokerClientHello,
    CanonicalBrokerClientHelloV1, SignedBrokerClientHelloV1, decode_canonical_client_hello_retaining_v1, decode_client_hello_engine);

projection_capture!(CanonicalBrokerServerHelloDecodeCaptureV1, BrokerServerHello,
    CanonicalBrokerServerHelloV1, SignedBrokerHelloV1, decode_canonical_server_hello_retaining_v1, decode_server_hello_engine);

projection_capture!(CanonicalBrokerRequestDecodeCaptureV1, BrokerRequestEnvelope,
    CanonicalBrokerRequestEnvelopeV1, SignedBrokerRequestV1, decode_canonical_request_retaining_v1, decode_request_engine);

projection_capture!(CanonicalBrokerResponseDecodeCaptureV1, BrokerResponseEnvelope,
    CanonicalBrokerResponseEnvelopeV1, SignedBrokerOutcomeV1, decode_canonical_response_retaining_v1, decode_response_engine);

pub(super) fn decode_client_hello_engine(
    bytes: &[u8],
    capture: Option<&mut CanonicalBrokerClientHelloDecodeCaptureV1>,
) -> Result<CanonicalBrokerClientHelloV1, BrokerSessionProjectionError> {
    if bytes.len() > CLIENT_HELLO_MAXIMUM_BYTES {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let (message_capture, canonical_capture, cleared_capture, signed_capture,
        feature_capture, decode_result) = match capture {
        Some(capture) => (
            Some(&mut capture.message),
            Some(&mut capture.canonical),
            Some(&mut capture.cleared),
            Some(&mut capture.signed),
            Some(&mut capture.features),
            Some(&mut capture.decode_result),
        ),
        None => (None, None, None, None, None, None),
    };
    let mut message = decode_message::<BrokerClientHello>(bytes, message_capture, decode_result)?;
    {
        let encoded = CaptureValueV1::new(encode_client_hello_v1(&message), canonical_capture);
        require_canonical(bytes, &encoded)?;
        // Canonical equality is the final borrower of this exact backing.
        encoded.dispose();
    }
    if !message.__buffa_unknown_fields.is_empty()
        || message
            .required_features
            .iter()
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
    {
        return Err(BrokerSessionProjectionError::UnknownFields);
    }
    validate_feature_set_engine(&message.required_features, feature_capture)?;
    validate_method_set(&message.required_methods)?;
    let mut signed_local = None;
    let signed = signed_capture.unwrap_or(&mut signed_local);
    *signed = Some(SignedBrokerClientHelloV1::from_canonical_bytes(&message.signed_session_hello)?);
    message.signed_session_hello.clear();
    let cleared = CaptureValueV1::new(encode_client_hello_v1(&message), cleared_capture);
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        CLIENT_HELLO_CLEARED_MAXIMUM_BYTES,
        CLIENT_HELLO_FIELD_CONTRIBUTION,
    )?;
    let completed = CanonicalBrokerClientHelloV1 {
        message: message.take(),
        signed: signed.take().ok_or(BrokerSessionProjectionError::InvalidSemantics)?,
        cleared_digest: length_prefixed_digest(CLIENT_HELLO_FIELDS_DOMAIN, &cleared),
    };
    cleared.dispose();
    Ok(completed)
}

pub(super) fn decode_server_hello_engine(
    bytes: &[u8],
    capture: Option<&mut CanonicalBrokerServerHelloDecodeCaptureV1>,
) -> Result<CanonicalBrokerServerHelloV1, BrokerSessionProjectionError> {
    if bytes.len() > SERVER_HELLO_MAXIMUM_BYTES {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let (message_capture, canonical_capture, cleared_capture, signed_capture,
        feature_capture, decode_result) = match capture {
        Some(capture) => (
            Some(&mut capture.message),
            Some(&mut capture.canonical),
            Some(&mut capture.cleared),
            Some(&mut capture.signed),
            Some(&mut capture.features),
            Some(&mut capture.decode_result),
        ),
        None => (None, None, None, None, None, None),
    };
    let mut message = decode_message::<BrokerServerHello>(bytes, message_capture, decode_result)?;
    {
        let encoded = CaptureValueV1::new(encode_server_hello_v1(&message), canonical_capture);
        require_canonical(bytes, &encoded)?;
        // Canonical equality is the final borrower of this exact backing.
        encoded.dispose();
    }
    if !message.__buffa_unknown_fields.is_empty()
        || message
            .features
            .iter()
            .any(|feature| !feature.__buffa_unknown_fields.is_empty())
        || message.error.as_option().is_some_and(error_has_unknown)
    {
        return Err(BrokerSessionProjectionError::UnknownFields);
    }
    validate_feature_set_engine(&message.features, feature_capture)?;
    validate_method_set(&message.methods)?;
    let mut signed_local = None;
    let signed = signed_capture.unwrap_or(&mut signed_local);
    *signed = Some(SignedBrokerHelloV1::from_canonical_bytes(&message.signed_session_hello)?);
    message.signed_session_hello.clear();
    let cleared = CaptureValueV1::new(encode_server_hello_v1(&message), cleared_capture);
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        SERVER_HELLO_CLEARED_MAXIMUM_BYTES,
        SERVER_HELLO_FIELD_CONTRIBUTION,
    )?;
    let completed = CanonicalBrokerServerHelloV1 {
        message: message.take(),
        signed: signed.take().ok_or(BrokerSessionProjectionError::InvalidSemantics)?,
        cleared_digest: length_prefixed_digest(SERVER_HELLO_FIELDS_DOMAIN, &cleared),
    };
    cleared.dispose();
    Ok(completed)
}

pub(super) fn decode_request_engine(
    bytes: &[u8],
    capture: Option<&mut CanonicalBrokerRequestDecodeCaptureV1>,
) -> Result<CanonicalBrokerRequestEnvelopeV1, BrokerSessionProjectionError> {
    if bytes.len() > authenticated_request_predecode_maximum_bytes_v1() {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let (message_capture, canonical_capture, cleared_capture, signed_capture,
        _feature_capture, decode_result) = match capture {
        Some(capture) => (
            Some(&mut capture.message),
            Some(&mut capture.canonical),
            Some(&mut capture.cleared),
            Some(&mut capture.signed),
            Some(&mut capture.features),
            Some(&mut capture.decode_result),
        ),
        None => (None, None, None, None, None, None),
    };
    let mut message = decode_message::<BrokerRequestEnvelope>(bytes, message_capture, decode_result)?;
    let method = message
        .method
        .as_known()
        .ok_or(BrokerSessionProjectionError::InvalidSemantics)?;
    let profile = authenticated_broker_method_profile_v1(method)
        .ok_or(BrokerSessionProjectionError::InvalidSemantics)?;
    if bytes.len() > profile.total_request_maximum_bytes() {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    {
        let encoded = CaptureValueV1::new(encode_request_v1(&message), canonical_capture);
        require_canonical(bytes, &encoded)?;
        // Canonical equality is the final borrower of this exact backing.
        encoded.dispose();
    }
    validate_request_nested(&message)?;
    let mut signed_local = None;
    let signed = signed_capture.unwrap_or(&mut signed_local);
    *signed = Some(SignedBrokerRequestV1::from_canonical_bytes(&message.signed_session_request)?);
    if message.method.as_known() != signed.as_ref().map(|signed| signed.method()) {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    message.signed_session_request.clear();
    let cleared = CaptureValueV1::new(encode_request_v1(&message), cleared_capture);
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        profile.cleared_request_maximum_bytes(),
        REQUEST_FIELD_CONTRIBUTION,
    )?;
    let completed = CanonicalBrokerRequestEnvelopeV1 {
        message: message.take(),
        signed: signed.take().ok_or(BrokerSessionProjectionError::InvalidSemantics)?,
        cleared_digest: length_prefixed_digest(REQUEST_FIELDS_DOMAIN, &cleared),
        encoded_len: bytes.len(),
    };
    cleared.dispose();
    Ok(completed)
}

pub(super) fn decode_response_engine(
    bytes: &[u8],
    capture: Option<&mut CanonicalBrokerResponseDecodeCaptureV1>,
) -> Result<CanonicalBrokerResponseEnvelopeV1, BrokerSessionProjectionError> {
    if bytes.len() > AUTHENTICATED_RESPONSE_MAXIMUM_BYTES {
        return Err(BrokerSessionProjectionError::TooLarge);
    }
    let (message_capture, canonical_capture, cleared_capture, signed_capture,
        _feature_capture, decode_result) = match capture {
        Some(capture) => (
            Some(&mut capture.message),
            Some(&mut capture.canonical),
            Some(&mut capture.cleared),
            Some(&mut capture.signed),
            Some(&mut capture.features),
            Some(&mut capture.decode_result),
        ),
        None => (None, None, None, None, None, None),
    };
    let mut message = decode_message::<BrokerResponseEnvelope>(bytes, message_capture, decode_result)?;
    {
        let encoded = CaptureValueV1::new(encode_response_v1(&message), canonical_capture);
        require_canonical(bytes, &encoded)?;
        // Canonical equality is the final borrower of this exact backing.
        encoded.dispose();
    }
    validate_response_nested(&message)?;
    let mut signed_local = None;
    let signed = signed_capture.unwrap_or(&mut signed_local);
    *signed = Some(SignedBrokerOutcomeV1::from_canonical_bytes(&message.signed_session_outcome)?);
    if message.method.as_known() != signed.as_ref().map(|signed| signed.method()) {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    message.signed_session_outcome.clear();
    let cleared = CaptureValueV1::new(encode_response_v1(&message), cleared_capture);
    require_projection_sizes(
        bytes.len(),
        cleared.len(),
        AUTHENTICATED_RESPONSE_CLEARED_MAXIMUM_BYTES,
        RESPONSE_FIELD_CONTRIBUTION,
    )?;
    let completed = CanonicalBrokerResponseEnvelopeV1 {
        message: message.take(),
        signed: signed.take().ok_or(BrokerSessionProjectionError::InvalidSemantics)?,
        cleared_digest: length_prefixed_digest(RESPONSE_FIELDS_DOMAIN, &cleared),
        encoded_len: bytes.len(),
        encoded_bytes: bytes.to_vec(),
    };
    cleared.dispose();
    Ok(completed)
}

#[derive(Default)]
pub(super) struct FeatureValidationCaptureV1 {
    values: Vec<FeatureRef>,
    current_namespace: Option<String>,
    registry_result: Option<Result<(), aos_sandbox_core::RegistryError>>,
}

pub(super) fn validate_feature_set_engine(
    features: &[aos_proto::aos::sandbox::local::v1::Feature],
    capture: Option<&mut FeatureValidationCaptureV1>,
) -> Result<(), BrokerSessionProjectionError> {
    let Some(capture) = capture else {
        return (|| {
            if features.len() > MAXIMUM_FEATURES {
                return Err(BrokerSessionProjectionError::InvalidSemantics);
            }
            let values = features
                .iter()
                .map(|feature| FeatureRef::new(feature.namespace.clone(), feature.major, feature.minor))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| BrokerSessionProjectionError::InvalidSemantics)?;
            if values.windows(2).any(|window| window[0] >= window[1])
                || validate_required_features(&values).is_err()
            {
                Err(BrokerSessionProjectionError::InvalidSemantics)
            } else {
                Ok(())
            }
        })();
    };
    if features.len() > MAXIMUM_FEATURES {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    for feature in features {
        capture.current_namespace = Some(feature.namespace.clone());
        let value = FeatureRef::new_retaining_v1(
            &mut capture.current_namespace, feature.major, feature.minor,
        ).map_err(|_| BrokerSessionProjectionError::InvalidSemantics)?;
        capture.values.push(value);
    }
    if capture.values.windows(2).any(|window| window[0] >= window[1]) {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    capture.registry_result = Some(validate_required_features(&capture.values));
    if capture.registry_result.as_ref().is_some_and(Result::is_err) {
        return Err(BrokerSessionProjectionError::InvalidSemantics);
    }
    // The complete feature predicate is the original final borrower of this
    // exact table. Keep its whole Result; retain failed prefixes and namespace.
    drop(std::mem::take(&mut capture.values));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::{BrokerDescriptorEntry, Feature};

    #[test]
    fn failed_top_level_merge_keeps_completed_bytes_and_original_error() {
        let message = BrokerRequestEnvelope {
            body: vec![1, 2, 3, 4],
            ..Default::default()
        };
        let mut bytes = message.encode_to_vec();
        bytes.push(0x80);
        let ordinary = decode_canonical_request_v1(&bytes).err().unwrap();
        let mut capture = CanonicalBrokerRequestDecodeCaptureV1::new();

        let retained = decode_canonical_request_retaining_v1(&bytes, &mut capture).unwrap_err();

        assert_eq!(retained, ordinary);
        assert_eq!(capture.failure(), Some(&ordinary));
        assert_eq!(capture.message.as_ref().unwrap().body, [1, 2, 3, 4]);
        assert!(matches!(capture.decode_result, Some(Err(_))));
        assert!(capture.take_model_once().is_err());
    }

    #[test]
    fn failed_repeated_feature_is_kept_in_the_actual_generated_parent() {
        // ClientHello.required_features contains one complete namespace, then
        // a truncated varint for Feature.major. Parent length is fully present.
        let bytes = [0x22, 6, 0x0a, 2, b'a', b'b', 0x10, 0x80];
        let mut ordinary = BrokerClientHello::default();
        let ordinary_error = ordinary.merge_from_slice(&bytes).unwrap_err();
        let mut retained = BrokerClientHello::default();

        let retained_error = retained.merge_retaining_from_slice(&bytes).unwrap_err();

        assert_eq!(ordinary_error, retained_error);
        assert!(ordinary.required_features.is_empty());
        assert_eq!(retained.required_features.len(), 1);
        assert_eq!(retained.required_features[0].namespace, "ab");
    }

    #[test]
    fn canonical_mismatch_keeps_actual_encoded_backing_and_message() {
        // A duplicate known field is accepted by protobuf's last-wins merge,
        // but the canonical encoder emits it once into a nonempty backing.
        let bytes = [0x08, 1, 0x08, 1];
        let mut capture = CanonicalBrokerClientHelloDecodeCaptureV1::new();

        let error = decode_canonical_client_hello_retaining_v1(&bytes, &mut capture).unwrap_err();

        assert_eq!(error, BrokerSessionProjectionError::Noncanonical);
        assert_eq!(capture.canonical.as_deref(), Some([0x08, 1].as_slice()));
        assert!(capture.message.is_some());
        assert!(capture.model().is_none());
        assert_eq!(decode_canonical_client_hello_retaining_v1(&[], &mut capture), Err(error));
    }

    #[test]
    fn feature_error_keeps_completed_prefix_and_actual_current_namespace() {
        let features = [
            Feature { namespace: "aos.first".into(), major: 1, ..Default::default() },
            Feature { namespace: "INVALID".into(), major: 1, ..Default::default() },
        ];
        let mut capture = FeatureValidationCaptureV1::default();

        let error = validate_feature_set_engine(&features, Some(&mut capture)).unwrap_err();

        assert_eq!(error, validate_feature_set_engine(&features, None).unwrap_err());
        assert_eq!(capture.values.len(), 1);
        assert_eq!(capture.values[0].namespace(), "aos.first");
        assert_eq!(capture.current_namespace.as_deref(), Some("INVALID"));
    }

    #[test]
    fn selected_and_ordinary_generated_decoders_share_budget_errors() {
        // Every prefix of an actually encoded nested child exercises the same
        // parser's truncation frontiers; selected custody alone may differ.
        let message = BrokerRequestEnvelope {
            body: vec![1, 2, 3],
            descriptors: vec![BrokerDescriptorEntry::default()],
            ..Default::default()
        };
        let bytes = message.encode_to_vec();
        for end in 0..=bytes.len() {
            let mut ordinary = BrokerRequestEnvelope::default();
            let mut retained = BrokerRequestEnvelope::default();
            assert_eq!(ordinary.merge_from_slice(&bytes[..end]),
                retained.merge_retaining_from_slice(&bytes[..end]));
        }
    }
}

#[cfg(test)]
mod message_move_tests {
    use super::*;

    #[test]
    fn the_actual_partial_message_buffer_moves_without_a_clone() {
        let original = BrokerRequestEnvelope { body: vec![3; 1024], ..Default::default() };
        let bytes = original.encode_to_vec();
        let mut slot = None;
        let mut parser_result = None;
        let message = decode_message::<BrokerRequestEnvelope>(
            &bytes, Some(&mut slot), Some(&mut parser_result),
        ).unwrap();
        let pointer = message.body.as_ptr();

        let moved = message.take();

        assert_eq!(moved.body.as_ptr(), pointer);
        assert_eq!(moved.body, original.body);
        assert!(slot.as_ref().unwrap().body.is_empty());
        assert_eq!(parser_result, Some(Ok(())));
    }
}
