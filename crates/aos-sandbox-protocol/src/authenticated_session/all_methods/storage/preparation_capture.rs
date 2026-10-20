//! Retains the actual Prepare protobuf and canonical comparison prefix.

use super::*;

#[derive(Default)]
pub(in crate::authenticated_session::all_methods) struct PreparationResponseCaptureV1 {
    pub(super) message: PrepareStorageCatalogResponse,
    pub(super) decode: Option<Result<(), buffa::DecodeError>>,
    pub(super) canonical: Vec<u8>,
    result: Option<Result<(), ProtocolValidationError>>,
    entered: bool,
}

impl PreparationResponseCaptureV1 {
    pub(in crate::authenticated_session::all_methods) fn decode_once(
        &mut self, bytes: &[u8], request: &CanonicalStoragePreparationSemanticsV1,
    ) -> Result<(), ProtocolValidationError> {
        if self.entered {
            return Err(ProtocolValidationError::InvalidField("repeated Prepare capture"));
        }
        self.entered = true;
        self.result = Some(super::validate_storage_preparation_response_engine(bytes, request, Some(self)));
        self.result.as_ref().ok_or(ProtocolValidationError::InvalidField("Prepare result"))?
            .as_ref().map(|_| ()).map_err(Clone::clone)
    }

    pub(in crate::authenticated_session::all_methods) fn value_v3(&self) -> Option<&PrepareStorageCatalogResponse> {
        if self.entered && matches!(self.decode, Some(Ok(()))) && matches!(self.result, Some(Ok(()))) {
            Some(&self.message)
        } else { None }
    }

    pub(in crate::authenticated_session::all_methods) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.decode.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.result.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::decode_message_v1;

    #[test]
    fn prepare_partial_decoder_retains_reached_fields_and_raw_error() {
        let response = PrepareStorageCatalogResponse {
            operation_id: vec![1; 16], catalog_generation: 2,
            catalog_digest: vec![3; 32], non_authorizing_receipt: vec![4; 32],
            ..Default::default()
        };
        let mut bytes = response.encode_to_vec();
        bytes.push(0x80);
        let mut original = PreparationResponseCaptureV1::default();

        assert!(decode_message_v1::<PrepareStorageCatalogResponse>(
            &bytes, Some(&mut original.message), Some(&mut original.decode),
        ).is_err());

        assert_eq!(original.message.operation_id, vec![1; 16]);
        assert!(matches!(original.decode, Some(Err(_))));
        assert!(original.failure().unwrap().downcast_ref::<buffa::DecodeError>().is_some());
        assert!(original.canonical.is_empty());
    }
}
