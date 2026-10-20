//! Private ownership adapters for the same ordinary and retained validators.
//!
//! Optional destinations change where reached DATA lives. They never supply a
//! payer, callback, protocol validator or positive authority constructor.

use aos_sandbox_model::retained::CaptureValueV1;
use buffa::Message;
use crate::ProtocolValidationError;

pub(crate) fn decode_message_v1<'a, M: Message>(
    bytes: &[u8],
    destination: Option<&'a mut M>,
    outcome: Option<&mut Option<Result<(), buffa::DecodeError>>>,
) -> Result<CaptureValueV1<'a, M>, ProtocolValidationError> {
    if destination.is_none() {
        // Preserve ordinary partial-message disposal before String projection.
        return M::decode_from_slice(bytes)
            .map(CaptureValueV1::Local)
            .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()));
    }
    let mut message = CaptureValueV1::new(M::default(), destination);
    let result = message.merge_retaining_from_slice(bytes);
    let returned = result.as_ref().map(|_| ())
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()));
    if let Some(outcome) = outcome {
        *outcome = Some(result);
    }
    returned?;
    Ok(message)
}

#[derive(Default)]
pub(crate) struct DescriptorCaptureV1 {
    pub(crate) input: Option<String>,
    pub(crate) syntax: Option<Result<aos_sandbox_model::MediaType, aos_sandbox_model::selector::InvalidMediaType>>,
    pub(crate) role: Option<Result<aos_sandbox_model::PortableMediaType, aos_sandbox_model::RegistryError>>,
    pub(crate) media_type: Option<aos_sandbox_model::MediaType>,
    pub(crate) descriptor: Option<aos_sandbox_model::ObjectDescriptor>,
}

impl DescriptorCaptureV1 {
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.syntax.as_ref().and_then(|value| value.as_ref().err())
            .map(|cause| cause as &(dyn std::error::Error + 'static))
            .or_else(|| self.role.as_ref().and_then(|value| value.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)))
    }
}
