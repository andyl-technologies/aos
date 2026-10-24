//! Retains the sole Apply response parser and exact late failure prefix.

use super::*;

#[derive(Default)]
pub(in crate::authenticated_session::all_methods) struct ApplyResponseCaptureV1 {
    pub(super) raw: StorageResult,
    pub(super) decode: Option<Result<(), buffa::DecodeError>>,
    pub(super) canonical: Vec<u8>,
    result: Option<Result<(), ProtocolValidationError>>,
}

impl ApplyResponseCaptureV1 {
    pub(in crate::authenticated_session::all_methods) fn validate_once(&mut self, body: &[u8],
        request: &CanonicalStorageSemanticsV1) -> Result<(), ProtocolValidationError>
    {
        if self.result.is_some() { return Err(ProtocolValidationError::MethodMismatch); }
        self.result = Some(super::validate_storage_apply_response_engine(body, request, Some(self)));
        self.result.as_ref().ok_or(ProtocolValidationError::MethodMismatch)?
            .as_ref().copied().map_err(Clone::clone)
    }

    pub(in crate::authenticated_session::all_methods) fn failure(&self)
        -> Option<&(dyn std::error::Error + 'static)>
    {
        self.decode.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }

    pub(in crate::authenticated_session::all_methods) fn value(&self) -> Option<&StorageResult> {
        if matches!(self.result, Some(Ok(()))) { Some(&self.raw) } else { None }
    }
}
